#!/usr/bin/env python3
"""Drive one model through diagnosing a faulted machine, from an operator box.

The agent gets a shell on ONE machine — the operator — via the `run` tool, plus
whatever remote-access tooling the harness pre-installed there (WireHop in one
condition, ssh in the other). To inspect the faulted target it must go through
that tooling; the driver never shells into the target directly, so the condition
under test is the only thing that changes what the agent can do and what the
target records.

A `diagnose` tool captures the agent's conclusion as structured fields, so the
harness scores the root cause without parsing prose. A model-generated string
never becomes a container name: `run` always targets the operator container the
harness passed in.

Usage:
  diagnosis-agent.py --operator op=diag-op --target-name db01 \
      --condition hop --fault full_disk --model claude-sonnet-5 \
      --transcript t.jsonl --summary s.json
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
CMD_TIMEOUT = 120
MAX_OUTPUT = 6000

RUN_TOOL = {
    "name": "run",
    "description": (
        "Run a shell command on the operator machine and get back its stdout, "
        "stderr and exit code. Non-interactive: there is no TTY, so anything "
        "that waits for input or opens a full-screen UI will time out. To look "
        "at the target machine, use the remote-access tooling described in the "
        "task from here."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "The shell command."},
        },
        "required": ["command"],
    },
}

DIAGNOSE_TOOL = {
    "name": "diagnose",
    "description": (
        "Report your conclusion once you have found the root cause of the "
        "target's problem. Call this exactly once, when you are confident."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "root_cause": {
                "type": "string",
                "description": "One line naming the underlying cause, concretely.",
            },
            "evidence": {
                "type": "string",
                "description": "The specific observation on the target that proves it.",
            },
            "fix": {
                "type": "string",
                "description": "The single action that would resolve it.",
            },
        },
        "required": ["root_cause", "evidence"],
    },
}

PROMPT = """\
You are an on-call operator at a terminal on a machine called `{op}`. A service \
on a different machine, `{target}`, is failing, and you need to find out why.

You can reach `{target}` from `{op}` using {access}. {access_how}

Investigate `{target}` and determine the single underlying root cause of its \
problem. Work only through the `run` tool (it executes on `{op}`); reach \
`{target}` with the access tooling above. When you are certain, call the \
`diagnose` tool with the root cause, the specific evidence, and the fix.

Constraints:
  - No human is available and there is no TTY. Never open an editor or an \
interactive session; use non-interactive flags. Prefer read-only inspection.
  - Do not reboot the target or delete data to "fix" it; you are diagnosing, \
not remediating. Finding and naming the cause is the whole task.
  - If you truly cannot proceed, call `diagnose` with root_cause "UNKNOWN" and \
explain what blocked you."""

ACCESS = {
    "hop": (
        "WireHop",
        "WireHop is installed and `{target}` is already reachable by that name. "
        "Run commands on it with `hop {target} exec -- <command>` and read files "
        "with `hop {target} exec -- cat <path>`. `hop fleet list` shows the "
        "fleet. Everything you run on `{target}` this way is recorded in its "
        "audit log.",
    ),
    "ssh": (
        "ssh",
        "An ssh key is set up and `{target}` is in your known hosts. Run "
        "commands on it with `ssh {target} <command>`. This is the conventional "
        "setup (equivalent to reaching it over a Tailscale tailnet).",
    ),
}


def api_call(key, model, system, messages, tools, max_tokens, retries=4):
    body = {"model": model, "max_tokens": max_tokens, "messages": messages, "tools": tools}
    if system:
        body["system"] = system
    data = json.dumps(body).encode()
    delay = 4
    for attempt in range(retries):
        req = urllib.request.Request(
            API_URL, data=data,
            headers={"content-type": "application/json", "x-api-key": key,
                     "anthropic-version": API_VERSION},
        )
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode()[:400]
            if e.code in (429, 500, 502, 503, 529) and attempt < retries - 1:
                sys.stderr.write(f"[agent] API {e.code}, retry in {delay}s\n")
                time.sleep(delay); delay *= 2; continue
            raise RuntimeError(f"API {e.code}: {detail}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < retries - 1:
                sys.stderr.write(f"[agent] network error, retry in {delay}s: {e}\n")
                time.sleep(delay); delay *= 2; continue
            raise
    raise RuntimeError("unreachable")


def run_in(container, command):
    try:
        p = subprocess.run(
            ["docker", "exec", container, "bash", "-lc", command],
            capture_output=True, text=True, timeout=CMD_TIMEOUT,
        )
        out = (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr else "")
        code = p.returncode
    except subprocess.TimeoutExpired:
        out = f"[timed out after {CMD_TIMEOUT}s]"
        code = 124
    if len(out) > MAX_OUTPUT:
        out = "[... truncated ...]\n" + out[-MAX_OUTPUT:]
    return f"exit={code}\n{out.strip() or '(no output)'}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--operator", required=True, help="logical=container, e.g. op=diag-op")
    ap.add_argument("--target-name", required=True, help="name the agent uses for the target")
    ap.add_argument("--condition", choices=["hop", "ssh"], required=True)
    ap.add_argument("--fault", required=True, help="fault id, for the transcript only")
    ap.add_argument("--model", default="claude-sonnet-5")
    ap.add_argument("--max-turns", type=int, default=30)
    ap.add_argument("--transcript", default="")
    ap.add_argument("--summary", default="")
    args = ap.parse_args()

    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        sys.stderr.write("ANTHROPIC_API_KEY not set\n")
        return 2

    logical, _, container = args.operator.partition("=")
    op_name, op_container = logical.strip(), container.strip()
    if not op_container:
        sys.stderr.write("bad --operator\n")
        return 2

    access_label, access_how = ACCESS[args.condition]
    access_how = access_how.format(target=args.target_name)
    text = PROMPT.format(
        op=op_name, target=args.target_name,
        access=access_label, access_how=access_how,
    )

    messages = [{"role": "user", "content": text}]
    tools = [RUN_TOOL, DIAGNOSE_TOOL]
    tx = open(args.transcript, "w") if args.transcript else None

    def log(kind, payload):
        if tx:
            tx.write(json.dumps({"kind": kind, **payload}) + "\n"); tx.flush()

    log("prompt", {"condition": args.condition, "fault": args.fault,
                   "model": args.model, "text": text})

    t0 = time.time()
    turns = tool_calls = in_tok = out_tok = 0
    diagnosis = None
    stop = "max_turns"
    final = ""

    while turns < args.max_turns:
        turns += 1
        resp = api_call(key, args.model, None, messages, tools, 4000)
        usage = resp.get("usage", {})
        in_tok += usage.get("input_tokens", 0)
        out_tok += usage.get("output_tokens", 0)
        content = resp.get("content", [])
        messages.append({"role": "assistant", "content": content})

        results = []
        for block in content:
            if block.get("type") == "text":
                final = block["text"]
                log("say", {"turn": turns, "text": final})
            elif block.get("type") == "tool_use":
                tool_calls += 1
                name = block.get("name")
                inp = block.get("input", {})
                if name == "diagnose":
                    diagnosis = {
                        "root_cause": str(inp.get("root_cause", "")),
                        "evidence": str(inp.get("evidence", "")),
                        "fix": str(inp.get("fix", "")),
                    }
                    log("diagnose", {"turn": turns, **diagnosis})
                    results.append({"type": "tool_result", "tool_use_id": block["id"],
                                    "content": "recorded"})
                else:  # run
                    command = str(inp.get("command", ""))
                    result = run_in(op_container, command)
                    log("run", {"turn": turns, "command": command, "result": result})
                    results.append({"type": "tool_result", "tool_use_id": block["id"],
                                    "content": result})

        if diagnosis is not None:
            stop = "diagnosed"
            break
        if results:
            messages.append({"role": "user", "content": results})
            continue
        stop = "stopped"
        break

    elapsed = round(time.time() - t0, 1)
    summary = {
        "condition": args.condition, "fault": args.fault, "model": args.model,
        "turns": turns, "tool_calls": tool_calls, "wall_secs": elapsed,
        "input_tokens": in_tok, "output_tokens": out_tok, "stop": stop,
        "diagnosis": diagnosis, "final": final[-1200:],
    }
    log("summary", summary)
    if tx:
        tx.close()
    if args.summary:
        with open(args.summary, "w") as f:
            json.dump(summary, f, indent=2)
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
