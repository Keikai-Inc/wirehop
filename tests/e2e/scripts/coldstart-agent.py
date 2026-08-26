#!/usr/bin/env python3
"""Drive a real LLM agent against cold containers, with a shell as its only tool.

This is the agent half of `tests/e2e/agent-coldstart.sh`. It deliberately does
NOT score anything — the harness scores the containers afterwards, by observing
what actually works. An agent that says it succeeded is not evidence; a warren
that carries a packet is.

The agent gets exactly one tool: run(machine, command). No filesystem, no
network of its own, no WireHop knowledge beyond what it fetches with curl. That
constraint is the entire point — it is what makes the resulting pass rate mean
"the docs carry an agent from zero" rather than "our test script works".

Safety: `machine` is checked against an explicit allowlist of container names
passed in by the harness. A model-generated string never reaches `docker exec`
as a container name, so the blast radius is the throwaway containers.

Stdlib only (urllib) — same zero-dependency instinct as the rest of tests/e2e.

Usage:
  coldstart-agent.py --containers alpha=cs-alpha,beta=cs-beta \
                     --docs-url http://docs:8080 --mode assisted \
                     --transcript out.jsonl --summary out.json
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

# Per-command ceiling. Long enough for a cross-build-free install + a warren to
# converge; short enough that one wedged command can't eat the trial budget.
CMD_TIMEOUT = 180
# Tool results are fed back into context every turn, so an unbounded `cat` of a
# log would blow the window. Truncate from the END — errors live at the tail.
MAX_OUTPUT = 6000

TOOL = {
    "name": "run",
    "description": (
        "Run a shell command on one of the machines and get back its stdout, "
        "stderr and exit code. Non-interactive: there is no TTY, so anything "
        "that waits for input or opens a full-screen UI will time out."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "machine": {"type": "string", "description": "Which machine to run on."},
            "command": {"type": "string", "description": "The shell command."},
        },
        "required": ["machine", "command"],
    },
}

ASSISTED_PROMPT = """\
You are operating {n} Linux machines — {names} — through the `run` tool. Right \
now they cannot reach each other, and neither has any remote-access tooling \
installed.

Get to a state where all three of these are true:

  1. A command issued from `{first}` executes on `{second}` and returns its output.
  2. Both machines belong to the same private network, each with its own virtual IP.
  3. One fleet-wide command issued from `{first}` runs across that network.

There is a tool for this called WireHop. Its agent documentation is at \
{docs}/llms.txt — fetch it with curl and follow it. Everything you need is \
reachable from there.

Constraints:
  - There is no human available. Nobody will click a link, create an account, \
open a browser, or paste a token for you. If you find yourself waiting on a \
person, you have taken a wrong turn — back up and find the non-interactive path.
  - The shells have no TTY. Never start an interactive session or an editor; it \
will hang and burn your budget. Prefer flags like `--json`, `-y`, and \
non-interactive subcommands.
  - Daemons must be started detached (e.g. `nohup ... &`) or the command will \
block until it is killed.

When all three goals hold, reply with DONE and one sentence on how you verified \
each. If you get stuck, reply with BLOCKED and the specific reason."""

DISCOVERY_PROMPT = """\
You are operating {n} Linux machines — {names} — through the `run` tool. Right \
now they cannot reach each other, and neither has any remote-access tooling \
installed.

Get to a state where all three of these are true:

  1. A command issued from `{first}` executes on `{second}` and returns its output.
  2. Both machines belong to the same private network, each with its own virtual IP.
  3. One fleet-wide command issued from `{first}` runs across that network.

Constraints:
  - There is no human available. Nobody will click a link, create an account, \
open a browser, or paste a token for you. If you find yourself waiting on a \
person, you have taken a wrong turn — back up and find the non-interactive path.
  - The shells have no TTY. Never start an interactive session or an editor; it \
will hang and burn your budget. Prefer flags like `--json`, `-y`, and \
non-interactive subcommands.
  - Daemons must be started detached (e.g. `nohup ... &`) or the command will \
block until it is killed.

When all three goals hold, reply with DONE and one sentence on how you verified \
each. If you get stuck, reply with BLOCKED and the specific reason."""


def api_call(key, model, system, messages, max_tokens, retries=4):
    """POST to the Messages API, retrying the errors that are worth retrying.

    Overload (429) and 5xx are transient and would otherwise show up as a
    failed trial — which would understate the pass rate for a reason that has
    nothing to do with the docs under test.
    """
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": messages,
        "tools": [TOOL],
    }
    if system:
        body["system"] = system
    data = json.dumps(body).encode()
    delay = 4
    for attempt in range(retries):
        req = urllib.request.Request(
            API_URL,
            data=data,
            headers={
                "content-type": "application/json",
                "x-api-key": key,
                "anthropic-version": API_VERSION,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode()[:400]
            if e.code in (429, 500, 502, 503, 529) and attempt < retries - 1:
                sys.stderr.write(
                    f"[agent] API {e.code}, retry in {delay}s: {detail}\n"
                )
                time.sleep(delay)
                delay *= 2
                continue
            raise RuntimeError(f"API {e.code}: {detail}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < retries - 1:
                sys.stderr.write(f"[agent] network error, retry in {delay}s: {e}\n")
                time.sleep(delay)
                delay *= 2
                continue
            raise
    raise RuntimeError("unreachable")


def run_in(container, command):
    """Execute one model-authored command inside a throwaway container."""
    try:
        p = subprocess.run(
            ["docker", "exec", container, "bash", "-lc", command],
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT,
        )
        out = (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr else "")
        code = p.returncode
    except subprocess.TimeoutExpired:
        out = f"[timed out after {CMD_TIMEOUT}s — the command was still running]"
        code = 124
    if len(out) > MAX_OUTPUT:
        out = "[... truncated ...]\n" + out[-MAX_OUTPUT:]
    return f"exit={code}\n{out.strip() or '(no output)'}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--containers", required=True,
                    help="comma-separated logical=container pairs, e.g. alpha=cs-alpha")
    ap.add_argument("--docs-url", default="")
    ap.add_argument("--mode", choices=["assisted", "discovery"], default="assisted")
    ap.add_argument("--skill", default="", help="path to SKILL.md (discovery mode)")
    ap.add_argument("--model", default="claude-sonnet-5")
    ap.add_argument("--max-turns", type=int, default=40)
    ap.add_argument("--transcript", default="")
    ap.add_argument("--summary", default="")
    args = ap.parse_args()

    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        sys.stderr.write("ANTHROPIC_API_KEY not set\n")
        return 2

    machines = {}
    for pair in args.containers.split(","):
        logical, _, container = pair.partition("=")
        machines[logical.strip()] = container.strip()
    names = list(machines)
    if len(names) < 2:
        sys.stderr.write("need at least two machines\n")
        return 2

    system = None
    if args.mode == "discovery":
        # Simulate an agent that has the skill installed but has never heard of
        # WireHop otherwise: the skill is the ONLY thing bridging the gap.
        if not args.skill or not os.path.exists(args.skill):
            sys.stderr.write("discovery mode needs --skill pointing at SKILL.md\n")
            return 2
        with open(args.skill) as f:
            skill = f.read()
        # Drop YAML frontmatter — it is loader metadata, not content.
        if skill.startswith("---"):
            end = skill.find("\n---", 3)
            if end != -1:
                skill = skill[end + 4:]
        system = (
            "You have the following skill available. Use it if and only if it "
            "is relevant to what you are asked to do.\n\n" + skill
        )
        prompt = DISCOVERY_PROMPT
    else:
        prompt = ASSISTED_PROMPT

    text = prompt.format(
        n=len(names),
        names=", ".join(f"`{m}`" for m in names),
        first=names[0],
        second=names[1],
        docs=args.docs_url,
    )

    messages = [{"role": "user", "content": text}]
    tx = open(args.transcript, "w") if args.transcript else None

    def log(kind, payload):
        if tx:
            tx.write(json.dumps({"kind": kind, **payload}) + "\n")
            tx.flush()

    log("prompt", {"mode": args.mode, "model": args.model, "text": text})

    t0 = time.time()
    turns = tool_calls = in_tok = out_tok = 0
    stop = "max_turns"
    final = ""

    while turns < args.max_turns:
        turns += 1
        resp = api_call(key, args.model, system, messages, 8000)
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
                inp = block.get("input", {})
                machine = str(inp.get("machine", ""))
                command = str(inp.get("command", ""))
                container = machines.get(machine)
                if container is None:
                    # Never let a model-authored string become a container name.
                    result = (
                        f"error: unknown machine {machine!r}. "
                        f"Available: {', '.join(names)}"
                    )
                else:
                    result = run_in(container, command)
                log("run", {"turn": turns, "machine": machine,
                            "command": command, "result": result})
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block["id"],
                    "content": result,
                })

        if results:
            messages.append({"role": "user", "content": results})
            continue

        # No tool calls: the agent is done talking.
        stop = "done" if "DONE" in final.upper() else "stopped"
        break

    elapsed = round(time.time() - t0, 1)
    summary = {
        "mode": args.mode,
        "model": args.model,
        "turns": turns,
        "tool_calls": tool_calls,
        "wall_secs": elapsed,
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "stop": stop,
        "final": final[-1500:],
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
