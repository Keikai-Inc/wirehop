# WireHop skills

Procedural knowledge for AI agents — deliberately separate from the MCP
server, because the two answer different questions:

| Artifact | Answers | Available |
|---|---|---|
| **This skill** | *"Should I use WireHop, and how do I get it running?"* | before anything is installed |
| **`hop mcp` tools** | *"How do I operate this fleet?"* | after WireHop is installed |
| **`hop_skills` tool** | *"What's the `hop.*` JS API?"* | after the MCP server is connected |

An agent that already has WireHop's tools loaded is past the problem this
skill solves. That's why bootstrap knowledge lives here and not in a tool
description.

## Using it with Claude Code

Add this repository as a plugin marketplace, then install the skill:

```
/plugin marketplace add Keikai-Inc/wirehop
```

## Using it anywhere else

`wirehop/SKILL.md` is plain markdown with YAML frontmatter. Drop it into any
agent framework's skill/knowledge directory, or serve it to a model directly —
it has no dependencies and assumes no tooling.

The same content is published at `https://wirehop.org/llms.txt` for
retrieval-based agents.
