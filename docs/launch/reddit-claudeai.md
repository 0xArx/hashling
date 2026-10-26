# r/ClaudeAI

Before posting: read the sidebar rules, pick the flair for things you built (the sub has had a "Built with Claude" style flair), and say plainly that you are the developer. One post, no reposting, and reply to comments for the first few hours.

**Title:**

```
I built a free MCP server that lets Claude Code audit your Mac's security, including what Claude Code itself is allowed to do
```

**Body:**

I'm the developer of Hashling, a free, open-source (MIT) security agent for macOS. Sharing it here because it was built for people who run Claude Code.

**The problem.** Claude Code can run commands, read and write files and push code. Once you've clicked "always allow" a few times, most of us can't say exactly what it's allowed to do, which MCP servers are switched on, or how many API keys are sitting in config files.

**What Hashling shows you** (for Claude Code, Codex, Cursor, Claude Desktop, VS Code, Windsurf, Gemini CLI and OpenCode):

- which commands each agent can run without asking (your allow rules, in plain words)
- which MCP servers and hooks are switched on, and which projects can add more without asking
- how many API keys are in their settings files (counted, never copied)
- what each agent is doing on the network right now
- booby-trapped repos: a cloned project whose `.mcp.json`, `.claude/settings.json` or git config would make Claude run something the moment you trust the folder. It checks who committed those files, so your own setups stay quiet and a stranger's get flagged

**Connect Claude to it:** install Hashling (download the installer from https://gethashling.com/start and double-click it, or `curl -fsSL https://gethashling.com/install.sh | sh`), then:

```
claude mcp add --scope user hashling -- hashling mcp
```

Then ask Claude: *"Is my Mac safe? What can my AI agents do?"* Claude calls Hashling's tools and answers from real data. It can only look and suggest: every change (quarantine a file, remove a permission, block a site) waits for your Touch ID, so even an agent holding the token can't approve its own fix.

**Don't want your questions going to the cloud?** Hashling has a Fully local mode that runs a free open model on your Mac (it picks one by RAM). Claude stays the better assistant; local is there for when privacy matters more.

**Honest limits:** not a firewall (pair it with LuLu), it scans files shortly after they arrive rather than blocking them first, and zero findings doesn't prove a Mac is clean.

The first time I ran it on my own Mac, it found API keys sitting in plain text in my Claude config files. That's what made me keep building.

Site and 75-second demo: https://gethashling.com
Code: https://github.com/0xArx/hashling

Happy to answer anything about how the agent audit works.
