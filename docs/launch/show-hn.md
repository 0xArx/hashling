# Show HN

**Title** (80 characters max, this one is 76):

```
Show HN: Hashling, an open-source Mac security agent your own AI can talk to
```

**URL to submit:** https://github.com/0xArx/hashling
(HN readers prefer the repo. The site and demo are linked in the comment.)

---

## First comment (post it right after submitting)

Hi HN, I'm Abdulrahman. Hashling is a free, MIT-licensed security agent for macOS. It started with one question: Claude Code, Codex and Cursor can run programs, read files and push code on my Mac, so what exactly is each one allowed to do?

What it does:

- **Audits the AI agents on your Mac.** For Claude Code, Codex, Cursor, Claude Desktop, VS Code, Windsurf, Gemini CLI and OpenCode it reads permission modes, allow rules, hooks, MCP servers and skills, counts API keys left in their config files (never copies them), and watches their live network use.
- **Catches booby-trapped repos.** It checks the folders your agents opened for the 2026 attack patterns: a committed `.mcp.json` that starts a server once you trust the folder (TrustFall), project settings that switch off safety questions, add hooks or redirect `ANTHROPIC_BASE_URL`, git config that runs commands (GitSpawn), hidden bare repos, and symlinks into `~/.ssh` (GhostApproval). It uses git authorship and macOS's download marker to separate your own setups from a stranger's, so your own `.mcp.json` files don't nag.
- **Is an MCP server.** Connect Claude Code (one command) and ask "is my Mac safe?". The agent calls Hashling's tools (overview, findings, network, uploads, storage, osquery and more) and answers from real data. Agents can only read and propose: every change waits for Touch ID through a small Swift helper, so an agent holding the API token still can't approve its own proposal.
- **Or runs fully local.** Pick "Fully local" and it installs llama.cpp, chooses a model by RAM (Qwen3 4B on a 16 GB Mac, up to Qwen3 30B-A3B), checks the download's SHA-256 and runs it only while you're asking. Testing small models taught me they confidently guess, so Hashling now hands the model the live facts (score, open findings, plus storage or what-changed data when the question needs it) before it says a word.
- **The usual checks, in plain words.** Per-app network connections, startup items, TCC permissions, ClamAV + YARA-X with Apple's XProtect and Elastic's macOS rules, a ransomware tripwire, scam check for texts, links and screenshots, breach watch, AirTag-style trackers, and a read-only phone check-up over USB.

Honest limits:

- It is not a firewall. It does not block connections live (pair it with LuLu or Little Snitch).
- It scans files shortly after they arrive, not before they run. Malwarebytes and Bitdefender intercept in real time.
- Bitdefender's AI Guardian beta (announced September 30) blocks risky agent actions in real time. Hashling observes, explains and proposes.
- Zero findings does not prove a Mac is clean.

Install: download the signed installer and double-click it (no Terminal, no admin password), or use the one-line installer. It is Apple silicon only, macOS 14+.

Stack: a Node 24 daemon on loopback (node:sqlite, no native modules), a dashboard at hashling.localhost:5750 behind a Touch ID unlock, and small Swift helpers for Touch ID, OCR, Bluetooth and the menu bar. Releases are notarized, CI boots it in a sandbox on a macOS runner for every commit.

The first time I ran it on my own Mac, it found API keys sitting in plain text in my AI agents' config files. That's the kind of thing I wanted to be able to see at a glance.

Demo (75 s): https://gethashling.com/#demo
Compared with Little Snitch, LuLu, Malwarebytes, Bitdefender and Snyk: https://gethashling.com/compare

I'm around all day for questions, especially about the agent audit and the local-model grounding.
