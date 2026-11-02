# Show HN

**Title** (80 characters max, this one is 71):

```
Show HN: Hashling, your own AI security engineer watching your Mac 24/7
```

**URL to submit:** https://github.com/0xArx/hashling
(HN readers prefer the repo. The site and demo are linked in the comment.)

---

## First comment (post it right after submitting)

Hi HN, I'm Abdulrahman. Hashling is a free, MIT-licensed security agent for macOS. The idea: most people can't read a firewall alert or tell whether a startup item is dangerous, and they've never had anyone to ask. AI changes that. Hashling gives a normal person their own cybersecurity engineer, watching their Mac 24/7 and answering in plain words.

What it does:

- **Becomes your security engineer, with your own AI.** Connect Claude Code (one command) or any MCP client and ask "is my Mac safe?". The AI calls Hashling's tools (overview, findings, network, uploads, storage, osquery and more) and answers from real data, not guesses. AI can only read and propose: every change waits for Touch ID through a small Swift helper, so an agent holding the API token still can't approve its own proposal.
- **Or runs fully local.** Pick "Fully local" and it installs llama.cpp, chooses a model by RAM (Qwen3 4B on a 16 GB Mac, up to Qwen3 30B-A3B), checks the download's SHA-256 and runs it only while you're asking. Testing small models taught me they confidently guess, so Hashling now hands the model the live facts (score, open findings, plus storage or what-changed data when the question needs it) before it says a word.
- **Watches 24/7, in plain words.** Per-app network connections, startup items, TCC permissions, ClamAV + YARA-X with Apple's XProtect and Elastic's macOS rules, a ransomware tripwire, breach watch, AirTag-style trackers, and a read-only phone check-up over USB.
- **Checks scams before you click.** Paste a text, email or link, or drop in a screenshot.
- **Watches what goes in and out.** How much each app uploaded and to where, first contact with new destinations, where every download came from and who signed it, and API keys or secrets left in plain text.
- **Keeps AI coding agents in check, too.** For Claude Code, Codex, Cursor, Claude Desktop, VS Code, Windsurf, Gemini CLI and OpenCode it reads permission modes, allow rules, hooks and MCP servers, and catches booby-trapped repos (TrustFall, GitSpawn and GhostApproval patterns). It uses git authorship and macOS's download marker to separate your own setups from a stranger's.

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

I'm around all day for questions, especially about the local-model grounding and the MCP design.
