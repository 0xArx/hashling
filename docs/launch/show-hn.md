# Show HN: Hashling, a free security engineer for your Mac that works with your AI

> Title (80 chars): Show HN: Hashling, a free security engineer for your Mac that works with your AI

**Link to submit:** https://hashling.vercel.app

---

## First comment (founder's voice)

Hi HN. Hashling is a personal cybersecurity engineer for the age of AI. It started from a simple question: AI coding agents like Claude Code, Cursor and Codex can run programs, read files and push code on my Mac, so what exactly is each one allowed to do? That turned into a broader personal security tool.

Hashling is free and open source (MIT). It runs entirely on your machine and watches the things that matter day to day: network connections per app, startup items, privacy permissions, AI coding agents and what they can do, malware (ClamAV + YARA-X + Apple's XProtect rules), scam check for texts and links, and a few newer things like breach watch, a ransomware tripwire, and text message scam watch.

The part I think is genuinely new: you connect Hashling to the AI you already have. Run one command and Claude Code (or Cursor, Codex, or any MCP agent) can ask your Mac about its own security. You can type "is my Mac safe?" and the agent calls Hashling's MCP tools, reads the findings, and tells you what needs attention in plain words. Every fix still waits for your Touch ID.

A few honest limitations I want to be upfront about:
- Hashling does not block network connections live. Pair it with LuLu or Little Snitch for that.
- It scans for malware after files arrive, not before they run. Malwarebytes and Bitdefender do the real-time interception and have been tested by independent labs. Hashling has not.
- The Bitdefender AI Guardian beta (launched last month) is a closer competitor for AI agent safety specifically. It blocks risky agent actions in real time. Hashling observes and explains.
- Zero findings in Hashling does not mean a Mac is clean.

[FOUNDER: Add a sentence about what triggered you to build this, or the first thing you found when you ran it on your own Mac that surprised you.]

The project is MIT licensed. Source: https://github.com/0xArx/hashling

Happy to answer questions about the architecture (it is a Node.js service running on loopback, a dashboard served at hashling.localhost:5750, and a set of MCP tools backed by osquery, ClamAV, YARA-X, and libimobiledevice).
