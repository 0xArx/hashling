# r/ClaudeAI post

> Note: r/ClaudeAI allows self-promotion if it is clearly relevant and you are transparent about being the developer. Add "I built this" early. Follow the sub's rules and do not spam. One post, no follow-up bumps.

---

**Title:** I built a free open-source tool that lets Claude Code audit your Mac's security. Ask it "is my Mac safe?" and it actually checks.

---

**Body:**

I want to share something I built that might be useful to people here who use Claude Code or Cursor regularly.

**The problem:** AI coding agents like Claude Code have broad access to your Mac by default. They can read files, run commands, install things, and talk to the internet. Most people (including me, until recently) have no easy way to see what permissions each agent actually has, what MCP servers they are connected to, or whether any keys have been left in their configuration files.

**What I built:** Hashling is a free, open-source security agent for Mac (MIT license) that connects to Claude Code via MCP. Once it is set up, you can type something like:

```
Is my Mac safe? Are my AI tools configured securely?
```

and Claude will call Hashling's tools behind the scenes, check your Mac's security state, and answer in plain words. It can see:

- What permissions each AI app has on your Mac
- What MCP servers are connected and what they can do
- Whether any passwords or keys have been left in settings files
- Live network connections per app
- Startup items, privacy permissions, malware scan results, and more

And it does not change anything by itself. Every fix waits for your Touch ID.

**How to set it up with Claude Code:**

1. Install Hashling: `curl -fsSL https://hashling.vercel.app/install.sh | sh`
2. Connect Claude Code: `claude mcp add --scope user hashling -- hashling mcp`
3. Ask: "Is my Mac safe?"

**Honest limitations:**

Hashling is not a firewall and does not block connections live (pair it with LuLu for that). It catches malware a few seconds after files arrive, not before they run. Zero findings does not mean a Mac is clean.

It is a tool for understanding your setup in plain words and connecting your AI to your own security, not a replacement for purpose-built security software.

Site: https://hashling.vercel.app
GitHub: https://github.com/0xArx/hashling

Happy to answer questions. [FOUNDER: Add a note about your experience using it yourself, or what you found the first time you ran the AI agent audit on your own machine.]
