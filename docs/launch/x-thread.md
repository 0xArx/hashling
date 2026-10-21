# X thread

> 5 to 7 posts. Post 1 is the hook; the rest expand. Keep each under 280 chars where possible. Thread them as replies to the first post.

---

**Post 1 (hook)**
Launching Hashling: your personal cybersecurity engineer for the age of AI. Free and open source, for Mac.

You connect it to Claude Code (or any MCP agent), ask "is my Mac safe?", and your AI actually checks before it answers. Touch ID for every fix.

hashling.vercel.app

---

**Post 2**
The part I built it for: Claude Code, Cursor, Codex all have broad access to your Mac by default.

Hashling shows you what each agent is allowed to do, what MCP servers are connected, and whether any keys are sitting in their config files. All in plain words.

---

**Post 3**
It watches a lot more than just AI tools.

Network connections per app. Startup items. Privacy permissions. Malware (ClamAV + YARA-X + Apple XProtect). Scam check for texts and links. Breach watch. Ransomware tripwire. Phone check-up via cable.

Plain words throughout. Simple/Standard/Expert mode.

---

**Post 4**
Honest about what it does NOT do:

It does not block connections live (pair it with LuLu for that). It scans files after arrival, not before they run. It has not been tested by independent security labs. Zero findings does not mean a clean Mac.

---

**Post 5**
[FOUNDER: Personal story post. Something like: "The first time I ran the AI audit on my own Mac, I found X" or "I built this after Y happened." Keep it honest and specific. 2-3 sentences.]

---

**Post 6**
MIT licensed. No account. No cloud. No tracking.

Everything runs on your Mac and stays there. The dashboard lives at hashling.localhost:5750 on loopback only. Your AI can look but never change anything without your OK.

github.com/0xArx/hashling

---

**Post 7 (CTA)**
Install in one line:

curl -fsSL hashling.vercel.app/install.sh | sh

Connect to Claude Code:
claude mcp add --scope user hashling -- hashling mcp

Then: "Is my Mac safe?"

Stars and feedback welcome.
