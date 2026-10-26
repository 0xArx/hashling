# Product Hunt

Everything the submission form asks for, in order. Images are in `docs/launch/assets/`.

**Name:** Hashling

**Tagline** (60 characters max, this is 54):
```
Your personal cybersecurity engineer for the age of AI
```

**Links:** https://hashling.vercel.app (website), https://github.com/0xArx/hashling (GitHub)

**Description** (260 characters max, this is 246):
```
Free, open-source security for your Mac. See what Claude Code, Codex and Cursor are allowed to do, check texts for scams, and ask your own AI (or one running fully on your Mac) "am I safe?". Plain words, and nothing changes without your Touch ID.
```

**Topics:** Security, Mac, Artificial Intelligence, Open Source, Developer Tools

**Pricing:** Free

**Thumbnail** (240 x 240): `assets/ph-thumbnail.png`

**Gallery** (1270 x 760, in this order):
1. `assets/ph-1-hero.png`: Your personal cybersecurity engineer for the age of AI
2. `assets/ph-2-agents.png`: See what every AI agent on your Mac can do
3. `assets/ph-3-scam.png`: Is this a scam? Paste it in
4. `assets/ph-4-local.png`: An AI that runs fully on your Mac
5. `assets/ph-5-control.png`: Nothing changes without your Touch ID

**Video:** Product Hunt takes a YouTube link. Upload `site/assets/demo/hashling-demo.mp4` to YouTube (unlisted is fine) and paste the link.

**Maker's first comment** (post it the moment the launch goes live):

Hi Product Hunt! I'm Abdulrahman, the solo developer behind Hashling.

AI agents like Claude Code, Codex and Cursor can now run programs, read files and push code on our Macs. I wanted a simple answer to "what is each one allowed to do?", and that grew into a personal security agent that explains everything in plain words.

What makes it different:
🤖 It audits the AI agents on your Mac: their permissions, MCP servers, keys left in config files, and live network use.
💬 Your own AI becomes your security engineer. Connect Claude through MCP and ask "is my Mac safe?", or switch on Fully local and a free model runs on your Mac, so nothing leaves it.
🔐 It can only look and suggest. Every change waits for your Touch ID, and most can be undone.

It also checks texts and links for scams, scans for malware, watches startup items, permissions and trackers, and checks your phone over USB.

Being upfront: it isn't a firewall, and it scans files shortly after they arrive rather than blocking them first. The compare page says where other tools do better: https://hashling.vercel.app/compare

It's free, MIT-licensed, notarized by Apple, with no account and no tracking. I'd love your feedback, especially on what's confusing.

[FOUNDER: optional one line about what it found on your own Mac.]

---

## Replies to have ready

- **"Is it really free? What's the catch?"** Free and open source (MIT). No account, no ads, no data collection. If it ever has paid extras, the core stays free.
- **"Windows?"** On the way, along with a browser extension. Watch the GitHub repo for releases.
- **"Intel Mac?"** Apple silicon only for now (M1 or newer, macOS 14+).
- **"Does it send my data anywhere?"** Your files never leave your Mac. Questions go only to the AI you choose, or nowhere at all in Fully local mode.
- **"How is this different from an antivirus?"** Antivirus blocks known bad files. Hashling explains your whole setup in plain words, watches your AI tools, and lets your own AI help, with every fix behind Touch ID. Many people run both.
