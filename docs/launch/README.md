# Launch playbook

Everything for launching Hashling on Hacker News, Reddit, X and Product Hunt. Nothing here has been posted.

## What's in this folder

| File | Where it goes |
|---|---|
| `show-hn.md` | Hacker News. Title, URL and the first comment |
| `reddit-localllama.md` | r/LocalLLaMA. The local AI story and what small models taught us |
| `reddit-claudeai.md` | r/ClaudeAI. Auditing Claude Code and connecting Claude through MCP |
| `reddit-macapps.md` | r/macapps. Friendly, non-technical |
| `x-thread.md` | X. Eight posts, video first |
| `product-hunt.md` | Product Hunt. Every form field, the maker comment and ready answers |
| `assets/ph-1…5-*.png` | Product Hunt gallery, 1270 × 760. They also work as X and Reddit images |
| `assets/ph-thumbnail.png` | Product Hunt thumbnail, 240 × 240 |
| `../../site/assets/demo/hashling-demo.mp4` | The 75-second demo with captions |

The founder lines are filled in with one true story: the first run found API keys in plain text in AI agents' config files. Change it to your own words if you like. A true, specific line about why you built it does more than anything else in a post.

## 1. The week before

- [ ] **Get 5 to 10 real people to install it** on their own Macs (friends, colleagues, one non-technical person). Watch where they get stuck and fix it. A launch with zero outside installs is a gamble.
- [ ] **Install it yourself on a clean Mac account** (System Settings, Users & Groups, add a user) with the double-click installer from gethashling.com/start, start to finish.
- [ ] **Upload the demo to YouTube** (unlisted is fine). Product Hunt needs a YouTube link.
- [x] **GitHub repo description** updated to the new tagline (done 26 October 2026).
- [x] **Founder lines** written (26 October 2026).
- [x] **Own domain and privacy page:** gethashling.com and gethashling.com/privacy (26 October 2026).
- [ ] **Read each subreddit's rules** in its sidebar. Most allow a developer's own post once, with the right flair, and remove anything that looks like an ad.
- [ ] **Clear your calendar** for launch days. The first 3 hours of replies decide how a post does.

## 2. The order

Space it out so you can answer everyone, and so feedback from one launch improves the next.

| When | Where | Notes |
|---|---|---|
| Day 1, Tue or Wed, 8 to 10 am US Eastern | **Show HN** | Submit the GitHub URL with the title from `show-hn.md`, then post the first comment right away. |
| Day 1, afternoon | **X thread** | Video in post 1. Link the HN post in a reply if it's doing well. |
| Day 2 | **r/LocalLLaMA** | The most technical story. Reply with numbers and code links. |
| Day 3 | **r/ClaudeAI** | Different angle: auditing Claude Code. |
| Day 4 or 5 | **r/macapps** | Plain-words version for everyday Mac users. |
| A week later, Tue to Thu at 12:01 am Pacific | **Product Hunt** | Schedule it in advance. By then you'll have stars, feedback and fixes to mention. |

Don't post the same text in several subreddits on the same day. Reddit treats that as spam.

## 3. On launch day

- Reply to every comment, quickly and kindly, even the harsh ones. Thank people for bug reports and fix them the same day if you can.
- Never ask for upvotes, on any site. HN and Product Hunt penalise it, and Reddit bans it. You can tell people the post is live.
- When you fix something people asked for, say so in the thread and add it to the changelog (`npm run changelog`). Visible progress on launch day earns trust.
- Keep a list of every question. The good ones become FAQ entries on the site.

## 4. The week after

- Post a short "what changed since launch" on X with real numbers (installs, stars, fixes).
- The site's proof strip shows the GitHub star count by itself once it reaches 25, and download counts once they reach 100.
- Write up what you learned. The local-model grounding story (`reddit-localllama.md`) can grow into a blog post.

## Rules for every post

- Say you're the developer.
- Keep the honest limits in: not a firewall, scans files after they arrive, zero findings doesn't prove a Mac is clean. Leaving them in earns more trust than it costs.
- Don't claim lab testing, user numbers or quotes that aren't real.
- No em dashes in copy.
