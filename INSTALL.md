# Installing Hashling

Hashling is your personal AI cybersecurity agent. It keeps watch over your Mac in the background, tells you in plain words if something is wrong, and fixes it when you say yes.

This guide assumes you have never used Terminal before. Every step says what you will see and what to click. Most people are done in about 10 minutes.

---

## 1. Check your Mac first (30 seconds)

Click the **Apple menu** (top-left corner of your screen), then **About This Mac**. You need:

| What it says | What Hashling needs |
|---|---|
| **Chip** | Apple M1, M2, M3, M4 or newer. (An "Intel" Mac will not work.) |
| **macOS** | 14 (Sonoma) or newer |

You also need:

- About **3 GB of free space**
- An **internet connection**
- Your **Mac password** (the one you use to log in)

---

## 2. Pick one way to install

All three ways do exactly the same thing. Pick the one that sounds easiest.

### Way A: Ask your AI to do it (easiest if you use one)

If you use Claude Code, Cursor, Codex or another AI agent that can run commands on your Mac, give it the Hashling folder (or the link to it) and say:

> Set up Hashling for me.

It reads the guide in [`SKILL.md`](SKILL.md), checks your Mac, installs Hashling, connects itself to Hashling, and tells you when it needs you (only for your password and two switches in System Settings).

### Way B: Download the installer (no typing, no password)

1. Open the [latest release](https://github.com/0xArx/hashling/releases/latest) and download **Hashling-x.y.z.pkg**.
2. Open it from your Downloads folder and follow the steps. It installs into your home folder, so it doesn't ask for your Mac password.
3. When it finishes, the **#** appears in your menu bar and the dashboard opens for a 2-minute setup.

It brings everything Hashling needs (its own copy of Node, the YARA-X and osquery engines), so there's nothing else to install. It's signed and notarized by Apple. The one thing it leaves out is the ClamAV virus scanner; Hashling still checks files with YARA-X and Apple's own malware rules, and the Terminal installer adds ClamAV if you want it.

### Way B2: The code folder and Install Hashling.command

1. Get the Hashling folder onto your Mac. On the GitHub page, click the green **Code** button, then **Download ZIP**, then double-click the downloaded ZIP to unpack it.
2. Open the **hashling** folder and double-click **Install Hashling.command**.
3. A Terminal window opens and the install starts. Skip to [What happens while it installs](#3-what-happens-while-it-installs).

**If macOS says it "cannot verify" the file:** this is normal for files downloaded from the internet. Click **Done**, then open **System Settings**, go to **Privacy & Security**, scroll down, and click **Open Anyway** next to "Install Hashling.command". Double-click it again.

**Prefer to skip that warning?** Use this trick instead:

1. Open **Terminal**: press **Command + Space**, type `Terminal`, press **Return**.
2. Type `sh` followed by a space (do not press Return yet).
3. Drag the file **install.sh** from the hashling folder into the Terminal window. Its location appears after `sh `.
4. Press **Return**.

### Way C: One line in Terminal

1. Open **Terminal**: press **Command + Space**, type `Terminal`, press **Return**.
2. Copy this line, paste it into Terminal (**Command + V**), and press **Return**:

```sh
curl -fsSL https://gethashling.com/install.sh | sh
```

This downloads the latest Hashling straight from GitHub, so you do not need to download the folder first.

---

## 3. What happens while it installs

Hashling introduces itself, then shows six numbered steps. You can keep using your Mac while it works. It only stops to ask you something in the places marked **You**.

| Step | What happens | Time |
|---|---|---|
| **1. Checking the tools I need** | Makes sure **Homebrew** is installed. Homebrew is a free, widely used tool for installing software on Macs; Hashling uses it to get its scanners. | seconds, or 5 to 15 minutes the first time |
| **2. Installing the scanning engines** | Installs ClamAV and YARA-X (open-source malware scanners) and Node (which runs Hashling). | 1 to 5 minutes |
| **3. Adding osquery** | An open-source tool that lets Hashling see what is running on your Mac. | under a minute |
| **4. Downloading my latest version** | Downloads Hashling itself and sets it up. | under a minute |
| **5. Downloading the latest malware fingerprints** | About 110 MB of virus signatures. They update themselves from now on. | 1 to 3 minutes |
| **6. Starting up** | Builds the Hashling app, starts it, and adds it to your login items so it runs every time you log in. | under a minute |

### You: the questions it may ask

- **"Install Homebrew now? [Y/n]"** (only if Homebrew is not on your Mac yet). Press **Return** to say yes.
- **"Password:"** Homebrew asks for your Mac password once. Type it and press **Return**. **Nothing appears while you type, not even dots. That is normal.** It is still reading what you type.
- **A window about "Command Line Tools"** (only on some Macs). These are free tools from Apple. Click **Install**, then **Agree**. The Hashling installer waits and carries on by itself when they are done.
- **"Press RETURN to continue"** (from Homebrew). Press **Return**.
- **"Connect me to Claude Code…? [Y/n]"** (only if you have Claude Code). Press **Return** to say yes, so you can ask Claude "is my Mac safe?".
- **macOS pop-ups** asking to allow **notifications** or **Bluetooth** for Hashling: click **Allow**. Notifications are how Hashling warns you; Bluetooth lets it spot hidden trackers like AirTags.

When you see **"All set. I’m installed and keeping watch over this Mac."** you are done with Terminal. You can close it.

---

## 4. The 2-minute setup

Your web browser opens the Hashling dashboard by itself with a short setup. Five screens:

1. **Welcome.** Click **Set up in 2 minutes**.
2. **How much detail.** Choose **Simple** unless you work in tech. Simple shows only what most people need, in plain words. You can change it any time in Settings.
3. **Full Disk Access.** This lets Hashling check things macOS keeps private, like which apps can use your camera. Hashling only looks; it never changes anything without your Touch ID.
   1. Click **Open System Settings**.
   2. Find **Hashling** in the list and turn its switch **on**. If Hashling is not in the list, click **+**, open your home folder, then **Applications**, and choose **Hashling**.
   3. Type your Mac password if asked.
   4. Come back to the dashboard and click **Check again**. If it still says off, click **Restart Hashling** (macOS sometimes needs that once).

   This step is optional, but Hashling can check much more with it.
4. **AI helper (optional).** If you have a Claude account, click **Connect Claude** so you can ask Hashling questions in your own words. No account? Click **Skip for now**. Every warning already comes with a plain explanation.
5. **Recommended protection.** Two switches most people should turn on:
   - **Safe browsing** blocks known scam and malware websites in every browser. It asks for your Mac password.
   - **Lock away malware automatically** moves any file that matches known malware into a safe place where it cannot run. You can always restore it.

Then click **Show me my Mac's check-up**. Hashling's first full check takes a few minutes.

---

## 5. Everyday use

- **The # in your menu bar** (top-right of your screen) is Hashling. Click it to open the dashboard.
- **The dashboard** lives at **`http://hashling.localhost:5750`** (an address that always means your own Mac). If you open it in a new browser, it asks you to unlock it with **Touch ID**, so nobody else can read it.
- **Warnings** pop up as notifications. The most serious ones also show a window you cannot miss.
- **Nothing changes on your Mac without you.** Every fix, from Hashling or from your AI, waits on the **Approvals** page until you approve it with Touch ID.

---

## 6. Updating and removing

**Update Hashling:** When a new version is out, Hashling shows an **Update now** button in its dashboard. It asks for your Touch ID, checks the download against the release's published checksum, and keeps your settings, history and approvals. Installing again the same way also works.

**Remove Hashling:** open Terminal and run:

```sh
hashling uninstall --all
```

It removes Hashling and then lists anything it left behind (such as websites you blocked with it), so nothing stays on your Mac by surprise. Before you remove it, check the **Approvals** page for files in quarantine you want back.

---

## 7. If something goes wrong

Hashling's installer explains every problem in plain words and says what to do. The most common ones:

| You see | What to do |
|---|---|
| "Hashling needs a Mac with Apple silicon" | Hashling cannot run on Intel Macs. |
| "Hashling needs macOS 14 (Sonoma) or newer" | Update macOS: **System Settings**, **General**, **Software Update**. |
| "Hashling needs about 3 GB of free space" | Empty the Trash or delete a few large files, then install again. |
| "Homebrew did not finish installing" | Usually a network hiccup. Install Hashling again. |
| "Could not reach GitHub" | Check your internet connection and try again. |
| "Hashling isn't available to download yet" | The one-line install only works once Hashling's code is published. Use Way B with the downloaded folder instead. |
| "Could not set up the parts Hashling needs" | A brief network problem. Install again. |
| "Could not build the Hashling app" | Apple's Command Line Tools are missing or broken. In Terminal run `xcode-select --install`, click **Install**, wait for it to finish, then install Hashling again. |
| "Hashling did not start" | Run `hashling logs` in Terminal to see why, or install again. |
| `hashling: command not found` | Open a **new** Terminal window (the old one does not know about Hashling yet). |
| The dashboard does not open | Click the # in the menu bar, or go to `http://hashling.localhost:5750`. |
| "Hashling can't see everything yet" | Full Disk Access is off. See step 3 of [the setup](#4-the-2-minute-setup). |
| No warnings ever appear | Notifications are off. **System Settings**, **Notifications**, **Hashling**, turn on **Allow notifications**. |

Running the installer again is always safe. It skips what is already done and fixes what is missing.

Every installer run keeps a detailed log; when something fails, the message shows where it is.

---

## What gets installed, and where

Hashling installs only what it needs, and nothing outside your user account except the Homebrew tools.

| What | Where |
|---|---|
| Node 24, ClamAV, YARA-X | Homebrew (`/opt/homebrew`) |
| Hashling itself and osquery | `~/.hashling` (a hidden folder in your home folder) |
| Your settings, history and quarantine | `~/.hashling` |
| The Hashling app (menu bar shield) | `Applications` inside your home folder |
| The `hashling` command | `/opt/homebrew/bin/hashling` |
| A login item so Hashling starts when you log in | `~/Library/LaunchAgents/dev.hashling.agent.plist` |
| A guide for AI agents (only if you use Claude Code) | `~/.claude/skills/hashling` |

**Privacy:** Hashling has no account and no cloud. It runs on your Mac and never uploads your files. It downloads updates (malware fingerprints and lists of scam websites). Your AI helper, if you connect one, only sees what you ask it about. Switch on **Fully local** in Settings and the AI runs on your Mac instead, so nothing you ask leaves it.

---

## For developers and testers

Install from a copy of the repo with `./install.sh`. To try the installer without touching a real install:

```sh
HOME=/tmp/hashling-test HASHLING_SKIP_SIGNATURES=1 HASHLING_NO_START=1 ./install.sh
```

| Variable | Effect |
|---|---|
| `HASHLING_SOURCE=/path/hashling.tgz` | Install from a local archive instead of GitHub |
| `HASHLING_SKIP_SIGNATURES=1` | Skip the 110 MB ClamAV download |
| `HASHLING_NO_START=1` | Build everything, but do not link, start or open Hashling |
| `HASHLING_ANSWER=y` or `n` | Answer the yes/no questions without a keyboard |
| `HASHLING_BREW_PATH=/nonexistent` | Pretend Homebrew is missing (tests the Homebrew prompt) |
