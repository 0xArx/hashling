# Security policy

Hashling is a security tool, so a hole in Hashling is a hole in your Mac's defences. If you find one, thank you. Please tell us privately first, so it can be fixed before anyone else learns about it.

## How to report a problem

**Please do not open a public issue for a security problem.**

1. Go to the [Security tab](https://github.com/0xArx/hashling/security) of this repository.
2. Press **Report a vulnerability**. (Direct link: [new private report](https://github.com/0xArx/hashling/security/advisories/new).)
3. Tell us what you found, how to make it happen, and what an attacker could do with it. A short video or a proof of concept helps, but is not required.

Only you and the maintainer can see the report. You need a free GitHub account to send one.

Things that are especially worth reporting:

- Anything that lets a website, app or other user on the Mac change the Mac **without** the owner's Touch ID approval.
- Anything that lets someone else reach the dashboard, the API key in `~/.hashling/token`, or the phone pairing channel.
- A way to make Hashling run a command, or to make the AI agent connected to Hashling do something it should not, by putting text in a file name, process name, web page, email or text message (prompt injection).
- A way to hide malware from Hashling's scans, or to make Hashling remove a file it should not.
- A problem in how the installer downloads, checks or signs anything.

## What happens next

| Step | When |
|---|---|
| We confirm we got your report | within 3 days |
| We tell you whether we can reproduce it and how serious it is | within 7 days |
| Fix released for a critical or high problem | aim: within 14 days |
| Fix released for a medium or low problem | aim: within 60 days |

We keep you updated while we work on it. When the fix is out we publish a security advisory on GitHub and, if you like, credit you by name. Please give us the chance to ship a fix before you talk about the problem publicly. If 90 days pass without a fix, you are free to publish.

Hashling is a free project with one maintainer and no bug bounty, so we cannot pay for reports. We are very grateful for them all the same.

## Supported versions

| Version | Gets security fixes |
|---|---|
| The latest release and the `main` branch | Yes |
| Anything older | No, please update |

The installer always installs the latest code from `main`, and running it again updates Hashling in place.

## How Hashling protects itself

These are the rules Hashling is built on. A report that breaks one of them is always treated as serious.

- **Local only.** The dashboard and API listen on `127.0.0.1` (this Mac) only, and every request needs a secret key that only your user account can read.
- **The AI can only read.** The AI agent connected over MCP can look but cannot change anything. It can only *suggest* a fix.
- **Every change needs your Touch ID.** Quarantining a file, quitting an app, removing a startup item or blocking a site waits on the dashboard until you approve it with Touch ID (or your Mac password).
- **No account, no telemetry.** Hashling has no analytics and never uploads your files. The few things it looks up online (malware and scam lists, a new download's fingerprint, who owns an internet address) are listed under [You stay in control](README.md#you-stay-in-control) in the README.
- **Open source.** Every line is here to read, under the MIT license.

## Checking what you downloaded

Each [release](https://github.com/0xArx/hashling/releases) includes a `SHA256SUMS.txt` file. After downloading, you can check a file has not been changed:

```sh
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
```

The `Hashling.app` in each release is signed with the maintainer's Apple Developer ID (team `VP9VT747BA`) and notarized by Apple. You can confirm that with:

```sh
spctl --assess --type execute --verbose=2 Hashling.app
```

It should say `accepted` and `source=Notarized Developer ID`.
