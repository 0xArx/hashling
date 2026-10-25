# Contributing to Hashling

Thanks for helping. Hashling is a security app, so the bar is simple: every change should be easy to read, easy to check, and never surprise the person using it.

Found a security problem? Do not open an issue. [Report it privately](SECURITY.md).

## Run it from source

You need a Mac with Apple silicon, macOS 14 or newer, and Node 24.

```sh
git clone https://github.com/0xArx/hashling.git
cd hashling
npm ci
npm run check   # type check
npm test        # phone encryption test + a smoke test that boots Hashling in a sandbox
```

To try a change without touching an installed copy, run a second Hashling with its own data folder and port:

```sh
export HASHLING_HOME=/tmp/hashling-dev HASHLING_PORT=5850
npm start
```

To open its dashboard, ask it for a one-time sign-in link (from a second Terminal window, after running the same `export` line) and open the `url` it returns:

```sh
curl -s -X POST -H "Authorization: Bearer $(cat "$HASHLING_HOME/token")" http://127.0.0.1:5850/api/session-code
```

The full install (Hashling.app, menu bar, scanning engines) is `./install.sh`.

## How the code is laid out

| Folder | What lives there |
|---|---|
| `src/` | The daemon: `daemon.ts` starts everything, `server.ts` is the local API, `mcp.ts` is the MCP server, `actions.ts` runs approved fixes. |
| `src/collectors/` | One file per thing Hashling watches (network, AI agents, startup items, permissions, trackers and more). Collectors only read. |
| `src/intel/` | Joins the dots: reputation lookups, breach watch, ransomware tripwire, what changed, linked warning signs. |
| `src/lib/` | Small shared helpers (running commands safely, code signatures, osquery, redaction). |
| `dashboard/` | The dashboard served at `hashling.localhost:5750`, plain HTML, CSS and JavaScript. `dashboard/phone/` is the phone app. |
| `helpers/` | Small Swift tools: the menu bar app and launcher, Touch ID approval, on-device text reading, Trash, Bluetooth trackers. |
| `bin/hashling` | The `hashling` command. |
| `scripts/` | Installer, helper build, release, changelog and tests. |
| `site/` | The website at hashling.vercel.app. |
| `docs/` | Test results, the certification plan and launch drafts. |

## Ground rules

- **Looking never changes anything.** Collectors, the API and MCP tools only read. Anything that changes the Mac goes through `propose_action` and waits for Touch ID.
- **Untrusted text stays data.** File, app and website names can be written by attackers. Never treat them as instructions.
- **Plain words.** Write for someone who is not a security expert. No em dashes in user-facing text; use periods or commas.
- **No noise.** A warning has to be worth someone's attention. Merge repeats and leave out low-value findings.
- **Hashling speaks as itself.** In the app it talks in the first person ("I found…"). The website and docs describe it in the third person.

## Pull requests

Keep each pull request to one change, say what it does for the person using Hashling, and make sure `npm run check` and `npm test` pass. User-facing changes get a line in the changelog: add a plain-word entry to `scripts/changelog.mjs` and run `npm run changelog`.
