#!/usr/bin/env node
/**
 * changelog.mjs
 * Reads git log from the current repo and writes the <main> content
 * block of site/changelog.html.
 *
 * Usage:
 *   node scripts/changelog.mjs
 *
 * To add or improve a commit's entry, edit ENTRIES below.
 * Each key is the short commit hash (7 chars), or the start of the commit
 * subject (handy for a commit whose hash is not known yet). The value has:
 *   title  - short human-readable title shown as the entry heading
 *   bullets - 1-3 plain-word bullet points for what changed for the user
 *   tag    - optional short label (e.g. "new feature", "fix", "design")
 */

import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

// ── Human summaries keyed by short hash ────────────────────────────────────
// Edit this map to improve how an entry reads. Unknown hashes fall back to
// the commit subject line plus a generic bullet.
const ENTRIES = {
  'Booby-trapped project folders:': {
    tag: 'new feature',
    title: 'I now catch project folders booby-trapped for your AI agents',
    bullets: [
      'I check the folders Claude Code, Cursor, VS Code, Codex and Gemini CLI opened for files that make an agent act by itself: a project’s own MCP servers, settings that switch off safety questions, add hooks or send your API traffic elsewhere, git settings that run commands, hidden git repositories, and shortcuts into ~/.ssh.',
      'I only warn when those came from someone else (another commit author, or a download). What you set up yourself stays quiet.',
      'Ask your AI about it: the new risky_projects tool shows the same list.',
    ],
  },
  // null leaves a commit out of the changelog (housekeeping nobody using Hashling would notice).
  'Launch materials: mark the repo description': null,
  'Changelog: leave housekeeping commits out': null,
  'Launch materials: 0.2.0 drafts': {
    tag: 'docs',
    title: 'Ready to share',
    bullets: ['Launch posts, Product Hunt images and a launch playbook, in docs/launch.'],
  },
  'Polish for 0.2.0:': {
    tag: 'polish',
    title: 'Fully local means fully local',
    bullets: [
      'While the AI on your Mac is still setting up, questions wait for it instead of opening in a cloud AI.',
      'The install guide, help pages and compare page now explain Update now and Fully local.',
    ],
  },
  'Local AI, tested with real models:': {
    tag: 'improvement',
    title: 'Sharper answers from the AI on your Mac',
    bullets: [
      'Before the AI on your Mac answers, I hand it the real facts first (your score, open warnings, and the data your question needs), so it never has to guess.',
      'Automatic now picks a model that gets details right (Qwen3 4B or bigger). The tiny model stays available if you choose it.',
      'Model downloads that stall or drop pick up where they stopped.',
      'My own rule files are no longer mistaken for malware when my data folder sits somewhere I scan.',
    ],
  },
  'Hashling 0.2.0:': {
    tag: 'new feature',
    title: 'Update now, and an AI that runs fully on your Mac',
    bullets: [
      'When a new version is out, an Update now button appears. It asks for your Touch ID, checks the download against its published checksum, and keeps your settings and history.',
      'Fully local mode: Hashling picks a free open model that fits your Mac (or one you choose, or your own Ollama or LM Studio), downloads it once and runs it on your Mac. Nothing you ask leaves it.',
      'The AI apps table and warning lists read better on a phone.',
    ],
  },
  'Security updates:': {
    tag: 'security',
    title: 'Security updates for the parts Hashling is built on',
    bullets: ['Three building blocks Hashling uses for AI connections got their latest security fixes. Nothing changes in how Hashling looks or works.'],
  },
  'Production polish:': {
    tag: 'website',
    title: 'A clearer website and a safety net for every change',
    bullets: [
      'The home page now starts with what Hashling does for the AI agents on your Mac, with a sharper picture of the AI agents table.',
      'Grey text on the website is darker and easier to read.',
      'Every change is now tested by starting Hashling on a real Mac, and there is a guide for anyone who wants to help.',
    ],
  },
  'Launch drafts:': {
    tag: 'docs',
    title: 'Tidier launch drafts',
    bullets: ['The drafts for the public launch stick to what Hashling does.'],
  },
  'Compare page: describe what each tool does': {
    tag: 'website',
    title: 'A tidier compare page',
    bullets: ['The compare page now sticks to what each tool does, in plain words.'],
  },
  'Privacy wording:': {
    tag: 'website',
    title: 'Clearer privacy wording',
    bullets: [
      'The website and the demo video now say exactly where your data can go: nothing leaves your computer except what you send to the AI provider you choose.',
    ],
  },
  'Website and README: drop the not-yet-tested note': {
    tag: 'website',
    title: 'A shorter trust section',
    bullets: [
      'The "Why you can trust Hashling" section on the website and the README is shorter and easier to read.',
    ],
  },
  'Launch kit:': {
    tag: 'website',
    title: 'A demo video, this changelog and an honest comparison page',
    bullets: [
      'The home page now opens with a 75 second recording of Hashling at work.',
      'This page lists every update in plain words, newest first.',
      'A new compare page shows how Hashling stacks up against Little Snitch, LuLu, Malwarebytes, Bitdefender and Snyk, including what they do better.',
    ],
  },
  '2810062': {
    tag: 'trust',
    title: 'A "Why you can trust Hashling" section on the website',
    bullets: [
      'The home page now lists what you can check for yourself: open source code, read-only AI access, Touch ID for every change and no tracking.',
      'A plan for independent testing is published in the repo.',
    ],
  },
  '309b03c': {
    tag: 'trust',
    title: 'Ways to check Hashling for yourself',
    bullets: [
      'A security policy explains how to report a problem privately.',
      'Every change is now scanned for security bugs, and the project is graded weekly by the OpenSSF Scorecard.',
      'Hashling catches the industry\'s standard test files for malware, and the results are published.',
    ],
  },
  '8aff17b': {
    tag: 'polish',
    title: 'Overview: one rail layout, no gaps, equal-size cards',
    bullets: [
      'Wide-screen overview now uses a single column with no empty corner.',
      'To-do card no longer shows duplicate items.',
      'Cards are equal size. Tabs that are already open pick up new data without a refresh.',
    ],
  },
  'a0ea140': {
    tag: 'design',
    title: 'Overview redesign: status band, tile grid, glanceable numbers',
    bullets: [
      'The overview page has a new layout: a status band at the top, tiles for each area, and numbers you can read at a glance.',
      'Every label now shows a plain-word explanation when you hover over it.',
    ],
  },
  '2cbfcf7': {
    tag: 'new feature',
    title: 'Breach watch, ransomware brake, text scam watch, AI picture check',
    bullets: [
      'Breach watch: add an email address and Hashling tells you if it turns up in a data breach.',
      'Ransomware brake: Hashling pauses a program that starts mass-renaming your files, then waits for your Touch ID.',
      'Text message scam watch: new texts from strangers are checked for scams like fake delivery fees.',
      'AI picture check: Hashling reads the labels AI tools leave in photos and videos to tell you if something was AI-made.',
    ],
  },
  '136f433': {
    tag: 'website',
    title: 'New website: plain-word landing page with Mac and Windows tabs',
    bullets: [
      'The Hashling website is now a clean 7-section page written in plain words.',
      'A Mac or Windows tab lets you see what is ready now and what is coming soon.',
      'Fresh screenshots throughout.',
    ],
  },
  '6d6414c': {
    tag: 'phone',
    title: 'Phone check-up: more checks, at-a-glance numbers, website section',
    bullets: [
      'The phone check-up now runs more checks on both iPhone and Android.',
      'Results show at-a-glance numbers so you can see the important points first.',
      'A new section on the website explains how phone check-up works.',
    ],
  },
  'db0468d': {
    tag: 'fix',
    title: 'Phone check-up: fixes after the first real iPhone test',
    bullets: [
      'Several small issues found during the first live iPhone run are now fixed.',
    ],
  },
  'f46a2a6': {
    tag: 'new feature',
    title: 'Phone check-up: plug in a phone and Hashling checks it',
    bullets: [
      'Plug an iPhone or Android into your Mac with a cable and Hashling offers a read-only check.',
      'It checks things like the iOS version, apps from outside the App Store, configuration profiles, and known stalkerware.',
      'Nothing about your phone leaves the Mac.',
    ],
  },
  '826ba3c': {
    tag: 'new feature',
    title: 'Phone mode: get Hashling on your phone over your own Wi-Fi',
    bullets: [
      'Scan the QR code in Settings and Hashling appears as a home-screen app on your phone.',
      'Your phone and Mac talk only over your own Wi-Fi. Every message is encrypted with ChaCha20-Poly1305.',
      'See your score, warnings, a scam check, and your approvals from your phone.',
    ],
  },
  'd9a09ed': {
    tag: 'fix',
    title: 'Suggestions: undecided items are now archived, not dropped',
    bullets: [
      'If you leave a suggestion without deciding, it is archived now instead of disappearing.',
      'Crucial fixes stay waiting until you act on them.',
      'Use "Bring back" or "Dismiss" any time from the Approvals page.',
    ],
  },
  '90bdc83': {
    tag: 'design',
    title: 'Motion: smoother animations and gentler reduced-motion mode',
    bullets: [
      'The score ring now draws in when the page loads.',
      'The sidebar highlight glides instead of jumping.',
      'Approve and reject actions show a quick confirmation animation.',
      'The reduced-motion setting is gentler throughout.',
    ],
  },
  '6d9aa03': {
    tag: 'polish',
    title: 'Calmer activity: fewer repeats, plainer approvals',
    bullets: [
      'Apps now count as new only once per version, so the activity feed is much quieter.',
      'Repeated entries are merged into one.',
      'Approval messages now use plain words instead of technical labels.',
    ],
  },
  'c68af4f': {
    tag: 'launch',
    title: 'Initial release: Hashling, your personal AI cybersecurity agent for Mac',
    bullets: [
      'Network monitoring, startup items, privacy permissions, AI agent auditing, malware scanning, scam check, and more.',
      'Ask anything in plain words. Hashling checks your Mac before it answers.',
      'Every fix waits for your Touch ID. No account, and nothing leaves your Mac except what you send to the AI provider you choose.',
    ],
  },
};

// ── Pull git log ────────────────────────────────────────────────────────────
const rawLog = execSync('git log --format="%h|%ad|%s" --date=short', { cwd: ROOT })
  .toString()
  .trim()
  .split('\n');

const commits = rawLog.map(line => {
  const [hash, date, ...subjectParts] = line.split('|');
  const subject = subjectParts.join('|');
  const bySubject = Object.keys(ENTRIES).find((k) => k.length > 7 && subject.startsWith(k));
  if (ENTRIES[hash] === null || (bySubject && ENTRIES[bySubject] === null)) return null;
  const entry = ENTRIES[hash] ?? ENTRIES[bySubject] ?? {
    title: subject,
    bullets: ['See the commit for details.'],
    tag: null,
  };
  return { hash, date, ...entry };
}).filter(Boolean);

// ── Group by date ───────────────────────────────────────────────────────────
const byDate = new Map();
for (const c of commits) {
  if (!byDate.has(c.date)) byDate.set(c.date, []);
  byDate.get(c.date).push(c);
}

// ── Render ──────────────────────────────────────────────────────────────────
function formatDate(iso) {
  const [year, month, day] = iso.split('-').map(Number);
  return new Date(year, month - 1, day).toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });
}

function entryHtml(c) {
  const tag = c.tag ? `<span class="cl-tag">${esc(c.tag)}</span>` : '';
  const bullets = c.bullets.map(b => `        <li>${esc(b)}</li>`).join('\n');
  return `      <article class="cl-entry">
        ${tag}
        <h3 class="cl-entry-title">${esc(c.title)}</h3>
        <ul class="cl-entry-bullets">
${bullets}
        </ul>
      </article>`;
}

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

let groupsHtml = '';
for (const [date, entries] of byDate) {
  const entriesHtml = entries.map(entryHtml).join('\n');
  groupsHtml += `    <section class="cl-group">
      <h2 class="cl-date">${esc(formatDate(date))}</h2>
      <div class="cl-entries">
${entriesHtml}
      </div>
    </section>\n`;
}

// ── Read the template file and splice in the generated block ────────────────
const outPath = resolve(ROOT, 'site/changelog.html');
let html = readFileSync(outPath, 'utf8');
html = html.replace(
  /<!-- CHANGELOG_START -->[\s\S]*?<!-- CHANGELOG_END -->/,
  `<!-- CHANGELOG_START -->\n${groupsHtml}    <!-- CHANGELOG_END -->`,
);
writeFileSync(outPath, html, 'utf8');
console.log('Wrote site/changelog.html');
