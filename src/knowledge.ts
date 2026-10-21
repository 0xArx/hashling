/**
 * Plain-English notes about common macOS processes and software, used to
 * explain what the user is looking at. Keys are process names (case-insensitive).
 */
export const PROCESS_NOTES: Record<string, string> = {
  apsd: 'Apple Push Notification service. Keeps one connection to Apple open so apps can receive notifications.',
  trustd: 'Checks certificates when apps make secure connections, including revocation checks with Apple and certificate authorities.',
  nsurlsessiond: 'Performs background downloads and uploads for apps and system services (iCloud, App Store, updates).',
  cloudd: 'iCloud sync engine for CloudKit data used by apps like Notes, Reminders and Photos.',
  bird: 'iCloud Drive file sync.',
  fileproviderd: 'Syncs cloud storage folders such as iCloud Drive, Google Drive and Dropbox.',
  akd: 'Apple ID authentication.',
  identityservicesd: 'Identity service for iMessage and FaceTime.',
  imagent: 'Messages (iMessage) background agent.',
  rapportd: 'Lets your Apple devices find each other (Handoff, Continuity, AirDrop helpers).',
  sharingd: 'AirDrop, Handoff and sharing features.',
  mdnsresponder: 'Resolves domain names (DNS) and discovers devices on the local network (Bonjour).',
  locationd: 'Location Services. Determines your location for apps you have allowed.',
  parsecd: 'Spotlight and Siri suggestions. Sends search queries to Apple when Siri Suggestions are on.',
  'com.apple.geod': 'Apple Maps data and geocoding.',
  geod: 'Apple Maps data and geocoding.',
  softwareupdated: 'Checks for and downloads macOS updates.',
  'com.apple.webkit.networking': 'Network process for Safari and apps that show web content.',
  'com.apple.safari.safebrowsing.service': 'Safari Safe Browsing checks against known malicious sites.',
  'com.apple.safari.safebrowsing': 'Safari Safe Browsing checks against known malicious sites.',
  syspolicyd: 'Gatekeeper. Checks downloaded apps against Apple notarization records.',
  xprotect: 'XProtect, the built-in macOS malware scanner.',
  xprotectservice: 'XProtect, the built-in macOS malware scanner.',
  mobileassetd: 'Downloads system assets such as fonts, voices, dictionaries and security data updates.',
  amsaccountsd: 'App Store and Apple Media Services account sync.',
  storedownloadd: 'App Store downloads.',
  commerce: 'App Store purchases.',
  timed: 'Keeps the system clock accurate (network time).',
  ntpd: 'Keeps the system clock accurate (network time).',
  netbiosd: 'Windows file-sharing name lookups on the local network.',
  remoted: 'Communicates with other Apple devices over USB or network.',
  symptomsd: 'Network diagnostics and usage statistics for the system.',
  networkserviceproxy: 'Apple network relays such as iCloud Private Relay.',
  'controlcenter': 'Control Center and menu bar status items.',
  dasd: 'Schedules background tasks.',
  'siriknowledged': 'Siri knowledge and suggestions.',
  assistantd: 'Siri.',
  'familycircled': 'Family Sharing.',
  findmydeviced: 'Find My for this Mac.',
  searchpartyd: 'Find My network (locating devices and AirTags).',
  'spotlightknowledged': 'Spotlight knowledge results.',
  sshd: 'SSH server. Allows remote command-line login to this Mac.',
  'screensharingd': 'Screen Sharing / Remote Management server.',
  'ardagent': 'Apple Remote Desktop agent.',
  launchd: 'The first process; starts and manages every other service.',
  kernel_task: 'The macOS kernel.',
  claude: 'Claude (Anthropic) app or Claude Code CLI.',
  node: 'Node.js runtime. Often used by developer tools, AI coding agents and MCP servers.',
  python: 'Python interpreter. Common for scripts, developer tools and AI tooling.',
  python3: 'Python interpreter. Common for scripts, developer tools and AI tooling.',
  'google chrome helper': 'Google Chrome helper process (tabs, extensions, network).',
  'google chrome': 'Google Chrome web browser.',
  'brave browser helper': 'Brave browser helper process.',
  firefox: 'Firefox web browser.',
  safari: 'Safari web browser.',
  slack: 'Slack messaging.',
  discord: 'Discord chat.',
  zoom: 'Zoom video calls.',
  'zoom.us': 'Zoom video calls.',
  spotify: 'Spotify music streaming.',
  dropbox: 'Dropbox file sync.',
  code: 'Visual Studio Code editor.',
  cursor: 'Cursor AI code editor.',
  docker: 'Docker containers.',
  'com.docker.backend': 'Docker Desktop backend.',
  anydesk: 'AnyDesk remote-access tool. Lets someone control this Mac remotely when a session is accepted.',
  teamviewer: 'TeamViewer remote-access tool. Lets someone control this Mac remotely.',
  ollama: 'Ollama local model server.',
  git: 'Git version control (fetching or pushing code).',
  'git-remote-https': 'Git talking to a remote repository over HTTPS.',
  curl: 'curl command-line downloader. Worth noticing when an agent or script uses it.',
  wget: 'wget command-line downloader.',
  ssh: 'SSH client: an outgoing remote shell or tunnel.',
  nc: 'netcat. A raw network tool sometimes used for reverse shells.',
  ncat: 'ncat. A raw network tool sometimes used for reverse shells.',
};

/** AI agents and their tooling. Tagged so their network activity stands out. */
export const AGENT_PATTERNS: { re: RegExp; name: string }[] = [
  { re: /\/claude(\.app)?\b|\bclaude$/i, name: 'Claude' },
  { re: /codex/i, name: 'Codex' },
  { re: /cursor/i, name: 'Cursor' },
  { re: /windsurf|codeium/i, name: 'Windsurf' },
  { re: /chatgpt/i, name: 'ChatGPT' },
  { re: /gemini/i, name: 'Gemini CLI' },
  { re: /opencode/i, name: 'OpenCode' },
  { re: /ollama/i, name: 'Ollama' },
  { re: /lm ?studio/i, name: 'LM Studio' },
  { re: /\bgoose\b/i, name: 'Goose' },
  { re: /openclaw|clawdbot|moltbot/i, name: 'OpenClaw' },
];

export function agentName(path: string, name: string): string | null {
  for (const a of AGENT_PATTERNS) if (a.re.test(path) || a.re.test(name)) return a.name;
  return null;
}

export function processNote(name: string): string | undefined {
  const n = name.toLowerCase().replace(/\.app$/, '');
  return PROCESS_NOTES[n] ?? PROCESS_NOTES[n.replace(/ helper.*$/, ' helper')] ?? PROCESS_NOTES[n.split(' ')[0]];
}

/** Remote-access and remote-control software. */
export const REMOTE_ACCESS_APPS = [
  'AnyDesk', 'TeamViewer', 'RustDesk', 'Splashtop', 'LogMeIn', 'GoTo', 'ScreenConnect', 'ConnectWise', 'Chrome Remote Desktop',
  'Parsec', 'RealVNC', 'VNC Viewer', 'VNC Server', 'Jump Desktop', 'Remote Desktop', 'Remotix', 'NoMachine', 'BeyondTrust', 'Zoho Assist', 'Ammyy',
];

/** The ones that let someone else control THIS Mac (viewers like Parsec or Microsoft Remote Desktop only connect out). */
export const REMOTE_CONTROL_HOSTS = /^(AnyDesk|TeamViewer|RustDesk|Splashtop Streamer|LogMeIn|GoTo|GoToAssist|ScreenConnect|ConnectWise|Chrome Remote Desktop|VNC Server|Zoho Assist|Ammyy|BeyondTrust|Bomgar|SupRemo|AeroAdmin|HopToDesk)/i;

/** Ports that are a classic sign of reverse shells, IRC bots or crypto miners. */
export const SUSPICIOUS_PORTS: Record<number, string> = {
  4444: 'Metasploit default listener',
  1337: 'common backdoor / "leet" port',
  31337: 'classic backdoor port',
  6667: 'IRC (used by old botnets)',
  6697: 'IRC over TLS (used by botnets)',
  3333: 'crypto-mining pool',
  5555: 'crypto-mining pool / Android debug',
  7777: 'crypto-mining pool',
  14444: 'Monero mining pool',
  45700: 'Monero mining pool',
  9050: 'Tor SOCKS proxy',
  9001: 'Tor relay',
};

export const SEVERITY_WORDS: Record<string, string> = {
  info: 'For your information',
  low: 'Worth a look',
  medium: 'Should be reviewed',
  high: 'Likely a problem',
  critical: 'Act now',
};
