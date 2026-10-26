// Checks the rules the security score promises (src/score.ts), with made-up Macs.
//   node scripts/test-score.mjs
const { computeScore, CHECK_WEIGHT } = await import(new URL('../src/score.ts', import.meta.url).pathname);

const NOW = Date.UTC(2026, 9, 26);
const allPass = Object.keys(CHECK_WEIGHT).map((id) => ({ id, label: id, status: 'pass' }));
const checks = (over = {}) => allPass.map((c) => ({ ...c, status: over[c.id] ?? 'pass' }));
let n = 0;
const f = (category, severity, tier, extra = {}) => ({ id: `f${++n}`, key: `${category}:${n}`, category, severity, tier, title: `${category} ${severity} ${tier}`, last_seen: NOW, ...extra });
const score = (findings = [], over = {}, more = {}) => computeScore({ findings, checks: checks(over), at: NOW, ...more });

let failed = false;
const check = (ok, what) => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`); if (!ok) failed = true; };

const clean = score();
check(clean.score === 100 && clean.grade === 'Excellent' && !clean.cap, `a clean Mac scores 100, Excellent (got ${clean.score}, ${clean.grade})`);

const tips = score(Array.from({ length: 10 }, () => f('permissions', 'low', 'hardening')));
const oneRisk = score([f('agents', 'high', 'risk')]);
check(tips.score > oneRisk.score, `ten optional tips cost less than one serious risk (${tips.score} vs ${oneRisk.score})`);
check(tips.score >= 90, `optional tips alone keep a Mac Excellent (got ${tips.score})`);

const medRisk = score([f('agents', 'medium', 'risk')]);
check(medRisk.score <= 89 && medRisk.grade !== 'Excellent', `anything worth fixing keeps the score out of Excellent (got ${medRisk.score})`);
check(medRisk.cap?.reason === 'fix' && medRisk.beforeCap > medRisk.score, 'and says it is held there, and what it would be otherwise');

check(oneRisk.score <= 74, `a serious risk keeps the score out of Good (got ${oneRisk.score})`);

const susHigh = score([f('malware', 'high', 'suspicious')]);
const susCrit = score([f('malware', 'critical', 'suspicious')]);
check(susHigh.score <= 59 && susCrit.score <= 39, `something suspicious caps the score (high ${susHigh.score} <= 59, critical ${susCrit.score} <= 39)`);
check(susCrit.grade === 'At risk', `a critical threat reads "At risk" (got ${susCrit.grade})`);

// FileVault off: the check and its warning describe the same thing, so points are taken once.
const fvFinding = { ...f('posture', 'high', 'risk'), key: 'posture:filevault' };
const fvOff = score([fvFinding], { filevault: 'fail' });
const fvCheckOnly = score([], { filevault: 'fail' });
const sys = (r) => r.areas.find((a) => a.id === 'system').score;
check(sys(fvOff) === sys(fvCheckOnly), `a setting is not counted twice (Mac settings ${sys(fvOff)} either way)`);
check(fvOff.score <= 74, `FileVault off keeps the score out of Good (got ${fvOff.score})`);
check(fvOff.topGains[0]?.title === 'filevault' && fvOff.topGains[0].kind === 'check', 'turning FileVault on is the top gain');

const ignored = score([], { filevault: 'fail' }, { ignoredChecks: ['filevault'] });
check(ignored.score === 100, `an ignored setting costs nothing (got ${ignored.score})`);
const unknown = score([], { sip: 'unknown' });
check(unknown.score === 100, `a setting that could not be read costs nothing (got ${unknown.score})`);

const stale = score([f('network', 'medium', 'risk', { last_seen: NOW - 5 * 86_400_000 })]);
check(stale.beforeCap > medRisk.beforeCap - 1 && stale.areas.find((a) => a.id === 'network').score > medRisk.areas.find((a) => a.id === 'agents').score, 'an old sighting counts less than a fresh one');

const outside = score([f('phone', 'high', 'suspicious'), f('storage', 'medium', 'risk')]);
check(outside.score === 100, `phone check-ups and storage tips don't change the Mac's score (got ${outside.score})`);

// Adding a problem never raises the score, and the weakest area pulls the total down.
const base = [f('agents', 'medium', 'risk'), f('persistence', 'low', 'hardening')];
const worse = score([...base, f('network', 'medium', 'risk')]);
check(worse.beforeCap <= score(base).beforeCap, 'adding a problem never raises the score');
const spread = score([f('agents', 'medium', 'risk'), f('network', 'medium', 'risk'), f('secrets', 'medium', 'risk')]);
const piled = score([f('agents', 'medium', 'risk'), f('agents', 'medium', 'risk'), f('agents', 'medium', 'risk')]);
check(piled.beforeCap < spread.beforeCap, `three problems in one part weigh more than three spread out (${piled.beforeCap} vs ${spread.beforeCap})`);

const gains = score([f('agents', 'high', 'risk'), f('permissions', 'low', 'hardening')]).topGains;
check(gains.length >= 1 && gains.every((g, i) => i === 0 || gains[i - 1].points >= g.points) && gains[0].title.startsWith('agents'), 'fixes are ranked by what they are worth');

check(score([], {}, { checks: null }).areas.find((a) => a.id === 'system').partial !== null, 'Mac settings say "not fully checked" before the check has run');

console.log(failed ? 'Score tests failed.' : 'Score tests passed: the score follows its rules.');
process.exitCode = failed ? 1 : 0;
