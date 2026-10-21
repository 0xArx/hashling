import { mkdirSync } from 'node:fs';
import { DATA_DIR, QUARANTINE_DIR, RULES_DIR, NAME, VERSION } from './config.ts';
import { startServer } from './server.ts';
import { startPhoneIfOn } from './phone.ts';
import { startScheduler } from './scheduler.ts';
import { logEvent } from './db.ts';

for (const d of [DATA_DIR, QUARANTINE_DIR, RULES_DIR]) mkdirSync(d, { recursive: true, mode: 0o700 });

process.on('unhandledRejection', (e) => console.error('unhandled', e));
process.on('uncaughtException', (e) => console.error('uncaught', e));

startServer();
startPhoneIfOn();
startScheduler({ skip: (process.env.HASHLING_SKIP ?? '').split(',').filter(Boolean) });
logEvent('system', 'info', `${NAME} ${VERSION} started`);

const stop = () => { console.log('stopping'); process.exit(0); };
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
