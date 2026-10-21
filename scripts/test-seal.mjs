// Checks the phone's JavaScript ChaCha20-Poly1305 against Node's native one, both ways.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { seal, open } from '../dashboard/phone/seal.js';

let n = 0;
for (const len of [0, 1, 15, 16, 17, 63, 64, 65, 1000, 70_000]) {
  const key = randomBytes(32), nonce = randomBytes(12), aad = randomBytes(len % 23), msg = randomBytes(len);
  const c = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  c.setAAD(aad, { plaintextLength: msg.length });
  const native = Buffer.concat([c.update(msg), c.final(), c.getAuthTag()]);
  const mine = Buffer.from(seal(key, nonce, msg, aad));
  if (!native.equals(mine)) throw new Error(`seal differs at length ${len}`);
  if (!Buffer.from(open(key, nonce, native, aad)).equals(msg)) throw new Error(`open failed at length ${len}`);
  const d = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  d.setAAD(aad, { plaintextLength: msg.length }); d.setAuthTag(mine.subarray(mine.length - 16));
  if (!Buffer.concat([d.update(mine.subarray(0, mine.length - 16)), d.final()]).equals(msg)) throw new Error('native open of mine failed');
  const bad = Buffer.from(native); bad[0] ^= 1;
  let rejected = false; try { open(key, nonce, bad, aad); } catch { rejected = true; }
  if (len && !rejected) throw new Error('tampered message was accepted');
  n++;
}
// RFC 8439 section 2.8.2 test vector.
const hex = (s) => Buffer.from(s.replace(/\s/g, ''), 'hex');
const key = hex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
const nonce = hex('070000004041424344454647');
const aad = hex('50515253c0c1c2c3c4c5c6c7');
const pt = Buffer.from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
const tag = Buffer.from(seal(key, nonce, pt, aad)).subarray(-16).toString('hex');
if (tag !== '1ae10b594f09e26a7e902ecbd0600691') throw new Error(`RFC tag mismatch: ${tag}`);
console.log(`seal.js matches native ChaCha20-Poly1305 in ${n} cases and the RFC 8439 vector; tampering is rejected.`);
