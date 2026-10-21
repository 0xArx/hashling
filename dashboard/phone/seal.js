/**
 * ChaCha20-Poly1305 (RFC 8439) in plain JavaScript, for the phone.
 *
 * A phone reaches Hashling over the home Wi-Fi at a plain http:// address, where browsers
 * switch off their built-in crypto (crypto.subtle needs HTTPS). So the phone seals every
 * request with this instead, using the key it got from the QR code. The Mac opens it with
 * Node's native chacha20-poly1305, which this matches byte for byte (see scripts/test-seal.mjs).
 */

const rotl = (v, n) => (v << n) | (v >>> (32 - n));

function quarter(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) | 0; s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) | 0; s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) | 0; s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) | 0; s[b] = rotl(s[b] ^ s[c], 7);
}

const u32le = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

/** One 64-byte block of keystream. */
function block(key, counter, nonce) {
  const init = new Uint32Array(16);
  init[0] = 0x61707865; init[1] = 0x3320646e; init[2] = 0x79622d32; init[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) init[4 + i] = u32le(key, i * 4);
  init[12] = counter >>> 0;
  for (let i = 0; i < 3; i++) init[13 + i] = u32le(nonce, i * 4);
  const s = Int32Array.from(init);
  for (let i = 0; i < 10; i++) {
    quarter(s, 0, 4, 8, 12); quarter(s, 1, 5, 9, 13); quarter(s, 2, 6, 10, 14); quarter(s, 3, 7, 11, 15);
    quarter(s, 0, 5, 10, 15); quarter(s, 1, 6, 11, 12); quarter(s, 2, 7, 8, 13); quarter(s, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    const v = (s[i] + init[i]) >>> 0;
    out[i * 4] = v & 255; out[i * 4 + 1] = (v >>> 8) & 255; out[i * 4 + 2] = (v >>> 16) & 255; out[i * 4 + 3] = v >>> 24;
  }
  return out;
}

function chacha20(key, counter, nonce, data) {
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 64) {
    const ks = block(key, counter + i / 64, nonce);
    for (let j = 0; j < 64 && i + j < data.length; j++) out[i + j] = data[i + j] ^ ks[j];
  }
  return out;
}

/** Little-endian bytes to BigInt. */
function leBig(b, from, to) {
  let v = 0n;
  for (let i = to - 1; i >= from; i--) v = (v << 8n) | BigInt(b[i]);
  return v;
}

const P1305 = (1n << 130n) - 5n;
function poly1305(msg, key) {
  const r = leBig(key, 0, 16) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const s = leBig(key, 16, 32);
  let acc = 0n;
  for (let i = 0; i < msg.length; i += 16) {
    const end = Math.min(i + 16, msg.length);
    acc = ((acc + leBig(msg, i, end) + (1n << BigInt(8 * (end - i)))) * r) % P1305;
  }
  let tag = (acc + s) & ((1n << 128n) - 1n);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) { out[i] = Number(tag & 255n); tag >>= 8n; }
  return out;
}

const pad16 = (n) => (16 - (n % 16)) % 16;
function macData(aad, ct) {
  const m = new Uint8Array(aad.length + pad16(aad.length) + ct.length + pad16(ct.length) + 16);
  m.set(aad, 0);
  const at = aad.length + pad16(aad.length);
  m.set(ct, at);
  const lens = at + ct.length + pad16(ct.length);
  const dv = new DataView(m.buffer);
  dv.setUint32(lens, aad.length, true); dv.setUint32(lens + 8, ct.length, true);
  return m;
}

/** Encrypt and authenticate: returns ciphertext followed by the 16-byte tag. */
export function seal(key, nonce, plaintext, aad = new Uint8Array(0)) {
  const otk = block(key, 0, nonce).slice(0, 32);
  const ct = chacha20(key, 1, nonce, plaintext);
  const out = new Uint8Array(ct.length + 16);
  out.set(ct, 0);
  out.set(poly1305(macData(aad, ct), otk), ct.length);
  return out;
}

/** Check and decrypt. Throws if anything was changed or the key is wrong. */
export function open(key, nonce, sealed, aad = new Uint8Array(0)) {
  if (sealed.length < 16) throw new Error('sealed message too short');
  const ct = sealed.subarray(0, sealed.length - 16);
  const tag = sealed.subarray(sealed.length - 16);
  const want = poly1305(macData(aad, ct), block(key, 0, nonce).slice(0, 32));
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= want[i] ^ tag[i];
  if (diff) throw new Error('message could not be verified');
  return chacha20(key, 1, nonce, ct);
}

export const b64u = {
  enc: (bytes) => { let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
  dec: (str) => { const s = atob(str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4)); const b = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i); return b; },
};
