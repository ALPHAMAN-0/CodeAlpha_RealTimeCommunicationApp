import { packAad } from './aad.js';
import { toArrayBuffer, utf8 } from './bytes.js';

const GROUPS = 12;
const DIGITS_PER_GROUP = 5;
const BYTES_PER_GROUP = 5;

/**
 * Render a digest as human-comparable decimal groups.
 *
 * Decimal digits rather than hex because two people reading them aloud over
 * the phone is the actual use case, and 'b' vs 'd' vs 'e' is where that goes
 * wrong.
 */
function toDigitGroups(digest: Uint8Array): string {
  const groups: string[] = [];
  for (let g = 0; g < GROUPS; g++) {
    let acc = 0n;
    for (let i = 0; i < BYTES_PER_GROUP; i++) {
      acc = (acc << 8n) | BigInt(digest[g * BYTES_PER_GROUP + i] ?? 0);
    }
    groups.push((acc % 100000n).toString().padStart(DIGITS_PER_GROUP, '0'));
  }
  return groups.join(' ');
}

export interface KeyMaterial {
  spkiEcdh: string;
  spkiEcdsa: string;
}

/**
 * The safety number for a 1:1 conversation: 60 digits both participants
 * compare out of band.
 *
 * Inputs are sorted so both sides compute the identical value without
 * agreeing who is "first". This is the ONLY defence against a server that
 * hands you a fabricated public key before you have ever pinned the real one
 * — the signed, append-only key log makes later tampering evident, but it
 * cannot detect a server that lied from first contact. That is why this is
 * surfaced in the UI and not buried in a doc.
 */
export async function safetyNumber(a: KeyMaterial, b: KeyMaterial): Promise<string> {
  const sideA = `${a.spkiEcdh}|${a.spkiEcdsa}`;
  const sideB = `${b.spkiEcdh}|${b.spkiEcdsa}`;
  const [first, second] = sideA < sideB ? [sideA, sideB] : [sideB, sideA];
  const digest = await crypto.subtle.digest(
    'SHA-512',
    toArrayBuffer(packAad('rtc/v1/safety-number', utf8(first), utf8(second))),
  );
  return toDigitGroups(new Uint8Array(digest));
}

/**
 * The call safety number: a digest of both peers' DTLS certificate
 * fingerprints.
 *
 * WebRTC media is genuinely end-to-end encrypted (DTLS-SRTP is mandatory and
 * in a mesh the bytes never touch our server) — but the handshake
 * authenticates against fingerprints carried in SDP, which our signalling
 * server relays. A malicious server could substitute its own and MITM the
 * media undetected.
 *
 * Comparing this value through the E2EE chat channel closes that gap, because
 * the chat channel's integrity does not depend on the signalling path.
 */
export async function callFingerprint(localFp: string, remoteFp: string): Promise<string> {
  const [first, second] = localFp < remoteFp ? [localFp, remoteFp] : [remoteFp, localFp];
  const digest = await crypto.subtle.digest(
    'SHA-512',
    toArrayBuffer(packAad('rtc/v1/call-fingerprint', utf8(first), utf8(second))),
  );
  return toDigitGroups(new Uint8Array(digest));
}

/** Pull the DTLS fingerprint lines out of an SDP blob for the check above. */
export function extractDtlsFingerprints(sdp: string): string[] {
  const out: string[] = [];
  for (const line of sdp.split(/\r?\n/)) {
    const m = /^a=fingerprint:(\S+)\s+(\S+)/.exec(line.trim());
    if (m) out.push(`${m[1]!.toLowerCase()} ${m[2]!.toUpperCase()}`);
  }
  return [...new Set(out)];
}
