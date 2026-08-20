import { describe, expect, it } from 'vitest';
import { callFingerprint, extractDtlsFingerprints, safetyNumber } from './fingerprint.js';
import { exportPublicKeys, generateIdentity } from './identity.js';

describe('safety number', () => {
  it('formats as 12 groups of 5 digits', async () => {
    const a = await exportPublicKeys(await generateIdentity());
    const b = await exportPublicKeys(await generateIdentity());
    const sn = await safetyNumber(a, b);
    expect(sn.split(' ')).toHaveLength(12);
    expect(sn.replace(/ /g, '')).toMatch(/^\d{60}$/);
  });

  it('is order-independent, so both sides read the same number', async () => {
    // Neither party has to agree on who is "first" before comparing.
    const a = await exportPublicKeys(await generateIdentity());
    const b = await exportPublicKeys(await generateIdentity());
    expect(await safetyNumber(a, b)).toBe(await safetyNumber(b, a));
  });

  it('changes if either party is substituted', async () => {
    // This is the whole detection mechanism for a server that swapped a key.
    const a = await exportPublicKeys(await generateIdentity());
    const b = await exportPublicKeys(await generateIdentity());
    const mitm = await exportPublicKeys(await generateIdentity());
    const real = await safetyNumber(a, b);
    expect(await safetyNumber(a, mitm)).not.toBe(real);
    expect(await safetyNumber(mitm, b)).not.toBe(real);
  });

  it('changes if only the signing half is substituted', async () => {
    const a = await exportPublicKeys(await generateIdentity());
    const b = await exportPublicKeys(await generateIdentity());
    const other = await exportPublicKeys(await generateIdentity());
    expect(await safetyNumber(a, { ...b, spkiEcdsa: other.spkiEcdsa })).not.toBe(await safetyNumber(a, b));
  });
});

describe('call fingerprint', () => {
  it('is order-independent and distinguishes a substituted certificate', async () => {
    const fpA = 'sha-256 AA:BB:CC';
    const fpB = 'sha-256 DD:EE:FF';
    const fpEvil = 'sha-256 11:22:33';
    expect(await callFingerprint(fpA, fpB)).toBe(await callFingerprint(fpB, fpA));
    expect(await callFingerprint(fpA, fpEvil)).not.toBe(await callFingerprint(fpA, fpB));
  });
});

describe('extractDtlsFingerprints', () => {
  const sdp = [
    'v=0',
    'o=- 1 2 IN IP4 127.0.0.1',
    'a=fingerprint:SHA-256 AB:CD:EF:01',
    'm=video 9 UDP/TLS/RTP/SAVPF 96',
    'a=fingerprint:sha-256 ab:cd:ef:01',
    'a=setup:actpass',
  ].join('\r\n');

  it('normalises case and de-duplicates across m-sections', () => {
    // A bundled SDP repeats the same fingerprint per m-line, with
    // inconsistent casing between browsers.
    expect(extractDtlsFingerprints(sdp)).toEqual(['sha-256 AB:CD:EF:01']);
  });

  it('returns nothing for an SDP with no fingerprint', () => {
    expect(extractDtlsFingerprints('v=0\r\na=setup:actpass')).toEqual([]);
  });
});
