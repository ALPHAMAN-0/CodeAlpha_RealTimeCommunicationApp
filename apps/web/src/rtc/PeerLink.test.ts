import { describe, expect, it } from 'vitest';
import { extractFingerprints, isPolite } from './PeerLink.js';

/**
 * The politeness rule is the single most catastrophic-if-wrong pure function
 * in the WebRTC layer: if both peers computed the same value, an offer
 * collision would deadlock the call instead of resolving.
 */
describe('perfect-negotiation politeness', () => {
  it('is complementary for every ordered pair', () => {
    const ids = ['aaa', 'zzz', 'AAA', 'ZZZ', '000', '___', 'abc-def', 'abc_def', 'x'];
    for (const a of ids) {
      for (const b of ids) {
        if (a === b) continue;
        expect(isPolite(a, b), `${a} vs ${b}`).not.toBe(isPolite(b, a));
      }
    }
  });

  it('holds for realistic Socket.IO ids', () => {
    const ids = Array.from({ length: 40 }, (_, i) => `sock_${(i * 7919).toString(36)}Xy`);
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        expect(isPolite(ids[i]!, ids[j]!)).not.toBe(isPolite(ids[j]!, ids[i]!));
      }
    }
  });

  it('gives exactly one polite side, never zero and never two', () => {
    let politeCount = 0;
    const a = 'socket-A';
    const b = 'socket-B';
    if (isPolite(a, b)) politeCount++;
    if (isPolite(b, a)) politeCount++;
    expect(politeCount).toBe(1);
  });
});

describe('DTLS fingerprint extraction', () => {
  it('de-duplicates across m-sections and normalises case', () => {
    // A bundled SDP repeats the same fingerprint per m-line, with casing that
    // differs between browsers.
    const sdp = [
      'v=0',
      'a=fingerprint:SHA-256 AA:BB:CC:DD',
      'm=audio 9 UDP/TLS/RTP/SAVPF 111',
      'a=fingerprint:sha-256 aa:bb:cc:dd',
      'm=video 9 UDP/TLS/RTP/SAVPF 96',
      'a=fingerprint:sha-256 AA:BB:CC:DD',
    ].join('\r\n');
    expect(extractFingerprints(sdp)).toEqual(['sha-256 AA:BB:CC:DD']);
  });

  it('returns distinct entries when a peer really presents two certificates', () => {
    const sdp = 'a=fingerprint:sha-256 AA:BB\r\na=fingerprint:sha-256 CC:DD';
    expect(extractFingerprints(sdp)).toHaveLength(2);
  });

  it('returns nothing for an SDP with no fingerprint line', () => {
    expect(extractFingerprints('v=0\r\nm=audio 9 RTP/SAVPF 111')).toEqual([]);
  });
});
