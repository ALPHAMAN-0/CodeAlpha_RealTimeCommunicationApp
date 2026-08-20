import { CALL, VIDEO_PROFILES, type IceServerConfig, type TrackSlot } from '@rtc/shared';

export interface PeerLinkSink {
  onTrack: (slot: TrackSlot, track: MediaStreamTrack) => void;
  onState: (state: RTCPeerConnectionState) => void;
  onDescription: (description: RTCSessionDescriptionInit) => void;
  onCandidate: (candidate: RTCIceCandidateInit) => void;
}

/**
 * One peer connection, implementing perfect negotiation.
 *
 * Two structural decisions carry most of the weight here.
 *
 * FIXED TRANSCEIVER LAYOUT. Exactly three transceivers are created at
 * construction, in the order mic, camera, screen — before any SDP exists. This
 * buys two things that are otherwise fiddly:
 *
 *  1. Screen sharing toggles with ZERO renegotiation, because the screen
 *     transceiver already exists and only needs `replaceTrack`. The
 *     alternative — addTrack when sharing starts — triggers
 *     onnegotiationneeded mid-call, which is a glare window and visibly
 *     flickers.
 *  2. Incoming tracks identify themselves POSITIONALLY. Both peers build the
 *     same three transceivers in the same order, so `setRemoteDescription`
 *     associates m-lines by index and `ontrack` can resolve purpose locally.
 *     No track-metadata message, and therefore no race where the track
 *     arrives before the message describing it — a bug class that plagues
 *     addTrack-based designs.
 *
 * The cost is one inert m-line per connection. Worth it many times over.
 *
 * DETERMINISTIC POLITENESS. `polite = localSocketId > remoteSocketId`. Socket
 * ids are unique, so both peers compute complementary values from the same two
 * strings with zero coordination. No "who offers first" choreography, no
 * timers, no deadlock where both sides wait for the other.
 */
export class PeerLink {
  readonly pc: RTCPeerConnection;
  private readonly polite: boolean;
  private makingOffer = false;
  private ignoreOffer = false;
  private isSettingRemoteAnswerPending = false;
  private restartTimer: ReturnType<typeof setTimeout> | undefined;
  private closed = false;
  private readonly senders: Record<TrackSlot, RTCRtpSender>;

  constructor(
    readonly remoteSocketId: string,
    localSocketId: string,
    iceServers: IceServerConfig[],
    private readonly sink: PeerLinkSink,
    opts?: { relayOnly?: boolean },
  ) {
    this.pc = new RTCPeerConnection({
      iceServers: iceServers as RTCIceServer[],
      bundlePolicy: 'max-bundle',
      rtcpMuxPolicy: 'require',
      iceCandidatePoolSize: 2,
      // Relay-only hides participant IPs from each other, at the cost of
      // routing all media through TURN. Must be room-wide to be effective:
      // one peer still offering host candidates defeats it for everyone.
      ...(opts?.relayOnly ? { iceTransportPolicy: 'relay' as RTCIceTransportPolicy } : {}),
    });

    this.polite = localSocketId > remoteSocketId;

    // Order must match CALL.TRACK_SLOTS on BOTH peers. Changing it is a
    // breaking wire change.
    this.senders = {
      mic: this.pc.addTransceiver('audio', { direction: 'sendrecv' }).sender,
      camera: this.pc.addTransceiver('video', { direction: 'sendrecv' }).sender,
      screen: this.pc.addTransceiver('video', { direction: 'sendrecv' }).sender,
    };

    this.pc.onnegotiationneeded = async () => {
      try {
        this.makingOffer = true;
        // Implicit offer: no argument, so the browser picks the right type
        // even mid-rollback.
        await this.pc.setLocalDescription();
        if (this.pc.localDescription) this.sink.onDescription(this.pc.localDescription.toJSON());
      } catch {
        // Negotiation failures surface through connectionstatechange; there is
        // nothing useful to do here and throwing would be unhandled.
      } finally {
        this.makingOffer = false;
      }
    };

    this.pc.onicecandidate = ({ candidate }) => {
      if (candidate) this.sink.onCandidate(candidate.toJSON());
    };

    this.pc.ontrack = ({ transceiver, track }) => {
      const slot = this.slotOf(transceiver);
      if (slot) this.sink.onTrack(slot, track);
    };

    this.pc.onconnectionstatechange = () => {
      const state = this.pc.connectionState;
      this.sink.onState(state);
      if (state === 'failed') {
        // Failed is terminal for the current ICE session; restart immediately.
        this.pc.restartIce();
      } else if (state === 'disconnected') {
        // Transient blips self-heal, so only escalate after a grace period.
        // Restarting instantly makes a brief wifi hiccup far more disruptive
        // than doing nothing.
        this.restartTimer = setTimeout(() => {
          if (this.pc.connectionState === 'disconnected') this.pc.restartIce();
        }, 4000);
      } else if (state === 'connected') {
        clearTimeout(this.restartTimer);
      }
    };
  }

  /**
   * Handle an incoming offer OR answer.
   *
   * One entry point for both, because splitting them duplicates the collision
   * logic into two code paths that must agree — and eventually do not.
   */
  async handleDescription(description: RTCSessionDescriptionInit): Promise<void> {
    if (this.closed) return;
    const readyForOffer =
      !this.makingOffer &&
      (this.pc.signalingState === 'stable' || this.isSettingRemoteAnswerPending);
    const offerCollision = description.type === 'offer' && !readyForOffer;

    // The impolite peer wins a collision by ignoring the incoming offer; the
    // polite peer rolls back implicitly inside setRemoteDescription.
    this.ignoreOffer = !this.polite && offerCollision;
    if (this.ignoreOffer) return;

    this.isSettingRemoteAnswerPending = description.type === 'answer';
    await this.pc.setRemoteDescription(description);
    this.isSettingRemoteAnswerPending = false;

    if (description.type === 'offer') {
      await this.pc.setLocalDescription();
      if (this.pc.localDescription) this.sink.onDescription(this.pc.localDescription.toJSON());
    }
  }

  async handleCandidate(candidate: RTCIceCandidateInit): Promise<void> {
    if (this.closed) return;
    try {
      await this.pc.addIceCandidate(candidate);
    } catch (err) {
      // Candidates for an offer we deliberately ignored will fail; that is
      // expected and must not surface as an error.
      if (!this.ignoreOffer) throw err;
    }
  }

  /** Attach or detach a local track. Renegotiation-free by construction. */
  setLocalTrack(slot: TrackSlot, track: MediaStreamTrack | null): Promise<void> {
    if (this.closed) return Promise.resolve();
    return this.senders[slot].replaceTrack(track);
  }

  /** Cap the outbound bitrate — mesh uplink scales with (n-1). */
  async setMaxBitrate(slot: 'camera' | 'screen', bps: number): Promise<void> {
    const sender = this.senders[slot];
    const params = sender.getParameters();
    params.encodings ??= [{}];
    if (params.encodings[0]) params.encodings[0].maxBitrate = bps;
    // A shared screen must stay legible, so drop frames before resolution.
    // A camera is the opposite: smooth motion matters more than sharpness.
    params.degradationPreference = slot === 'screen' ? 'maintain-resolution' : 'balanced';
    await sender.setParameters(params);
  }

  async applyProfile(participantCount: number, screenActive: boolean): Promise<void> {
    const profile = participantCount >= 3 ? VIDEO_PROFILES.low : VIDEO_PROFILES.high;
    await this.setMaxBitrate('camera', screenActive ? VIDEO_PROFILES.thumb.maxBitrate : profile.maxBitrate);
    if (screenActive) await this.setMaxBitrate('screen', 1_500_000);
  }

  /** Local DTLS fingerprints, for the out-of-band call safety number. */
  localFingerprints(): string[] {
    return extractFingerprints(this.pc.localDescription?.sdp ?? '');
  }

  remoteFingerprints(): string[] {
    return extractFingerprints(this.pc.remoteDescription?.sdp ?? '');
  }

  async stats(): Promise<{ rttMs?: number; outboundKbps?: number }> {
    const report = await this.pc.getStats();
    let rttMs: number | undefined;
    let bytes = 0;
    report.forEach((s) => {
      if (s.type === 'candidate-pair' && (s as { nominated?: boolean }).nominated) {
        const rtt = (s as { currentRoundTripTime?: number }).currentRoundTripTime;
        if (rtt !== undefined) rttMs = Math.round(rtt * 1000);
      }
      if (s.type === 'outbound-rtp') bytes += (s as { bytesSent?: number }).bytesSent ?? 0;
    });
    return { ...(rttMs !== undefined ? { rttMs } : {}), outboundKbps: Math.round((bytes * 8) / 1000) };
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    clearTimeout(this.restartTimer);
    for (const t of this.pc.getTransceivers()) {
      try {
        t.stop();
      } catch {
        // Already stopped by a remote close.
      }
    }
    this.pc.onnegotiationneeded = null;
    this.pc.onicecandidate = null;
    this.pc.ontrack = null;
    this.pc.onconnectionstatechange = null;
    this.pc.close();
  }

  private slotOf(transceiver: RTCRtpTransceiver): TrackSlot | undefined {
    const index = this.pc.getTransceivers().indexOf(transceiver);
    return CALL.TRACK_SLOTS[index];
  }
}

/** Exported so the safety-number UI can hash both sides' fingerprints. */
export function extractFingerprints(sdp: string): string[] {
  const out: string[] = [];
  for (const line of sdp.split(/\r?\n/)) {
    const m = /^a=fingerprint:(\S+)\s+(\S+)/.exec(line.trim());
    if (m) out.push(`${m[1]!.toLowerCase()} ${m[2]!.toUpperCase()}`);
  }
  return [...new Set(out)];
}

/** Pure and exported for tests: the politeness rule must be complementary. */
export const isPolite = (localSocketId: string, remoteSocketId: string): boolean =>
  localSocketId > remoteSocketId;
