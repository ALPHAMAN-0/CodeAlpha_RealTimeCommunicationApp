import { CALL, type CallPeerDTO, type IceServerConfig, type MediaState, type TrackSlot } from '@rtc/shared';
import { emit } from '../lib/socket.js';
import { PeerLink } from './PeerLink.js';
import { describeMediaError, localMedia } from './localMedia.js';

export interface RemotePeer {
  socketId: string;
  userId: string;
  displayName: string;
  avatarColor: string;
  state: MediaState;
  tracks: Partial<Record<TrackSlot, MediaStreamTrack>>;
  connection: RTCPeerConnectionState;
}

export interface MeshEvents {
  onPeers: (peers: RemotePeer[]) => void;
  onError: (message: string) => void;
}

/**
 * A full-mesh call.
 *
 * Mesh means every participant connects to every other: n(n-1)/2 connections
 * in total, and each client uploads n-1 separate encodes of its own camera.
 * That is why the participant cap exists and is enforced server-side — at
 * n=8 a client would need ~8.4 Mbps up, which exceeds a typical consumer
 * uplink. Beyond about five participants an SFU is the right answer; see
 * docs/WEBRTC.md.
 */
export class MeshManager {
  private links = new Map<string, PeerLink>();
  private peers = new Map<string, RemotePeer>();
  private iceServers: IceServerConfig[] = [];
  private selfSocketId = '';
  private relayOnly = false;
  private mediaState: MediaState = { audio: true, video: true, screen: false };

  constructor(
    private readonly conversationId: string,
    private readonly events: MeshEvents,
  ) {}

  get state(): MediaState {
    return { ...this.mediaState };
  }

  get participantCount(): number {
    return this.peers.size + 1;
  }

  async join(opts: { iceServers: IceServerConfig[]; relayOnly?: boolean; audio?: boolean; video?: boolean }): Promise<void> {
    this.iceServers = opts.iceServers;
    this.relayOnly = opts.relayOnly ?? false;
    this.mediaState = { audio: opts.audio !== false, video: opts.video !== false, screen: false };

    try {
      await localMedia.start({ audio: opts.audio !== false, video: opts.video !== false });
    } catch (err) {
      // Joining audio-only, or as a viewer, is far better than failing outright.
      this.events.onError(describeMediaError(err));
      this.mediaState = { audio: false, video: false, screen: false };
    }

    const result = await emit<{ peers: CallPeerDTO[]; selfSocketId: string; maxParticipants: number }>(
      'call:join', { conversationId: this.conversationId, media: this.mediaState },
    );
    this.selfSocketId = result.selfSocketId;

    // Both sides create a link and both may offer. Perfect negotiation makes
    // the resulting collision harmless, which is why no "who goes first"
    // handshake is needed.
    for (const peer of result.peers) this.addPeer(peer);
    this.publish();
  }

  addPeer(peer: CallPeerDTO): void {
    const socketId = String(peer.socketId);
    if (this.links.has(socketId)) return;

    this.peers.set(socketId, {
      socketId,
      userId: String(peer.userId),
      displayName: peer.displayName,
      avatarColor: peer.avatarColor,
      state: peer.state,
      tracks: {},
      connection: 'new',
    });

    const link = new PeerLink(socketId, this.selfSocketId, this.iceServers, {
      onTrack: (slot, track) => {
        const existing = this.peers.get(socketId);
        if (!existing) return;
        existing.tracks = { ...existing.tracks, [slot]: track };
        // A remote track that ends (peer stopped sharing) must clear the tile.
        track.addEventListener('ended', () => {
          const p = this.peers.get(socketId);
          if (!p) return;
          const { [slot]: _gone, ...rest } = p.tracks;
          p.tracks = rest;
          this.publish();
        });
        this.publish();
      },
      onState: (state) => {
        const existing = this.peers.get(socketId);
        if (existing) {
          existing.connection = state;
          this.publish();
        }
      },
      onDescription: (description) => {
        void emit('rtc:describe', { conversationId: this.conversationId, to: socketId, description })
          .catch(() => undefined);
      },
      onCandidate: (candidate) => {
        void emit('rtc:ice', { conversationId: this.conversationId, to: socketId, candidate })
          .catch(() => undefined);
      },
    }, { relayOnly: this.relayOnly });

    this.links.set(socketId, link);

    // Attach local tracks immediately, which is what triggers negotiation.
    void link.setLocalTrack('mic', localMedia.micTrack() ?? null);
    void link.setLocalTrack('camera', localMedia.cameraTrack() ?? null);
    if (this.mediaState.screen) void link.setLocalTrack('screen', localMedia.screenTrack() ?? null);
    void link.applyProfile(this.participantCount, this.mediaState.screen);
    this.publish();
  }

  removePeer(socketId: string): void {
    this.links.get(socketId)?.close();
    this.links.delete(socketId);
    this.peers.delete(socketId);
    // Uplink pressure drops as the room shrinks, so bitrates can go back up.
    for (const link of this.links.values()) {
      void link.applyProfile(this.participantCount, this.mediaState.screen);
    }
    this.publish();
  }

  async handleDescription(from: string, description: RTCSessionDescriptionInit): Promise<void> {
    await this.links.get(from)?.handleDescription(description);
  }

  async handleCandidate(from: string, candidate: RTCIceCandidateInit): Promise<void> {
    await this.links.get(from)?.handleCandidate(candidate);
  }

  setRemoteMediaState(socketId: string, state: MediaState): void {
    const peer = this.peers.get(socketId);
    if (peer) {
      peer.state = state;
      this.publish();
    }
  }

  async setAudio(enabled: boolean): Promise<void> {
    localMedia.setAudioEnabled(enabled);
    this.mediaState = { ...this.mediaState, audio: enabled };
    await this.announce();
  }

  async setVideo(enabled: boolean): Promise<void> {
    localMedia.setVideoEnabled(enabled);
    this.mediaState = { ...this.mediaState, video: enabled };
    await this.announce();
  }

  /**
   * Start sharing the screen.
   *
   * `replaceTrack` on the pre-created screen transceiver, so this is a local
   * operation with no offer/answer round trip and no glare window.
   */
  async startScreenShare(): Promise<void> {
    const track = await localMedia.startScreenShare(() => {
      void this.stopScreenShare();
    });
    for (const link of this.links.values()) {
      await link.setLocalTrack('screen', track);
      // The sharer's own camera drops to a thumbnail bitrate: remote UIs render
      // the share large and the camera small, so spending uplink on a
      // full-resolution camera would be wasted.
      await link.applyProfile(this.participantCount, true);
    }
    this.mediaState = { ...this.mediaState, screen: true };
    await this.announce();
  }

  async stopScreenShare(): Promise<void> {
    localMedia.stopScreenShare();
    for (const link of this.links.values()) {
      await link.setLocalTrack('screen', null);
      await link.applyProfile(this.participantCount, false);
    }
    this.mediaState = { ...this.mediaState, screen: false };
    await this.announce();
  }

  /** Fingerprints for the call safety number, compared over the E2EE channel. */
  fingerprintsFor(socketId: string): { local: string[]; remote: string[] } {
    const link = this.links.get(socketId);
    return { local: link?.localFingerprints() ?? [], remote: link?.remoteFingerprints() ?? [] };
  }

  async leave(): Promise<void> {
    for (const link of this.links.values()) link.close();
    this.links.clear();
    this.peers.clear();
    localMedia.stopAll();
    await emit('call:leave', { conversationId: this.conversationId }).catch(() => undefined);
    this.publish();
  }

  private async announce(): Promise<void> {
    this.publish();
    await emit('rtc:media-state', { conversationId: this.conversationId, state: this.mediaState })
      .catch(() => undefined);
  }

  private publish(): void {
    this.events.onPeers([...this.peers.values()]);
  }

  static get maxParticipants(): number {
    return CALL.MAX_PARTICIPANTS;
  }
}
