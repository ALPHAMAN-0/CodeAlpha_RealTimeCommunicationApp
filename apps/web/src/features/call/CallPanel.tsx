import { useEffect, useRef, useState } from 'react';
import { callFingerprint } from '@rtc/crypto';
import type { IceConfigDTO } from '@rtc/shared';
import { request } from '../../lib/api.js';
import { MeshManager } from '../../rtc/MeshManager.js';
import { localMedia } from '../../rtc/localMedia.js';
import { clearMeshBridge, setMeshBridge } from '../../realtime/bindings.js';
import { useCall } from '../../stores/call.store.js';
import { Avatar, Badge, Button, Spinner } from '../../components/ui.js';

/** A tile whose <video> is fed directly from a MediaStreamTrack. */
function VideoTile({
  track, label, color, muted, mirrored, screen, connection, speaking,
}: {
  track: MediaStreamTrack | undefined;
  label: string;
  color: string;
  muted: boolean;
  mirrored?: boolean;
  screen?: boolean;
  connection?: RTCPeerConnectionState;
  speaking?: boolean;
}) {
  const ref = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (!track) {
      el.srcObject = null;
      return;
    }
    // A fresh MediaStream per track: reusing one across track swaps leaves
    // stale tracks attached and shows the wrong video.
    el.srcObject = new MediaStream([track]);
    void el.play().catch(() => undefined);
  }, [track]);

  const degraded = connection === 'disconnected' || connection === 'failed';

  return (
    <div
      className={`relative overflow-hidden rounded-xl bg-ink-950 ring-1 ${
        speaking ? 'ring-accent-400' : 'ring-ink-700'
      }`}
    >
      <video
        ref={ref}
        playsInline
        autoPlay
        muted={muted}
        className={`aspect-video size-full ${screen ? 'object-contain' : 'object-cover'} ${
          mirrored ? 'scale-x-[-1]' : ''
        }`}
      />
      {!track && (
        <div className="absolute inset-0 grid place-items-center">
          <Avatar name={label} color={color} size={56} />
        </div>
      )}
      <div className="absolute inset-x-0 bottom-0 flex items-center justify-between gap-2 bg-gradient-to-t from-ink-950/90 to-transparent px-2.5 py-2">
        <span className="truncate text-[12px] font-medium text-ink-200">{label}</span>
        <span className="flex items-center gap-1.5">
          {degraded && <Badge tone="warn">Reconnecting</Badge>}
          {screen && <Badge tone="accent">Screen</Badge>}
        </span>
      </div>
    </div>
  );
}

export function CallPanel({ conversationId, onClose }: { conversationId: string; onClose: () => void }) {
  const mesh = useRef<MeshManager | undefined>(undefined);
  const { peers, local, joining, error, relayOnly, relayAvailable, safetyNumbers } = useCall();
  const [showSafety, setShowSafety] = useState(false);
  const setPeers = useCall((s) => s.setPeers);

  useEffect(() => {
    const manager = new MeshManager(conversationId, {
      onPeers: (next) => setPeers([...next]),
      onError: (message) => useCall.getState().setError(message),
    });
    mesh.current = manager;

    // Route signalling into this mesh while the call is live.
    setMeshBridge({
      describe: (from, description) => void manager.handleDescription(from, description),
      candidate: (from, candidate) => void manager.handleCandidate(from, candidate),
      peerJoined: (peer) => manager.addPeer(peer as never),
      peerLeft: (socketId) => manager.removePeer(socketId),
      mediaState: (socketId, state) => manager.setRemoteMediaState(socketId, state as never),
    });

    useCall.getState().setJoining(true);
    useCall.getState().setActive(conversationId);

    void (async () => {
      try {
        const ice = await request<IceConfigDTO>('/api/rtc/ice');
        useCall.getState().setRelay(false, ice.relayAvailable);
        await manager.join({ iceServers: ice.iceServers, relayOnly: false });
        useCall.getState().setLocal(manager.state);
      } catch {
        useCall.getState().setError('Could not join the call.');
      } finally {
        useCall.getState().setJoining(false);
      }
    })();

    return () => {
      clearMeshBridge();
      void manager.leave();
      useCall.getState().reset();
    };
  }, [conversationId, setPeers]);

  /**
   * Verify the media path.
   *
   * WebRTC media really is end-to-end encrypted — DTLS-SRTP is mandatory and
   * in a mesh the bytes never touch our server. But the handshake
   * authenticates against certificate fingerprints that OUR signalling server
   * relays, so a malicious server could substitute its own and sit in the
   * middle undetected. Comparing this digest out of band closes that gap.
   */
  const computeSafety = async () => {
    setShowSafety(true);
    for (const peer of peers) {
      const { local: localFp, remote: remoteFp } = mesh.current!.fingerprintsFor(peer.socketId);
      if (localFp[0] && remoteFp[0]) {
        useCall.getState().setSafetyNumber(peer.socketId, await callFingerprint(localFp[0], remoteFp[0]));
      }
    }
  };

  const screenSharer = peers.find((p) => p.state.screen && p.tracks.screen);
  const tileCount = peers.length + 1;
  const columns = tileCount <= 1 ? 1 : tileCount <= 4 ? 2 : 3;

  return (
    <section className="flex h-full flex-col bg-ink-950/60">
      <header className="flex items-center gap-3 border-b border-ink-700/70 px-4 py-3">
        <h2 className="text-sm font-semibold text-ink-200">
          Call · {tileCount}/{MeshManager.maxParticipants}
        </h2>
        <Badge tone="good">Media is peer-to-peer</Badge>
        {joining && <Spinner label="Connecting…" />}
        <div className="ml-auto flex items-center gap-1.5">
          <Button size="sm" variant="ghost" onClick={() => void computeSafety()}>Verify call</Button>
          <Button size="sm" variant="danger" onClick={onClose}>Leave</Button>
        </div>
      </header>

      {error && (
        <p className="border-b border-warn/25 bg-warn/10 px-4 py-2.5 text-[13px] text-warn" role="alert">
          {error}
        </p>
      )}

      {/*
        Surfaced in the UI, not buried in a README: in a peer-to-peer mesh every
        participant learns every other participant's IP address. That is
        inherent to P2P, and users deserve to know before they join.
      */}
      <p className="border-b border-ink-700/50 px-4 py-2 text-[11px] leading-relaxed text-ink-400">
        In a peer-to-peer call, participants can see each other’s IP addresses.
        {relayAvailable
          ? ' Turn on relay mode to route media through the server instead.'
          : ' A TURN relay is not configured on this deployment, so this cannot be hidden.'}
        {relayAvailable && (
          <button
            className="ml-1.5 underline hover:text-ink-200"
            onClick={() => useCall.getState().setRelay(!relayOnly, relayAvailable)}
          >
            {relayOnly ? 'Disable relay mode' : 'Enable relay mode'}
          </button>
        )}
      </p>

      <div className="flex-1 overflow-y-auto p-4">
        {screenSharer && (
          <div className="mb-4">
            <VideoTile
              track={screenSharer.tracks.screen}
              label={`${screenSharer.displayName} · screen`}
              color={screenSharer.avatarColor}
              muted
              screen
            />
          </div>
        )}
        <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}>
          <VideoTile
            track={local.video ? localMedia.cameraTrack() : undefined}
            label="You"
            color="#22c3d6"
            muted
            mirrored
          />
          {peers.map((peer) => (
            <VideoTile
              key={peer.socketId}
              track={peer.state.video ? peer.tracks.camera : undefined}
              label={peer.displayName + (peer.state.audio ? '' : ' · muted')}
              color={peer.avatarColor}
              muted={false}
              connection={peer.connection}
            />
          ))}
        </div>

        {showSafety && (
          <div className="panel mt-4 p-4">
            <p className="text-[13px] font-medium text-ink-200">Call verification codes</p>
            <p className="mt-1 text-xs leading-relaxed text-ink-400">
              Read a code aloud to that participant. If it matches on both screens, nothing is
              intercepting your media. Compare it over the encrypted chat or in person — not
              through this call.
            </p>
            {peers.length === 0 && <p className="mt-2 text-xs text-ink-400">No one else is in the call yet.</p>}
            {peers.map((peer) => (
              <div key={peer.socketId} className="mt-3">
                <p className="text-[11px] text-ink-400">{peer.displayName}</p>
                <pre className="mt-1 overflow-x-auto rounded-md bg-ink-950/70 p-2.5 font-mono text-[11px] tracking-wider text-accent-400">
                  {safetyNumbers[peer.socketId] ?? 'Waiting for the connection to establish…'}
                </pre>
              </div>
            ))}
          </div>
        )}
      </div>

      <footer className="flex flex-wrap items-center justify-center gap-2 border-t border-ink-700/70 px-4 py-3">
        <Button
          variant={local.audio ? 'subtle' : 'danger'}
          size="sm"
          onClick={() => void mesh.current?.setAudio(!local.audio).then(() => useCall.getState().setLocal(mesh.current!.state))}
        >
          {local.audio ? '🎙 Mute' : '🔇 Unmute'}
        </Button>
        <Button
          variant={local.video ? 'subtle' : 'danger'}
          size="sm"
          onClick={() => void mesh.current?.setVideo(!local.video).then(() => useCall.getState().setLocal(mesh.current!.state))}
        >
          {local.video ? '📹 Camera off' : '📷 Camera on'}
        </Button>
        <Button
          variant={local.screen ? 'primary' : 'subtle'}
          size="sm"
          onClick={() =>
            void (local.screen ? mesh.current?.stopScreenShare() : mesh.current?.startScreenShare())
              ?.then(() => useCall.getState().setLocal(mesh.current!.state))
              .catch(() => useCall.getState().setError('Screen sharing was cancelled or denied.'))
          }
        >
          {local.screen ? '🖥 Stop sharing' : '🖥 Share screen'}
        </Button>
      </footer>
    </section>
  );
}
