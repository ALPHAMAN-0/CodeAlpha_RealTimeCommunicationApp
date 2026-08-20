# Video calling

## Topology: full mesh, and where it stops

Every participant connects directly to every other. For `n` participants:

- total peer connections: `n(n-1)/2`
- per client: `n-1` connections, `n-1` **separate upstream encodes** of its own camera

| n | Connections | Per-client uplink @ 1.2 Mbps | Verdict |
|---|---|---|---|
| 2 | 1 | 1.2 Mbps | ideal |
| 3 | 3 | 2.4 Mbps | fine |
| **4** | **6** | **3.6 Mbps** | **our cap** |
| 6 | 15 | 6.0 Mbps | degraded, CPU-bound on laptops |
| 8 | 28 | 8.4 Mbps | exceeds typical consumer uplink |

The cap is enforced **server-side**: the fifth `call:join` receives
`ROOM_FULL`. An unbounded room is a self-inflicted denial of service on every
participant's uplink and CPU.

Adaptive downscale: at n ≥ 3, cameras step from 1280×720 / 1.2 Mbps down to
640×360 / 500 kbps.

**Where mesh stops being the right answer.** Beyond about five participants you
need an SFU (mediasoup, LiveKit), which makes uplink O(1) — each client sends
one stream and the server forwards. That also unlocks simulcast, server-side
recording and dial-in. It costs you the property that media never touches your
server: with an SFU, media is no longer end-to-end encrypted by default and you
need Insertable Streams / SFrame to get it back. This project chose the mesh
and states the limit rather than implying it scales.

## Fixed transceiver layout

Every peer connection creates exactly three transceivers at construction, in a
fixed order, **before any SDP exists**:

```
index 0 → audio  → microphone
index 1 → video  → camera
index 2 → video  → screen share   (pre-created, initially trackless)
```

Two payoffs:

1. **Screen sharing toggles with zero renegotiation.** `replaceTrack(track)` and `replaceTrack(null)` on a transceiver that already exists. The alternative — `addTrack` when sharing starts — fires `onnegotiationneeded` mid-call, which is a glare window and visibly flickers.
2. **Incoming tracks identify themselves positionally.** Both peers build the same three transceivers in the same order, so `setRemoteDescription` associates m-lines by index and `ontrack` resolves purpose locally from `getTransceivers().indexOf(t)`. No track-metadata message, and therefore **no race where the track arrives before the message describing it** — a bug class that plagues `addTrack`-based designs.

The cost is one inert m-line per connection (a trackless `sendrecv` transceiver
sends no RTP). Worth it many times over.

If the app ever needs dynamic track sets — multiple shares, N cameras — that is
the point to add explicit mid→purpose signalling.

## Perfect negotiation

```ts
const polite = localSocketId > remoteSocketId;
```

Socket ids are unique, so both peers compute **complementary** values from the
same two strings with zero coordination. No "who offers first" choreography, no
timers, no deadlock where both sides wait for the other.

Both peers attach local tracks immediately and both fire
`onnegotiationneeded`, so both offer. That is glare, and perfect negotiation
makes it harmless: the polite peer rolls back implicitly inside
`setRemoteDescription` and answers; the impolite peer ignores the incoming
offer and its own offer completes.

Offers and answers share **one** wire event, `rtc:describe`. Splitting them
duplicates the collision logic into two code paths that must agree — and
eventually do not.

There is a unit test asserting `polite(a, b) !== polite(b, a)` across many id
pairs. It is the most catastrophic-if-wrong pure function in the layer: if both
sides computed the same value, a collision would deadlock the call.

## Mute is an explicit event, not a track removal

Muting sets `track.enabled = false` and emits `rtc:media-state`. The track
keeps flowing as silence or black.

Removing the track instead would force a renegotiation and **freeze the
remote's last frame**, which looks like a crash. And because a receiver cannot
observe `enabled = false`, the explicit event is the only thing that can drive
the remote mute icon.

## Recovery

- `connectionState === 'failed'` → `restartIce()` immediately.
- `connectionState === 'disconnected'` → wait 4 seconds first. Transient blips self-heal, and restarting instantly makes a brief wifi hiccup far more disruptive than doing nothing.
- `track.onended` catches the browser's own "Stop sharing" bar, which ends the track without telling the app.
- On leave, every local track is stopped explicitly. A camera light that stays on after a call ends is something users notice immediately.

## Signalling authorization

`apps/server/src/realtime/handlers/rtc.ts` is the highest-risk authorization
code in the app. Every relay checks, in order:

1. the access token is still valid;
2. the sender is a **current database member** of the conversation;
3. the sender's socket actually **joined** that room;
4. the sender is in the call;
5. the target socket exists, is authenticated, is in the **same** call, and is not the sender;
6. the per-socket rate limit allows it.

The message is then emitted to that **one resolved socket**, with `from`
stamped from verified server state and never read from the payload.
Broadcasting to the room instead would hand every participant's ICE candidates
and DTLS fingerprints to everyone.

Checks 2 and 3 are both required: the database is the authority on membership,
the socket's room set is the authority on delivery. A removed-but-still-joined
socket must fail the first; a member who never joined must fail the second.

**Deliberate non-goal: the SDP is never parsed, rewritten or "sanitized."** An
SDP mangler is a parser attack surface and a reliable source of subtle interop
breakage. It is size-capped (64 KB) and passed through; membership
authorization is what makes that safe. A malicious *member* can put whatever it
likes in SDP — that is the accepted risk in SECURITY.md row 5.

## Media encryption, and the caveat

DTLS-SRTP is mandatory in WebRTC: `RTCPeerConnection` will not send
unencrypted media and there is no API to disable it. In a mesh the media is
peer-to-peer, so it never touches our server. This is a genuine end-to-end
claim.

**The catch:** DTLS authenticates against certificate fingerprints carried in
the SDP that our signalling server relays. A malicious server could substitute
its own and MITM the media undetected. So media security reduces to signalling
integrity, which reduces to trusting the server.

The fix is cheap and implemented: after connecting, both peers hash their
local and remote DTLS fingerprints into a **call verification code** and
compare it out of band. The "Verify call" button in the call UI shows it.

## IP addresses

ICE works by trading candidate addresses, so **every participant learns every
other participant's private LAN IP and public IP**. In a four-person room,
joining reveals your home IP to three people.

This is inherent to peer-to-peer, not a bug — so the call UI says so directly
rather than burying it in this file.

A TURN relay changes it: with `iceTransportPolicy: 'relay'` the browser offers
only relay candidates, so peers see the TURN server and nothing else. Media
still stays end-to-end encrypted through a relay, which is exactly why TURN is
safe to use for privacy. The cost is bandwidth through your server.

`coturn` ships behind an optional compose profile with 300-second HMAC
credentials from an authenticated endpoint, and every private IP range denied —
an open TURN server is an SSRF and port-scan pivot into the internal network.
The static auth secret never reaches a browser.

Without TURN configured, roughly 10–20% of real-world connections fail behind
symmetric NAT or CGNAT. On localhost, host candidates always work, so this is
invisible during a demo. Said plainly rather than discovered later.

## What is not tested automatically

WebRTC media itself. There is no meaningful media stack in Node, and
`wrtc`/`node-datachannel` are heavy and flaky in CI. What **is** tested:
signalling routing, the full authorization chain, the participant cap,
peer-left cleanup, media-state relay, SDP size caps, and the pure negotiation
predicate. Media is verified by hand with multiple browser windows, per
`docs/DEMO_SCRIPT.md`.

Pretending to test media would be worse than documenting that we do not.
