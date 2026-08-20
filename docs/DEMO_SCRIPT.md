# Demo script

Doubles as a manual QA checklist and as a script for a recorded walkthrough.
Roughly six minutes end to end.

## Setup

```bash
cp .env.example .env && pnpm setup && docker compose up --build
```

Open **http://localhost:8080** in two side-by-side windows. Sign in as **Alice**
in one and **Bob** in the other, using the one-click demo buttons.

## 1 · Real-time chat (60s)

- Open the **Bob** conversation on Alice's side. Seeded history decrypts and renders.
- Type in Alice's window — Bob shows "Alice is typing…".
- Send. It appears instantly for both, and Alice's message shows **Sent**, then **Read** once Bob's window has it on screen.
- Point out the unread badge on Bob's sidebar before he opens the conversation.

## 2 · Prove the encryption is real (45s)

This is the most convincing thing in the whole demo, because it is a fact
rather than a claim.

```bash
docker compose exec mongo mongosh rtc --quiet --eval \
  'JSON.stringify(db.messages.findOne({}, {envelope:1, senderId:1, seq:1}), null, 2)'
```

The document has a sender, a sequence number and an opaque `envelope`. There is
no message text anywhere, because the server never had it.

Then say what that costs, so the claim stays honest: no server-side search, no
message previews on the conversation list, and no antivirus on attachments.

## 3 · Encrypted file sharing (45s)

- Click 📎 in Alice's window and pick a PDF or image.
- The progress bar reads "Encrypting & uploading".
- In Bob's window, click the file bubble. It downloads, decrypts locally, and saves.
- Optional: rename a `.png` to `.pdf` before sending. On open, Bob gets a warning that the contents do not match the extension — client-side magic-byte sniffing, which is the only place such a check *can* happen when the server holds ciphertext.

## 4 · Multi-user video call and screen share (90s)

- Click **Call** in both windows. Two tiles connect peer-to-peer.
- Mute Alice — Bob's tile label updates. This is an explicit event, because a receiver cannot observe a disabled track.
- Toggle Alice's camera off — the tile falls back to an avatar.
- **Share screen** in Alice's window. It appears large in Bob's window with no flicker, because the transceiver already existed and only needed `replaceTrack`.
- Click **Verify call**. Read the code aloud: it is a hash of both DTLS fingerprints, and matching codes mean nothing is intercepting the media.
- Note the banner about IP addresses being visible to peers — inherent to peer-to-peer, stated rather than hidden.
- Open a third window as **Carol** and join. Three tiles. The fifth join would be refused with "Call is full".
- Close Bob's window. His tile disappears immediately rather than freezing.

## 5 · Collaborative whiteboard (60s)

- Click **Whiteboard** in both windows. The seeded sketch is already there.
- Draw in Alice's window — strokes appear in Bob's as you draw, and remote cursors follow.
- Press **Undo** in Bob's window and try to undo one of Alice's strokes: refused. Undo is per-author, because global undo means one person erasing another's work.
- Open a third window and join late — the whole board replays from the encrypted op log.
- Reload the page. The board survives, because the op log is the board.

## 6 · Reliability under failure (60s)

The part reviewers usually assume is broken.

```bash
docker compose stop app
```

- Both windows show "Reconnecting… messages you send are queued".
- Type and send two messages in Alice's window. They render as **Queued**.

```bash
docker compose start app
```

- The queue flushes automatically, exactly once, in order.
- Bob receives them, and anything sent while he was disconnected arrives through backfill with no duplicates.

Then show why duplicates are impossible rather than unlikely:

```bash
pnpm vitest run --project integration -t "idempotent send"
```

## 7 · Authentication (45s)

- Sign out and back in — the session restores from an httpOnly refresh cookie plus keys in IndexedDB.
- Create a new account to show the **recovery code** screen. It cannot be skipped, because losing it means losing all history and no server-side reset can recover it.
- Optional, for the security-minded: `docker compose exec mongo mongosh rtc --eval 'db.users.findOne({}, {emailSealed:1, proofHash:1})'` — the email is a sealed binary field and the password is an Argon2id hash of a client-derived proof.

## Things worth saying out loud

- The server is a router and a filing cabinet. It authorizes, orders and stores; it decrypts nothing.
- Retrying a send is always safe, because the message id is minted by the client and enforced unique by the database.
- Every limit is written down: four participants per call, gaps in sequence numbers, no TURN by default, one identity key per account.
- `docs/SECURITY.md` has a section on the security theatre we chose *not* to build. Knowing what to leave out is part of the design.
