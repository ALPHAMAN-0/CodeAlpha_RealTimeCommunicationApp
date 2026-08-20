import { VIDEO_PROFILES } from '@rtc/shared';

/**
 * Local capture.
 *
 * Tracks are stopped explicitly on leave: the camera indicator light staying
 * on after a call ends is something users notice immediately and read as the
 * app spying on them.
 */
export class LocalMedia {
  private stream: MediaStream | undefined;
  private screen: MediaStream | undefined;

  async start(constraints?: { audio?: boolean; video?: boolean }): Promise<MediaStream> {
    if (this.stream) return this.stream;
    this.stream = await navigator.mediaDevices.getUserMedia({
      audio: constraints?.audio === false ? false : {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true,
      },
      video: constraints?.video === false ? false : {
        width: { ideal: VIDEO_PROFILES.high.width },
        height: { ideal: VIDEO_PROFILES.high.height },
        frameRate: { ideal: 30, max: 30 },
        facingMode: 'user',
      },
    });
    return this.stream;
  }

  get current(): MediaStream | undefined {
    return this.stream;
  }

  micTrack(): MediaStreamTrack | undefined {
    return this.stream?.getAudioTracks()[0];
  }

  cameraTrack(): MediaStreamTrack | undefined {
    return this.stream?.getVideoTracks()[0];
  }

  screenTrack(): MediaStreamTrack | undefined {
    return this.screen?.getVideoTracks()[0];
  }

  /**
   * Mute and camera-off flip `enabled` rather than removing the track.
   *
   * Removing it would force a renegotiation and freeze the remote's last
   * frame — which looks like a crash. A disabled track keeps flowing as
   * silence or black, and the peer learns the real state from the explicit
   * rtc:media-state event, since `enabled` is not observable remotely.
   */
  setAudioEnabled(enabled: boolean): void {
    const track = this.micTrack();
    if (track) track.enabled = enabled;
  }

  setVideoEnabled(enabled: boolean): void {
    const track = this.cameraTrack();
    if (track) track.enabled = enabled;
  }

  async startScreenShare(onEnded: () => void): Promise<MediaStreamTrack> {
    this.screen = await navigator.mediaDevices.getDisplayMedia({
      video: { frameRate: { ideal: 15, max: 30 } },
      audio: false,
    });
    const track = this.screen.getVideoTracks()[0]!;
    // Hint the encoder to preserve text legibility over motion smoothness.
    track.contentHint = 'detail';
    // The browser's own "Stop sharing" bar ends the track without telling the
    // app, so this is the only way to keep UI state honest.
    track.addEventListener('ended', () => {
      this.screen = undefined;
      onEnded();
    });
    return track;
  }

  stopScreenShare(): void {
    this.screen?.getTracks().forEach((t) => t.stop());
    this.screen = undefined;
  }

  stopAll(): void {
    this.stream?.getTracks().forEach((t) => t.stop());
    this.stopScreenShare();
    this.stream = undefined;
  }
}

export const localMedia = new LocalMedia();

/** Distinguish "no camera" from "permission denied" — the fixes differ. */
export function describeMediaError(err: unknown): string {
  const name = (err as { name?: string }).name;
  switch (name) {
    case 'NotAllowedError':
      return 'Camera and microphone access was denied. Allow it in your browser’s site settings, then rejoin.';
    case 'NotFoundError':
      return 'No camera or microphone was found. You can still join to listen and share your screen.';
    case 'NotReadableError':
      return 'Your camera or microphone is already in use by another application.';
    case 'OverconstrainedError':
      return 'Your camera does not support the requested resolution.';
    default:
      return 'Could not access your camera or microphone.';
  }
}
