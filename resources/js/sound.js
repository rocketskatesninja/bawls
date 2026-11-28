// The new-alert chirp: two short tones made with Web Audio, so there's no
// sound file to load. Off by default; the choice is kept per browser.
//
// Browsers only let a page make sound after a click or key press on it. The
// toggle's own click counts; after a reload, the first click or key press
// anywhere on the page does (until then a new alert is silent).

import { SOUND, load, save } from './storage';

let audio = null;

export function soundOn() {
    return load(SOUND) === 'on';
}

export function setSoundOn(on) {
    save(SOUND, on ? 'on' : null);
}

/** Start the audio. Call it from a click or key press; resolves once it's running. */
export function unlockSound() {
    const Context = window.AudioContext || window.webkitAudioContext;
    if (!Context) return Promise.resolve();
    audio ??= new Context();
    return audio.state === 'suspended' ? audio.resume().catch(() => {}) : Promise.resolve();
}

export function chirp() {
    if (!audio || audio.state !== 'running') return;
    const start = audio.currentTime + 0.01;
    [880, 1320].forEach((frequency, i) => {
        const tone = audio.createOscillator();
        const volume = audio.createGain();
        const at = start + i * 0.1;
        tone.type = 'sine';
        tone.frequency.value = frequency;
        volume.gain.setValueAtTime(0, at);
        volume.gain.linearRampToValueAtTime(0.08, at + 0.01);
        volume.gain.exponentialRampToValueAtTime(0.0001, at + 0.09);
        tone.connect(volume).connect(audio.destination);
        tone.start(at);
        tone.stop(at + 0.1);
    });
}
