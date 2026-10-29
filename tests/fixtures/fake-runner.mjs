// A stand-in for runner/runner.mjs that needs no browser: it speaks the same JSON lines, and
// keeps "cookies" the way a site that rotates its session would: every close gives back the
// cookies it was opened with, each value one step further on ("v" -> "v#1" -> "v#2").
//
// For signing in by hand (`config.login`), the start page picks what the "person" does:
//   .../autoclose?site=x  closes the window at once, with a session for x
//   .../wait?site=x       waits for cred to ask for the session (Enter in the terminal)
//   .../nothing           closes the window without signing in
//   .../fail              can't start
// Every `open` config is appended to $FAKE_RUNNER_LOG, one JSON line each.

import fs from 'node:fs';
import readline from 'node:readline';

const send = (msg) => process.stdout.write(JSON.stringify(msg) + '\n');
let config;

const step = (value) => (/#(\d+)$/.test(value) ? value.replace(/#(\d+)$/, (_, n) => `#${Number(n) + 1}`) : `${value}#1`);

const signedIn = (start) => {
  const site = new URL(start).searchParams.get('site') ?? 'site';
  return {
    cookies: [{ name: 'session', value: `signed-in-to-${site}-by-hand`, domain: '127.0.0.1', path: '/', expires: -1, httpOnly: true, secure: false, sameSite: 'Lax' }],
    origins: [{ origin: 'http://127.0.0.1', localStorage: [{ name: 'token', value: `local-${site}-token-value` }] }],
  };
};

const page = () =>
  [
    'URL: fake',
    `cookies: ${config.cookies.map((c) => `${c.name}=${c.value}`).join('; ')}`,
    `storage: ${config.storage.map((e) => `${e.key}=${e.value}`).join('; ')}`,
    `proxy: ${JSON.stringify(config.proxy ?? null)}`,
  ].join('\n');

const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  const msg = JSON.parse(line);
  if (msg.cmd === 'open') {
    config = msg.config;
    if (process.env.FAKE_RUNNER_LOG) fs.appendFileSync(process.env.FAKE_RUNNER_LOG, JSON.stringify(config) + '\n');
    if (config.login && config.start.includes('/fail')) return send({ id: msg.id, ok: false, error: 'cannot start the window' });
    send({ id: msg.id, ok: true, text: page() });
    if (config.login && config.start.includes('/autoclose')) {
      send({ closed: true, storageState: signedIn(config.start) });
      process.exit(0);
    }
    if (config.login && config.start.includes('/nothing')) {
      send({ closed: true, storageState: { cookies: [], origins: [] } });
      process.exit(0);
    }
  } else if (msg.cmd === 'close') {
    const storageState = config.login
      ? signedIn(config.start)
      : { cookies: config.cookies.map((c) => ({ ...c, value: step(c.value) })), origins: [] };
    send({ id: msg.id, ok: true, text: JSON.stringify({ storageState }) });
    process.exit(0);
  } else {
    send({ id: msg.id, ok: true, text: page() });
  }
});
rl.on('close', () => process.exit(0));
