// cred browser runner: drives one headless Chromium for one site, on cred's behalf.
//
// It talks JSON lines with cred over stdin/stdout (stdout carries only protocol messages).
// The browser profile lives in memory only. Every request is checked against the site's
// rules from cred: pages only from `origins`, other requests also to `requests`, and anything
// but GET/HEAD/OPTIONS follows `writes` (deny, ask cred, or allow). The agent never talks to
// this process; cred relays a narrow set of commands and masks what comes back.

import readline from 'node:readline';
import { chromium } from 'playwright-core';

const SNAPSHOT_LIMIT = 60_000;
let config, browser, context, page;
const notes = [];
const answers = new Map();
let asks = 0;

const send = (msg) => process.stdout.write(JSON.stringify(msg) + '\n');

function originOf(url) {
  try {
    const u = new URL(url.replace(/^ws(s?):/, 'http$1:'));
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.origin : null;
  } catch {
    return null;
  }
}

// A site rule: "*" (any https site), "https://*.example.com" (the domain and its subdomains),
// or an exact origin.
function allowed(list, origin) {
  if (!origin) return false;
  return list.some((site) => {
    if (site === '*') return origin.startsWith('https://');
    const wild = site.match(/^(https?):\/\/\*\.(.+)$/);
    if (!wild) return site === origin;
    const u = new URL(origin);
    return u.protocol === `${wild[1]}:` && (u.hostname === wild[2] || u.hostname.endsWith(`.${wild[2]}`));
  });
}

function note(text) {
  if (notes.length < 30 && !notes.includes(text)) notes.push(text);
}

// Ask cred (which asks the user) whether a page may send a write request.
function ask(method, url) {
  const id = ++asks;
  send({ ask: id, method, url });
  return new Promise((resolve) => answers.set(id, resolve));
}

async function guard(route) {
  const req = route.request();
  const url = req.url();
  const origin = originOf(url);
  const mainFrameNavigation = req.isNavigationRequest() && req.frame() === page?.mainFrame();
  const sites = mainFrameNavigation ? config.origins : config.origins.concat(config.requests);
  if (!allowed(sites, origin)) {
    note(`blocked ${req.method()} ${url.slice(0, 120)} (host not allowed)`);
    return route.abort('blockedbyclient');
  }
  const method = req.method();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return route.continue();
  if (config.allow_writes.some((prefix) => url.startsWith(prefix))) return route.continue();
  if (config.writes === 'allow' || (config.writes === 'ask' && (await ask(method, url)))) return route.continue();
  note(`blocked ${method} ${url.slice(0, 120)} (writes aren't allowed)`);
  return route.abort('blockedbyclient');
}

async function settle() {
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await page.waitForLoadState('networkidle', { timeout: 4000 }).catch(() => {});
}

async function describe() {
  await settle();
  // "ai" mode adds the [ref=…] handles that click/type take.
  let snap = await page.locator(':root').ariaSnapshot({ mode: 'ai', timeout: 10_000 });
  if (snap.length > SNAPSHOT_LIMIT) snap = snap.slice(0, SNAPSHOT_LIMIT) + '\n(cut off)';
  const blocked = notes.splice(0).map((n) => `note: ${n}\n`).join('');
  return `URL: ${page.url()}\nTitle: ${await page.title()}\n${blocked}\n${snap}`;
}

const locate = (ref) => {
  if (!/^[a-z0-9]{1,16}$/i.test(String(ref))) throw new Error(`not an element ref: ${ref}`);
  return page.locator(`aria-ref=${ref}`);
};

const commands = {
  async open(msg) {
    config = msg.config;
    browser = await chromium.launch({ headless: true });
    context = await browser.newContext({
      serviceWorkers: 'block',
      acceptDownloads: false,
      viewport: { width: 1280, height: 900 },
    });
    await context.route('**/*', guard);
    await context.routeWebSocket(/.*/, (ws) => {
      if (allowed(config.origins.concat(config.requests), originOf(ws.url()))) return ws.connectToServer();
      note(`blocked websocket ${ws.url().slice(0, 120)}`);
      ws.close();
    });
    if (config.cookies.length) await context.addCookies(config.cookies);
    if (config.storage.length) {
      await context.addInitScript((entries) => {
        for (const e of entries) {
          if (location.origin === e.origin) {
            try { localStorage.setItem(e.key, e.value); } catch {}
          }
        }
      }, config.storage);
    }
    page = await context.newPage();
    if (config.start) await page.goto(config.start, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    return describe();
  },
  async goto({ url }) {
    if (!allowed(config.origins, originOf(url))) throw new Error(`${originOf(url) ?? url} isn't one of the pages this site allows`);
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    return describe();
  },
  snapshot: () => describe(),
  // The image goes back to cred in memory; nothing is written to disk.
  async screenshot({ full_page }) {
    if (!config.screenshots) throw new Error("this site's policy doesn't allow screenshots");
    await settle();
    const image = await page.screenshot({ type: 'jpeg', quality: 70, fullPage: full_page === true, timeout: 15_000 });
    return JSON.stringify({ url: page.url(), jpeg: image.toString('base64') });
  },
  async click({ ref }) {
    await locate(ref).click({ timeout: 5_000 });
    return describe();
  },
  async type({ ref, text, submit }) {
    await locate(ref).fill(text, { timeout: 10_000 });
    if (submit) await locate(ref).press('Enter');
    return describe();
  },
  async press({ key }) {
    await page.keyboard.press(key);
    return describe();
  },
  async back() {
    await page.goBack({ timeout: 15_000 });
    return describe();
  },
  async close() {
    await browser?.close();
    return 'closed';
  },
};

const rl = readline.createInterface({ input: process.stdin });
rl.on('line', async (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if ('answer' in msg) {
    answers.get(msg.answer)?.(msg.allow === true);
    answers.delete(msg.answer);
    return;
  }
  const run = commands[msg.cmd];
  try {
    if (!run) throw new Error(`unknown command ${msg.cmd}`);
    if (msg.cmd !== 'open' && !page) throw new Error('no page is open');
    send({ id: msg.id, ok: true, text: await run(msg) });
  } catch (e) {
    // Playwright errors carry terminal colors and long call logs; keep the gist.
    const text = String(e?.message ?? e).replace(/\u001b\[[0-9;]*m/g, '');
    send({ id: msg.id, ok: false, error: text.split('\n').slice(0, 3).join('\n') });
  }
  if (msg.cmd === 'close') process.exit(0);
});
rl.on('close', async () => {
  await browser?.close().catch(() => {});
  process.exit(0);
});
