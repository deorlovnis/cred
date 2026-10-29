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
// How long to wait for a click (or Enter) to change the URL or the page's text.
const CHANGE_WAIT = 3000;
const REQUEST_LIMIT = 100;
const FIND_LIMIT = 50;
let config, browser, context, page;
const notes = [];
const requests = new Set();
let blockedWrites = false;
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
  if (config.writes === 'allow') return route.continue();
  // cred lists these in `cred info`, so the user can add the harmless ones to allow_writes.
  send({ write: { method, url } });
  if (config.writes === 'ask' && (await ask(method, url))) return route.continue();
  note(`blocked ${method} ${url.slice(0, 120)} (writes aren't allowed)`);
  blockedWrites = true;
  return route.abort('blockedbyclient');
}

// A data request as the agent sees it: method and URL, never headers or bodies. Query values
// longer than 16 characters look like tokens and are left out.
function recordRequest(req) {
  if (!['xhr', 'fetch'].includes(req.resourceType())) return;
  let line;
  try {
    const u = new URL(req.url());
    const query = [...u.searchParams].map(([k, v]) => (v.length <= 16 ? `${k}=${v}` : `${k}=…`)).join('&');
    line = `${req.method()} ${u.origin}${u.pathname}${query && `?${query}`}`;
  } catch {
    return;
  }
  requests.delete(line);
  requests.add(line);
  if (requests.size > REQUEST_LIMIT) requests.delete(requests.values().next().value);
}

async function settle() {
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await page.waitForLoadState('networkidle', { timeout: 4000 }).catch(() => {});
}

// "ai" mode adds the [ref=…] handles that click/type take.
const ariaSnapshot = (target) => target.ariaSnapshot({ mode: 'ai', timeout: 10_000 });

async function describe({ ref, compact } = {}) {
  await settle();
  let snap = await ariaSnapshot(ref ? locate(ref) : page.locator(':root'));
  // A snapshot of one element drops the refs outside it; take the whole page again so they work.
  if (ref) await ariaSnapshot(page.locator(':root'));
  if (compact) snap = outline(snap).map((l) => l.text).join('\n');
  if (snap.length > SNAPSHOT_LIMIT) snap = snap.slice(0, SNAPSHOT_LIMIT) + '\n(cut off)';
  const blocked = notes.splice(0).map((n) => `note: ${n}\n`).join('');
  const hint = blockedWrites
    ? "note: the user can allow blocked writes by adding their URL prefixes to allow_writes in the site's [browse] policy (cred info lists them)\n"
    : '';
  blockedWrites = false;
  return `URL: ${page.url()}\nTitle: ${await page.title()}\n${blocked}${hint}\n${snap}`;
}

// One line per element that has a name or text, without indentation: the containers around
// them are dropped and a link's URL joins its line. A line with no ref of its own (plain
// text) says which element it is in.
function outline(snap) {
  const lines = [];
  const refs = [];
  for (const raw of snap.split('\n').filter((l) => l.trim())) {
    const depth = raw.search(/\S/) / 2;
    const text = raw.trim().replace(' [cursor=pointer]', '');
    const own = text.match(/\[ref=(\w+)\]/)?.[1];
    refs.length = depth;
    refs[depth] = own ?? refs[depth - 1];
    if (text.startsWith('- /')) {
      if (lines.at(-1)?.depth === depth - 1) lines.at(-1).text = `${lines.at(-1).text.replace(/:$/, '')} ${text.slice(2)}`;
    } else if (!/^- [\w-]+( \[[^\]]*\])*:?$/.test(text)) {
      lines.push({ depth, text: own || !refs[depth] ? text : `${text} [in ref=${refs[depth]}]` });
    }
  }
  return lines;
}

async function find(text) {
  await settle();
  const needle = text.toLowerCase();
  const found = outline(await ariaSnapshot(page.locator(':root'))).filter((l) => l.text.toLowerCase().includes(needle));
  const shown = found.slice(0, FIND_LIMIT).map((l) => l.text);
  if (found.length > FIND_LIMIT) shown.push(`(${found.length - FIND_LIMIT} more)`);
  return `URL: ${page.url()}\n\n${shown.join('\n') || `nothing on the page matches "${text}"`}`;
}

const SIGNATURE = `(() => {
  const t = document.body?.innerText ?? '';
  let h = 0;
  for (let i = 0; i < t.length; i++) h = (h * 31 + t.charCodeAt(i)) | 0;
  return location.href + '|' + document.title + '|' + t.length + '|' + h;
})()`;

// Run an action that may change the page, then wait (briefly) for the URL or the page's text
// to change before describing it: a client-side navigation updates the page after the click.
async function acting(action) {
  const before = await page.evaluate(SIGNATURE).catch(() => null);
  await action();
  if (before) {
    await page.waitForFunction(`${SIGNATURE} !== ${JSON.stringify(before)}`, null, { timeout: CHANGE_WAIT, polling: 100 }).catch(() => {});
  }
  return describe();
}

const locate = (ref) => {
  if (!/^[a-z0-9]{1,16}$/i.test(String(ref))) throw new Error(`not an element ref: ${ref}`);
  return page.locator(`aria-ref=${ref}`);
};

const commands = {
  async open(msg) {
    config = msg.config;
    // Playwright passes --no-sandbox unless asked for Chromium's own sandbox.
    browser = await chromium.launch({ headless: true, chromiumSandbox: true });
    context = await browser.newContext({
      serviceWorkers: 'block',
      acceptDownloads: false,
      viewport: { width: 1280, height: 900 },
    });
    await context.route('**/*', guard);
    context.on('request', recordRequest);
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
  snapshot: ({ ref, compact }) => describe({ ref, compact }),
  find: ({ text }) => find(text),
  requests: () => `Data requests the page made (method and URL; query values over 16 characters left out):\n${[...requests].join('\n') || 'none yet'}`,
  // The image goes back to cred in memory; nothing is written to disk.
  async screenshot({ full_page }) {
    if (!config.screenshots) throw new Error("this site's policy doesn't allow screenshots");
    await settle();
    const image = await page.screenshot({ type: 'jpeg', quality: 70, fullPage: full_page === true, timeout: 15_000 });
    return JSON.stringify({ url: page.url(), jpeg: image.toString('base64') });
  },
  click: ({ ref }) => acting(() => locate(ref).click({ timeout: 5_000 })),
  async type({ ref, text, submit }) {
    await locate(ref).fill(text, { timeout: 10_000 });
    return submit ? acting(() => locate(ref).press('Enter')) : describe();
  },
  // Enter can submit a form or follow a link; other keys rarely change what the page says.
  press: ({ key }) => (/(^|\+)Enter$/.test(key) ? acting(() => page.keyboard.press(key)) : page.keyboard.press(key).then(() => describe())),
  // Types a stored credential (cred sends it as `value`) into a field. The page, and the frame
  // holding the field, must be on one of the policy's origins.
  async fill({ ref, value }) {
    const target = locate(ref);
    const frame = await (await target.elementHandle({ timeout: 5_000 })).ownerFrame();
    for (const f of [page.mainFrame(), frame]) {
      if (!allowed(config.origins, originOf(f?.url() ?? ''))) throw new Error("this page isn't on the site's own origin, so cred won't type a credential into it");
    }
    await target.fill(value, { timeout: 10_000 });
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
    let text = String(e?.message ?? e).replace(/\u001b\[[0-9;]*m/g, '');
    // A credential cred was asked to type must not come back in an error.
    if (msg.value) text = text.replaceAll(msg.value, '********');
    send({ id: msg.id, ok: false, error: text.split('\n').slice(0, 3).join('\n') });
  }
  if (msg.cmd === 'close') process.exit(0);
});
rl.on('close', async () => {
  await browser?.close().catch(() => {});
  process.exit(0);
});
