// AGENTS APP bake-off gate - probe and oracle runner (runs inside the pinned Playwright image, on the preview's internal
// network only: it can reach the preview, the ingest test double and the book-API test double, nothing else).
// Input: /out/plan.json. Output: /out/results.jsonl (one line per criterion), /out/shots/*.png, /out/crawl/*, /out/runner.log.
// The runner never receives the canary: the gate scans what the runner captured.
import fs from 'node:fs'; import path from 'node:path'; import { spawn } from 'node:child_process'; import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { chromium } = require('playwright'); const { PNG } = require('pngjs'); const pixelmatch = require('pixelmatch').default || require('pixelmatch');
const AXE = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const PLAN = JSON.parse(fs.readFileSync('/out/plan.json', 'utf8')); const BASE = PLAN.base; const INGEST = PLAN.ingest;
fs.mkdirSync('/out/shots', { recursive: true }); fs.mkdirSync('/out/crawl', { recursive: true });
const LOG = fs.createWriteStream('/out/runner.log', { flags: 'a' }); const log = (...a) => LOG.write(new Date().toISOString() + ' ' + a.map(x => typeof x === 'string' ? x : JSON.stringify(x)).join(' ') + '\n');
const RES = fs.createWriteStream('/out/results.jsonl', { flags: 'a' });
const put = (crit, result, detail, source) => { RES.write(JSON.stringify({ crit, result, detail: String(detail || '').slice(0, 800), source }) + '\n'); log('RESULT', crit, result, detail); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const browser = await chromium.launch({ args: ['--no-sandbox'] });
const newCtx = async (o = {}) => browser.newContext({ viewport: { width: o.width || 1280, height: o.height || 800 }, ignoreHTTPSErrors: true, ...o.ctx });
const ANIM = '*,*::before,*::after{animation:none!important;transition:none!important;caret-color:transparent!important}';
async function signIn(page, u) {
  await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded' });
  await page.getByLabel('Email', { exact: true }).fill(u.email); await page.getByLabel('Password', { exact: true }).fill(u.password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.waitForURL(u => new URL(u).pathname === '/lists', { timeout: 15000 });
}
const med = a => { const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length / 2)]; };

const PROBES = {
  async layout(p) { // no horizontal overflow, one h1 with text, required links - at each width
    const bad = [];
    for (const w of p.widths) {
      const ctx = await newCtx({ width: w, height: 900 }); const page = await ctx.newPage();
      try {
        const r = await page.goto(BASE + p.route, { waitUntil: 'load', timeout: 30000 }); await sleep(500);
        if (!r || r.status() >= 400) { bad.push(`${w}px: HTTP ${r && r.status()}`); continue; }
        const m = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, iw: window.innerWidth, h1: [...document.querySelectorAll('h1')].map(h => h.innerText) }));
        if (m.sw > m.iw + 1) bad.push(`${w}px: horizontal overflow ${m.sw}>${m.iw}`);
        if (m.h1.length !== 1 || !m.h1[0].includes(p.h1)) bad.push(`${w}px: h1 ${JSON.stringify(m.h1)}`);
        for (const [name, href] of Object.entries(p.links || {})) {
          const l = page.getByRole('link', { name, exact: true });
          const n = await l.count(); let ok = false;
          for (let i = 0; i < n; i++) { const h = await l.nth(i).getAttribute('href'); if (h && new URL(h, BASE).pathname === href && await l.nth(i).isVisible()) ok = true; }
          if (!ok) bad.push(`${w}px: no visible link "${name}" -> ${href}`);
        }
      } catch (e) { bad.push(`${w}px: ${e.message.split('\n')[0]}`); } finally { await ctx.close(); }
    }
    return bad.length ? ['fail', bad.join('; ')] : ['pass', 'widths ' + p.widths.join(',')];
  },
  async axe(p) {
    const bad = []; const counts = {};
    for (const w of p.widths) {
      const ctx = await newCtx({ width: w, height: 900 }); const page = await ctx.newPage();
      try {
        await page.goto(BASE + p.route, { waitUntil: 'load', timeout: 30000 }); await sleep(500);
        await page.addScriptTag({ content: AXE });
        const v = await page.evaluate(async () => (await window.axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] } })).violations.map(x => ({ id: x.id, impact: x.impact, n: x.nodes.length })));
        const sev = v.filter(x => x.impact === 'serious' || x.impact === 'critical'); counts[w] = v;
        if (sev.length) bad.push(`${w}px: ${sev.map(x => x.id + '(' + x.impact + ',' + x.n + ')').join(',')}`);
      } catch (e) { return ['unknown', `${w}px: ${e.message.split('\n')[0]}`]; } finally { await ctx.close(); }
    }
    log('axe', counts);
    return bad.length ? ['fail', bad.join('; ')] : ['pass', '0 serious/critical at ' + p.widths.join(',')];
  },
  async lcp(p) {
    const vals = [];
    for (let i = 0; i < (p.runs || 3); i++) {
      const ctx = await newCtx({ width: 375, height: 812 }); const page = await ctx.newPage();
      try {
        await page.addInitScript(() => { window.__lcp = 0; new PerformanceObserver(l => { for (const e of l.getEntries()) window.__lcp = Math.max(window.__lcp, e.startTime); }).observe({ type: 'largest-contentful-paint', buffered: true }); });
        const cdp = await ctx.newCDPSession(page); await cdp.send('Emulation.setCPUThrottlingRate', { rate: p.cpu || 4 });
        await page.goto(BASE + p.route, { waitUntil: 'load', timeout: 60000 }); await sleep(3000);
        vals.push(await page.evaluate(() => window.__lcp));
      } catch (e) { return ['unknown', e.message.split('\n')[0]]; } finally { await ctx.close(); }
    }
    const m = med(vals); log('lcp', vals);
    if (!(m > 0)) return ['unknown', 'no LCP entry: ' + JSON.stringify(vals)];
    return [m <= p.max_ms ? 'pass' : 'fail', `median LCP ${Math.round(m)} ms (runs ${vals.map(Math.round).join(',')}; target <= ${p.max_ms})`];
  },
  async baseline(p) { // full-page screenshots compared with owner-approved baselines (pixelmatch threshold 0.1; max 1% differing pixels)
    const bad = [], missing = [];
    for (const s of p.shots) {
      const ctx = await newCtx({ width: s.width, height: s.height || 800 }); const page = await ctx.newPage();
      try {
        if (s.user) { await signIn(page, PLAN.users[s.user]); }
        if (s.setup === 'one-list') { // deterministic content for the list screen
          await page.goto(BASE + '/lists', { waitUntil: 'load' });
          if (!(await page.getByRole('link', { name: 'Weekend reads', exact: true }).count())) {
            await page.goto(BASE + '/lists/new'); await page.getByLabel('Name', { exact: true }).fill('Weekend reads'); await page.getByRole('button', { name: 'Create list', exact: true }).click(); await page.waitForURL(/\/lists\/[^/]+$/);
          }
        }
        await page.goto(BASE + s.route, { waitUntil: 'load', timeout: 30000 }); await page.addStyleTag({ content: ANIM }); await sleep(800);
        const buf = await page.screenshot({ fullPage: true }); fs.writeFileSync(`/out/shots/${p.task}-${s.name}.png`, buf);
        const bf = path.join('/baselines', p.task, s.name + '.png');
        if (!fs.existsSync(bf)) { missing.push(s.name); continue; }
        const a = PNG.sync.read(fs.readFileSync(bf)), b = PNG.sync.read(buf);
        if (a.width !== b.width || a.height !== b.height) { bad.push(`${s.name}: size ${b.width}x${b.height} vs baseline ${a.width}x${a.height}`); continue; }
        const d = pixelmatch(a.data, b.data, null, a.width, a.height, { threshold: 0.1 }); const r = d / (a.width * a.height);
        if (r > (p.max_ratio || 0.01)) bad.push(`${s.name}: ${(r * 100).toFixed(2)}% pixels differ`);
      } catch (e) { bad.push(`${s.name}: ${e.message.split('\n')[0]}`); } finally { await ctx.close(); }
    }
    if (bad.length) return ['fail', bad.join('; ')];
    if (missing.length) return ['unknown', 'no owner-approved baseline yet for ' + missing.join(',')];
    return ['pass', 'matches baselines ' + p.shots.map(s => s.name).join(',')];
  },
  async sentry(p) { // T5: forced server and client errors reach the ingest with the release tag
    const out = {};
    const events = async () => { try { const r = await fetch(INGEST + '/__events'); return await r.json(); } catch (e) { return []; } };
    const hasErr = (ev, ua) => ev.some(e => e.release === PLAN.release && e.has_exception && (ua === undefined || e.from_browser === ua));
    try { await fetch(BASE + '/debug/server-error'); } catch (e) { }
    let ev = []; for (let i = 0; i < 20 && !hasErr(ev = await events(), false); i++) await sleep(1000);
    out.server = hasErr(ev, false) && ev.some(e => e.release === PLAN.release && e.has_exception && !e.from_browser && e.environment === PLAN.app_env);
    const ctx = await newCtx(); const page = await ctx.newPage();
    try { await page.goto(BASE + '/debug/client-error', { waitUntil: 'load', timeout: 30000 }); await page.getByRole('button', { name: 'Trigger client error', exact: true }).click(); } catch (e) { log('client-error page', e.message); }
    for (let i = 0; i < 20 && !hasErr(ev = await events(), true); i++) await sleep(1000);
    await ctx.close(); out.client = hasErr(ev, true);
    fs.writeFileSync('/out/ingest-summary.json', JSON.stringify(ev.map(e => ({ release: e.release, environment: e.environment, from_browser: e.from_browser, has_exception: e.has_exception })), null, 1));
    return out;
  },
};

async function crawl(p) { // capture every client-visible response body + storage/cookies on the key pages (canary scan by the gate)
  let n = 0; const index = []; const seenJs = new Set();
  const attach = page => page.on('response', async r => {
    try { const b = await r.body(); const f = `r${++n}.bin`; fs.writeFileSync('/out/crawl/' + f, b); index.push({ f, url: r.url(), status: r.status(), headers: await r.allHeaders() });
      if (/javascript/.test(r.headers()['content-type'] || '') || r.url().endsWith('.js')) seenJs.add(r.url()); } catch (e) { }
  });
  const dumpStorage = async (page, tag) => { try { const s = await page.evaluate(() => ({ cookie: document.cookie, local: JSON.stringify(Object.entries(localStorage)), session: JSON.stringify(Object.entries(sessionStorage)) }));
      const c = await page.context().cookies(); fs.writeFileSync(`/out/crawl/storage-${++n}.json`, JSON.stringify({ tag, url: page.url(), ...s, cookies: c })); } catch (e) { } };
  const visited = [];
  const ctx = await newCtx(); const page = await ctx.newPage(); attach(page);
  for (const r of p.routes) { try { await page.goto(BASE + r, { waitUntil: 'load', timeout: 30000 }); await sleep(300); await dumpStorage(page, 'anon ' + r); visited.push(r); } catch (e) { log('crawl', r, e.message); } }
  if (p.auth) {
    try {
      await signIn(page, PLAN.users.alice); visited.push('signed-in /lists'); await dumpStorage(page, 'alice /lists');
      await page.goto(BASE + '/lists/new'); await page.getByLabel('Name', { exact: true }).fill('Canary crawl list'); await page.getByRole('button', { name: 'Create list', exact: true }).click();
      await page.waitForURL(/\/lists\/[^/]+$/); const listUrl = page.url(); visited.push('list page'); await dumpStorage(page, 'alice list');
      if (p.books) { try { await page.getByLabel('Search books', { exact: true }).fill('dune'); await page.getByRole('button', { name: 'Search', exact: true }).click(); await sleep(2000);
          const add = page.getByRole('button', { name: 'Add', exact: true }).first(); if (await add.count()) { await add.click(); await sleep(1000); } visited.push('book search'); } catch (e) { log('crawl books', e.message); } }
      await page.goto(listUrl + '/edit').catch(() => { }); await sleep(300); await dumpStorage(page, 'alice edit');
      if (p.share) { try { await page.goto(listUrl); await page.getByRole('button', { name: 'Create share link', exact: true }).click(); await sleep(1500);
          const link = await page.getByLabel('Share link', { exact: true }).inputValue(); visited.push('share link created');
          const actx = await newCtx(); const ap = await actx.newPage(); attach(ap); await ap.goto(link.replace(/^https?:\/\/[^/]+/, BASE), { waitUntil: 'load' }); await sleep(500); await dumpStorage(ap, 'anon share'); visited.push('share page'); await actx.close(); } catch (e) { log('crawl share', e.message); } }
    } catch (e) { log('crawl auth', e.message.split('\n')[0]); }
  }
  await ctx.close();
  // source maps referenced by (or conventionally next to) every JavaScript file that was loaded
  for (const u of seenJs) for (const m of [u + '.map']) { try { const r = await fetch(m); if (r.ok) { const b = Buffer.from(await r.arrayBuffer()); const f = `r${++n}.bin`; fs.writeFileSync('/out/crawl/' + f, b); index.push({ f, url: m, status: r.status, sourcemap: true }); } } catch (e) { } }
  for (const it of [...index]) { if (!/\.js(\?|$)/.test(it.url)) continue; try { const t = fs.readFileSync('/out/crawl/' + it.f, 'utf8'); const mm = t.match(/sourceMappingURL=([^\s'"]+)/); if (mm && !mm[1].startsWith('data:')) { const mu = new URL(mm[1], it.url).href; const r = await fetch(mu); if (r.ok) { const f = `r${++n}.bin`; fs.writeFileSync('/out/crawl/' + f, Buffer.from(await r.arrayBuffer())); index.push({ f, url: mu, status: r.status, sourcemap: true }); } } } catch (e) { } }
  fs.writeFileSync('/out/crawl/index.json', JSON.stringify({ visited, responses: index.length, index }, null, 0));
  log('crawl', { visited, responses: index.length });
}

async function runOracle(o) { // an owner-approved oracle of record, from the BASE branch: node <file> <baseURL>
  return new Promise(res => {
    const ch = spawn('node', [o.file, BASE], { env: { PATH: process.env.PATH, NODE_PATH: process.env.NODE_PATH, PLAYWRIGHT_BROWSERS_PATH: process.env.PLAYWRIGHT_BROWSERS_PATH, HOME: '/tmp', BASE_URL: BASE, INGEST_URL: INGEST }, stdio: ['ignore', 'pipe', 'pipe'] });
    let so = '', se = ''; ch.stdout.on('data', d => so += d); ch.stderr.on('data', d => se += d);
    const t = setTimeout(() => { ch.kill('SIGKILL'); }, (o.timeout_s || 600) * 1000);
    ch.on('close', (code, sig) => { clearTimeout(t); res({ code, sig, so, se }); });
  });
}

for (const pr of PLAN.probes || []) {
  log('probe', pr.name, pr.crit);
  try {
    if (pr.name === 'crawl') { await crawl(pr.params); continue; }
    const r = await PROBES[pr.name](pr.params);
    if (pr.name === 'sentry') { put(pr.crits.server, r.server ? 'pass' : 'fail', r.server ? 'server event with release received' : 'no server error event with release/environment within 20 s', 'probe:sentry');
      put(pr.crits.client, r.client ? 'pass' : 'fail', r.client ? 'browser event with release received' : 'no browser error event with release within 20 s', 'probe:sentry'); continue; }
    put(pr.crit, r[0], r[1], 'probe:' + pr.name);
  } catch (e) { if (pr.crit) put(pr.crit, 'unknown', 'probe crashed: ' + e.message.split('\n')[0], 'probe:' + pr.name); log('probe crash', pr.name, e.stack); }
}
for (const o of PLAN.oracles || []) {
  log('oracle', o.file); const r = await runOracle(o); const seen = {};
  for (const line of r.so.split('\n')) { try { const j = JSON.parse(line); if (j && typeof j.criterion === 'string') (seen[j.criterion] = seen[j.criterion] || []).push(j); } catch (e) { } }
  fs.writeFileSync('/out/oracle-' + path.basename(path.dirname(o.file)) + '-' + path.basename(o.file) + '.log', `exit ${r.code} ${r.sig || ''}\n--- stdout ---\n${r.so.slice(-20000)}\n--- stderr ---\n${r.se.slice(-8000)}`);
  for (const [local, crit] of Object.entries(o.crits)) {
    const s = seen[local] || [];
    if (r.code !== 0 || s.length !== 1 || !['pass', 'fail'].includes(s[0].result)) put(crit, 'unknown', `oracle exit ${r.code}${r.sig ? ' ' + r.sig : ''}, ${s.length} result line(s) for ${local}`, o.file);
    else put(crit, s[0].result, s[0].detail || '', o.file);
  }
}
await browser.close(); RES.end(); LOG.end();
