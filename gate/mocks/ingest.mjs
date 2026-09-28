// Sentry-protocol ingest test double (store + envelope endpoints, CORS). Records every request body for the gate's canary
// scan and a parsed summary of error events for the T5 probe. Listens on :9000. No outbound network.
import http from 'node:http'; import zlib from 'node:zlib';
const RAW = []; const EVENTS = [];
const decode = (buf, enc) => { try { if (/gzip/.test(enc)) return zlib.gunzipSync(buf); if (/deflate/.test(enc)) return zlib.inflateSync(buf); if (/br/.test(enc)) return zlib.brotliDecompressSync(buf); } catch (e) { } return buf; };
const summarize = (ev, fromBrowser, kind) => {
  const ex = ev.exception && (ev.exception.values || ev.exception); const hasEx = Array.isArray(ex) ? ex.length > 0 : !!ex;
  EVENTS.push({ kind, release: ev.release || null, environment: ev.environment || null, platform: ev.platform || null, sdk: ev.sdk && ev.sdk.name || null,
    has_exception: hasEx || ev.level === 'error' && !!(ev.message || ev.logentry), from_browser: fromBrowser, type: ev.type || 'event', at: new Date().toISOString() });
};
http.createServer((req, res) => {
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' };
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
  const u = new URL(req.url, 'http://x');
  if (req.method === 'GET' && u.pathname === '/__events') { res.writeHead(200, { 'Content-Type': 'application/json', ...cors }); return res.end(JSON.stringify(EVENTS)); }
  if (req.method === 'GET' && u.pathname === '/__raw') { res.writeHead(200, { 'Content-Type': 'application/octet-stream' }); return res.end(Buffer.concat(RAW.map(b => Buffer.concat([b, Buffer.from('\n')])))); }
  const ch = []; req.on('data', d => ch.push(d)); req.on('end', () => {
    const body = decode(Buffer.concat(ch), String(req.headers['content-encoding'] || '')); RAW.push(Buffer.from(req.url + ' ' + JSON.stringify(req.headers) + '\n')); RAW.push(body);
    const fromBrowser = !!req.headers.origin; const text = body.toString('utf8');
    try {
      if (/\/envelope\/?$/.test(u.pathname)) {
        const lines = text.split('\n'); let i = 1;
        while (i < lines.length) { let ih; try { ih = JSON.parse(lines[i]); } catch (e) { i++; continue; }
          const payload = lines[i + 1] || ''; i += 2; if (ih.type === 'event' || ih.type === 'error') { try { summarize(JSON.parse(payload), fromBrowser, 'envelope'); } catch (e) { } } }
      } else if (/\/store\/?$/.test(u.pathname)) {
        let t = text; if (!t.trim().startsWith('{')) { try { t = zlib.inflateSync(Buffer.from(t, 'base64')).toString('utf8'); } catch (e) { } }
        summarize(JSON.parse(t), fromBrowser, 'store');
      }
    } catch (e) { }
    res.writeHead(200, { 'Content-Type': 'application/json', ...cors }); res.end(JSON.stringify({ id: '00000000000000000000000000000000' }));
  });
}).listen(9000, '0.0.0.0');
