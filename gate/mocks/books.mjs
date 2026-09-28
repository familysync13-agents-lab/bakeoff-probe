// Book-search API test double in Open Library /search.json format. Listens on :9100. No outbound network.
//   q=__error__ -> 500   q=__malformed__ -> 200 invalid JSON   q=__timeout__ -> never answers   q=zzzz-nothing -> no results
import http from 'node:http';
const W = (key, title, authors, year, cover) => ({ key: '/works/' + key, title, author_name: authors, first_publish_year: year, cover_i: cover });
const FIX = {
  dune: [W('OL893415W', 'Dune', ['Frank Herbert'], 1965, 11481354), W('OL893526W', 'Dune Messiah', ['Frank Herbert'], 1969, 6976407),
         W('OL893527W', 'Children of Dune', ['Frank Herbert'], 1976, 6976410), W('OL16808977W', 'Dune: House Atreides', ['Brian Herbert', 'Kevin J. Anderson'], 1999, 8231856)],
  orwell: [W('OL1168083W', 'Nineteen Eighty-Four', ['George Orwell'], 1949, 9267242), W('OL1168007W', 'Animal Farm', ['George Orwell'], 1945, 11261770)],
  tolkien: [W('OL27448W', 'The Lord of the Rings', ['J.R.R. Tolkien'], 1954, 14625765), W('OL262758W', 'The Hobbit', ['J.R.R. Tolkien'], 1937, 14627509)],
};
let N = 0;
http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x'); N++;
  if (u.pathname === '/__count') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ requests: N })); }
  if (u.pathname !== '/search.json') { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{"error":"not found"}'); }
  const q = (u.searchParams.get('q') || '').trim().toLowerCase(); const limit = Math.max(1, Math.min(100, Number(u.searchParams.get('limit') || 100)));
  if (q === '__timeout__') return;   // never answers
  if (q === '__error__') { res.writeHead(500, { 'Content-Type': 'application/json' }); return res.end('{"error":"internal"}'); }
  if (q === '__malformed__') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end('{"numFound": 3, "docs": [ {"title": "Dune",'); }
  const docs = q === 'zzzz-nothing' ? [] : (FIX[q] || [W('OL' + (100000 + q.length) + 'W', 'Result for ' + q, ['Test Author'], 2001, 1)]);
  res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ numFound: docs.length, start: 0, docs: docs.slice(0, limit) }));
}).listen(9100, '0.0.0.0');
