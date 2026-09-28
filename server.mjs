import http from 'node:http'; import pg from 'pg';
const db = new pg.Pool({ connectionString: process.env.DATABASE_URL });
await db.query('create table if not exists users (id serial primary key, name text not null, email text unique not null)');
await db.query("insert into users (name, email) values ('Alice','alice@example.test'),('Bob','bob@example.test') on conflict (email) do nothing");
const LEAK = process.env.DRY_LEAK === '1' || (await import('node:fs')).existsSync('./LEAK');
const page = () => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shared Reading Lists</title><style>body{margin:0;font-family:system-ui,sans-serif;color:#111;background:#fff}header,footer{padding:16px 24px;background:#f3f4f6}
main{padding:32px 24px;max-width:960px;margin:auto}h1{font-size:2rem;margin:0 0 12px}a{color:#1d4ed8}nav a{margin-right:16px}</style></head>
<body><header><strong>Shared Reading Lists</strong> <nav aria-label="Primary"><a href="/signup">Sign up</a><a href="/login">Sign in</a></nav></header>
<main><h1>Shared Reading Lists</h1><p>Create reading lists, add books and share them read-only.</p>${LEAK ? '<p data-x="' + process.env.V0_SECRET_CANARY + '">x</p>' : ''}</main>
<footer><small>Bake-off gate dry run</small></footer></body></html>`;
http.createServer(async (req, res) => {
  if (req.url === '/healthz') { const r = await db.query('select count(*)::int as n from users'); res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ status: 'ok', env: process.env.APP_ENV, users: r.rows[0].n })); }
  if (req.url === '/') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(page()); }
  res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('not found');
}).listen(Number(process.env.PORT || 8080), '0.0.0.0');
