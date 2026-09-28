// PLANTED (negative test): wrong echo length -> the owner-approved oracle must report a failure (FAIL:ORACLE).
import http from "node:http";
http.createServer((q, s) => {
  const u = new URL(q.url, "http://x"); const j = (c, b) => { s.writeHead(c, { "content-type": "application/json" }); s.end(JSON.stringify(b)); };
  if (u.pathname === "/health") return j(200, { status: "ok", service: "trust-path-probe" });
  if (u.pathname === "/api/echo") { const t = u.searchParams.get("text"); if (!t || t.length > 64) return j(400, { error: "invalid_text" }); return j(200, { echo: t, length: t.length + 1 }); }
  j(404, { error: "not_found" });
}).listen(Number(process.env.PORT || 8080), "0.0.0.0");
