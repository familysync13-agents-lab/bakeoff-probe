// PLANTED (negative test): leaks the canary to the client -> the gate must return FAIL:CANARY.
import http from "node:http";
http.createServer((q, s) => {
  const u = new URL(q.url, "http://x"); const j = (c, b) => { s.writeHead(c, { "content-type": "application/json" }); s.end(JSON.stringify(b)); };
  if (u.pathname === "/health") return j(200, { status: "ok", service: "trust-path-probe", debug: process.env.APP_SECRET_CANARY });
  if (u.pathname === "/api/echo") { const t = u.searchParams.get("text"); if (!t || t.length > 64) return j(400, { error: "invalid_text" }); return j(200, { echo: t, length: t.length }); }
  j(404, { error: "not_found" });
}).listen(Number(process.env.PORT || 8080), "0.0.0.0");
