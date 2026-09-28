// T-F1: trust-path probe service. Node 24, no dependencies.
import http from "node:http";

const port = Number(process.env.PORT || 8080);
const SERVICE = "trust-path-probe";
const MAX_TEXT = 64;

// Never echo the canary back, even if a client supplies it.
const canary = process.env.APP_SECRET_CANARY || "";

function send(res, status, body) {
  let payload = JSON.stringify(body);
  if (canary && payload.includes(canary)) {
    status = 500;
    payload = JSON.stringify({ error: "internal_error" });
  }
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(payload);
}

function handle(req, res) {
  let url;
  try {
    url = new URL(req.url, "http://localhost");
  } catch {
    return send(res, 404, { error: "not_found" });
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    return send(res, 404, { error: "not_found" });
  }

  switch (url.pathname) {
    case "/":
      return send(res, 200, { service: SERVICE, routes: ["/health", "/api/echo?text="] });
    case "/health":
      return send(res, 200, { status: "ok", service: SERVICE });
    case "/api/echo": {
      const text = url.searchParams.get("text");
      const length = text === null ? 0 : [...text].length;
      if (!text || length > MAX_TEXT || (canary && text.includes(canary))) {
        return send(res, 400, { error: "invalid_text" });
      }
      return send(res, 200, { echo: text, length });
    }
    default:
      return send(res, 404, { error: "not_found" });
  }
}

http
  .createServer((req, res) => {
    try {
      handle(req, res);
    } catch {
      if (!res.headersSent) send(res, 500, { error: "internal_error" });
      else res.end();
    }
  })
  .listen(port, "0.0.0.0");
