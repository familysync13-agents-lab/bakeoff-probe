// T-F1 skeleton (the Builder implements the contract here). Node 24, no dependencies.
import http from "node:http";
const port = Number(process.env.PORT || 8080);
http.createServer((req, res) => {
  res.writeHead(501, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not_implemented" }));
}).listen(port, "0.0.0.0");
