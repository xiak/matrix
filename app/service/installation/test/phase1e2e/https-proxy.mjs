// Test-only TLS terminator for the native, disconnected release gate.
// Credentials and request/response bodies are streamed, never recorded.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import http from "node:http";
import https from "node:https";

const [certificate, privateKey] = process.argv.slice(2);
assert.equal(process.argv.length, 4);
const options = { cert: await readFile(certificate), key: await readFile(privateKey), minVersion: "TLSv1.2" };
const upstream = (request) => ({ hostname: "127.0.0.1", port: 8080, method: request.method, path: request.url, headers: request.headers });
const server = https.createServer(options, (request, response) => {
  const outgoing = http.request(upstream(request), (incoming) => {
    response.writeHead(incoming.statusCode, incoming.headers);
    incoming.pipe(response);
  });
  outgoing.on("error", () => { if (!response.headersSent) response.writeHead(502); response.end(); });
  request.on("error", () => outgoing.destroy());
  request.pipe(outgoing);
});
server.on("upgrade", (request, socket, head) => {
  const outgoing = http.request(upstream(request));
  outgoing.on("upgrade", (incoming, peer, upstreamHead) => {
    const headers = incoming.rawHeaders.reduce((lines, entry, index, all) => index % 2 ? lines : `${lines}${entry}: ${all[index + 1]}\r\n`, "");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\n${headers}\r\n`);
    if (upstreamHead.length) socket.write(upstreamHead);
    if (head.length) peer.write(head);
    socket.pipe(peer).pipe(socket);
    socket.on("error", () => peer.destroy());
    peer.on("error", () => socket.destroy());
    socket.on("close", () => peer.destroy());
    peer.on("close", () => socket.destroy());
  });
  outgoing.on("response", (response) => { response.resume(); socket.end(`HTTP/1.1 ${response.statusCode} Rejected\r\nConnection: close\r\n\r\n`); });
  outgoing.on("error", () => socket.destroy());
  outgoing.end();
});
server.on("tlsClientError", () => {});
server.listen(18443, "127.0.0.1", () => process.stdout.write("HTTPS fixture ready\n"));
process.on("SIGTERM", () => { server.close(); server.closeAllConnections(); });
