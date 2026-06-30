'use strict';

let response;

self.addEventListener("install", () => {
    self.skipWaiting();
});

self.addEventListener("activate", (e) => {
    e.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', async (e) => {
	console.log(e.request.url);
	let url = new URL(e.request.url);
	let size = 40;
	let body = "A".repeat(Number(size));

	if (e.request.headers.get("range") === "bytes=0-") {
		e.respondWith(new Response(body, {status: 206, headers: {
			"Content-Type": "audio/mp4",
			"Content-Range": `bytes 0-${Number(size) - 1}/10000`
		}}));
	} else if (e.request.headers.get("range") === `bytes=${Number(size)}-`) {
		response = await fetch(e.request);
	} else if (e.request.url.includes("/mock.css")) {
		e.respondWith(response.clone());
	}
});
