// Cloudflare Pages (advanced mode): one project serves both hostnames.
//   web.lockin-app.online  -> the Lock In web app (static files in this folder)
//   ipa.lockin-app.online  -> the SideStore/AltStore source (always the latest from GitHub)
const SOURCE = 'https://raw.githubusercontent.com/Trohorm/summer-lock-in/main/source.json';
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.hostname.startsWith('ipa.')) {
      const r = await fetch(SOURCE, { cf: { cacheTtl: 60, cacheEverything: true } });
      const text = await r.text();
      if (url.pathname === '/latest' || url.pathname === '/latest.ipa') {
        try { return Response.redirect(JSON.parse(text).apps[0].versions[0].downloadURL, 302); } catch (e) {}
      }
      return new Response(text, { status: r.ok ? 200 : 502, headers: {
        'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=60' } });
    }
    const res = await env.ASSETS.fetch(request);
    if ((res.headers.get('content-type') || '').includes('text/html') || url.pathname.endsWith('sw.js')) {
      const h = new Headers(res.headers); h.set('cache-control', 'no-cache');
      return new Response(res.body, { status: res.status, headers: h });
    }
    return res;
  }
};
