// server.js —— 挑战码 -> 密码（Node + 内置 OpenSSL SM4）
// 本地: node server.js  → http://localhost:8080
// 云端: 监听 process.env.PORT
const http = require('http');
const crypto = require('crypto');

const AB = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const KEY = Buffer.from('6211662F5BC67801554A554A554A554A', 'hex');

function b58(buf) {
  let n = 0n;
  for (const b of buf) n = n * 256n + BigInt(b);
  let s = '';
  while (n > 0n) { s = AB[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = '1' + s; else break; }
  return s;
}

function calc(challenge, decrypt) {
  const md = crypto.createHash('md5').update(challenge, 'binary').digest();
  const c = decrypt
    ? crypto.createDecipheriv('sm4-ecb', KEY, null)
    : crypto.createCipheriv('sm4-ecb', KEY, null);
  c.setAutoPadding(false);
  const out = Buffer.concat([c.update(md), c.final()]);
  const e = b58(out);
  return { md5: md.toString('hex'), sm4: out.toString('hex'), b58: e, pwd: e.slice(0, 8) };
}

const PAGE = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>挑战码 → 密码</title>
<style>
body{font-family:-apple-system,system-ui,sans-serif;background:#111;color:#eee;margin:0;padding:20px}
h1{font-size:20px;margin:0 0 16px}
input{width:100%;box-sizing:border-box;font-size:22px;padding:14px;border-radius:10px;border:1px solid #444;background:#1c1c1c;color:#fff;letter-spacing:2px}
button{width:100%;margin-top:12px;font-size:20px;padding:14px;border-radius:10px;border:0;background:#2d7ef7;color:#fff;font-weight:600}
.card{background:#1a1a1a;border:1px solid #333;border-radius:12px;padding:16px;margin-top:16px}
.pwd{font-size:34px;letter-spacing:6px;color:#4ade80;font-weight:700;text-align:center;padding:8px 0}
.k{color:#888;font-size:13px}.v{font-size:13px;word-break:break-all;color:#bbb}
.err{color:#f87171}
</style></head><body>
<h1>挑战码 → 密码</h1>
<input id="c" placeholder="输入 8 位挑战码" autocomplete="off" autocapitalize="off" spellcheck="false">
<button onclick="go()">计算</button>
<div id="out"></div>
<script>
async function go(){
  const c=document.getElementById('c').value.trim();
  const out=document.getElementById('out');
  if(!c){out.innerHTML='<div class="card err">请输入挑战码</div>';return;}
  out.innerHTML='<div class="card">计算中…</div>';
  try{
    const r=await fetch('/api?c='+encodeURIComponent(c));
    const j=await r.json();
    if(j.error){out.innerHTML='<div class="card err">'+j.error+'</div>';return;}
    out.innerHTML='<div class="card"><div class="k">密码（先试这个）</div><div class="pwd">'+j.pwd+'</div>'+
      '<div class="k" style="margin-top:10px">备用（解密版）</div><div style="font-size:22px;letter-spacing:4px;color:#fbbf24;text-align:center;padding:6px 0">'+j.pwdDec+'</div></div>'+
      '<div class="card"><div class="k">MD5</div><div class="v">'+j.md5+'</div>'+
      '<div class="k" style="margin-top:8px">SM4</div><div class="v">'+j.sm4+'</div>'+
      '<div class="k" style="margin-top:8px">Base58</div><div class="v">'+j.b58+'</div></div>';
  }catch(e){out.innerHTML='<div class="card err">请求失败: '+e+'</div>';}
}
document.getElementById('c').addEventListener('keydown',e=>{if(e.key==='Enter')go();});
</script></body></html>`;

const srv = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/api') {
    const c = (u.searchParams.get('c') || '').trim();
    if (!c) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: 'empty' })); }
    try {
      const a = calc(c, false), b = calc(c, true);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ pwd: a.pwd, pwdDec: b.pwd, md5: a.md5, sm4: a.sm4, b58: a.b58 }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: String(e) }));
    }
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(PAGE);
});

const PORT = process.env.PORT || 8080;
srv.listen(PORT, '0.0.0.0', () => console.log('listening on ' + PORT));
