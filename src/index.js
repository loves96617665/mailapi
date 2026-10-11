import PostalMime from "postal-mime";
import UI from "./ui.html";

const RESERVED = new Set(["admin", "root", "postmaster", "abuse", "webmaster", "hostmaster", "noreply", "no-reply", "support", "security", "mail", "api", "www"]);
const NAME_RE = /^[a-z0-9][a-z0-9._-]{2,31}$/;
const MAX_BODY = 200_000;

// ---------- helpers ----------
const json = (data, status = 200) =>
  new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...CORS },
  });
const err = (msg, status = 400) => json({ ok: false, error: msg }, status);
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
  "access-control-allow-headers": "authorization,content-type,x-api-key",
};
const now = () => Date.now();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const randHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const randName = () => {
  const a = "abcdefghijkmnpqrstuvwxyz23456789";
  const r = crypto.getRandomValues(new Uint8Array(10));
  return [...r].map((x) => a[x % a.length]).join("");
};

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const salt = new Uint8Array(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, key, 256);
  return hex(bits);
}
function safeEq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export function extractCode(subject = "", text = "", html = "") {
  const plain = (text || html.replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ")).replace(/&nbsp;/g, " ");
  const hay = `${subject}\n${plain}`;
  const kw = "(?:code|otp|pin|passcode|verification|verify|security|驗證碼|验证码|驗證|验证|校驗碼|校验码|確認碼|确认码|動態碼|动态码|認證碼|认证码)";
  // 1) keyword followed by a code
  let m = hay.match(new RegExp(kw + "[^\\n\\dA-Za-z]{0,40}?(?:is|為|为|:|：)?\\s*([A-Z0-9]{4,8}|\\d{3}[- ]\\d{3})\\b", "i"));
  if (m && /\d/.test(m[1])) return m[1].replace(/[- ]/g, "");
  // 2) code followed by keyword ("123456 is your code")
  m = hay.match(new RegExp("\\b(\\d{4,8}|\\d{3}[- ]\\d{3})\\b[^\\n]{0,30}" + kw, "i"));
  if (m) return m[1].replace(/[- ]/g, "");
  // 3) standalone 6-digit number
  m = hay.match(/(?<![\d#])(\d{6})(?!\d)/);
  if (m) return m[1];
  // 4) standalone 4-8 digit near keyword anywhere in same line
  for (const line of hay.split(/\n/)) {
    if (new RegExp(kw, "i").test(line)) {
      const d = line.match(/(?<!\d)(\d{4,8})(?!\d)/);
      if (d) return d[1];
    }
  }
  return null;
}

async function readJson(req) {
  try { return await req.json(); } catch { return {}; }
}

async function auth(req, env) {
  const h = req.headers.get("authorization") || "";
  const key = (h.startsWith("Bearer ") ? h.slice(7) : req.headers.get("x-api-key") || new URL(req.url).searchParams.get("key") || "").trim();
  if (!key) return null;
  return await env.DB.prepare("SELECT id, username, is_admin, created_at FROM users WHERE api_key = ? AND disabled = 0").bind(key).first();
}

async function ownMailbox(env, user, address) {
  if (!address) return null;
  return await env.DB.prepare("SELECT * FROM mailboxes WHERE address = ? AND user_id = ?").bind(address.toLowerCase(), user.id).first();
}

async function getSettings(env) {
  const { results } = await env.DB.prepare("SELECT key, value FROM settings").all();
  const o = Object.fromEntries(results.map((r) => [r.key, r.value]));
  return {
    allow_register: (o.allow_register ?? env.ALLOW_REGISTER ?? "true") === "true",
    invite_code: o.invite_code ?? env.INVITE_CODE ?? "",
  };
}

// ---------- API ----------
async function api(req, env, url) {
  const p = url.pathname.replace(/\/+$/, "");
  const M = req.method;
  const domain = env.MAIL_DOMAIN;

  if (p === "/api/register" && M === "POST") {
    const cfg = await getSettings(env);
    if (!cfg.allow_register) return err("registration closed", 403);
    const b = await readJson(req);
    if (cfg.invite_code && b.invite !== cfg.invite_code) return err("invalid invite code", 403);
    const username = String(b.username || "").toLowerCase().trim();
    const password = String(b.password || "");
    if (!NAME_RE.test(username)) return err("username must be 3-32 chars: a-z 0-9 . _ -");
    if (RESERVED.has(username)) return err("username reserved");
    if (password.length < 8) return err("password must be at least 8 characters");
    const address = `${username}@${domain}`;
    const exists = await env.DB.prepare("SELECT 1 FROM users WHERE username = ? UNION SELECT 1 FROM mailboxes WHERE address = ?").bind(username, address).first();
    if (exists) return err("username taken", 409);
    const salt = randHex(16);
    const api_key = "mk_" + randHex(24);
    const pass_hash = await hashPassword(password, salt);
    const r = await env.DB.prepare("INSERT INTO users (username, pass_hash, salt, api_key, created_at) VALUES (?,?,?,?,?)").bind(username, pass_hash, salt, api_key, now()).run();
    await env.DB.prepare("INSERT INTO mailboxes (user_id, address, created_at) VALUES (?,?,?)").bind(r.meta.last_row_id, address, now()).run();
    return json({ ok: true, username, api_key, address }, 201);
  }

  if (p === "/api/login" && M === "POST") {
    const b = await readJson(req);
    const u = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(String(b.username || "").toLowerCase().trim()).first();
    if (!u) return err("invalid credentials", 401);
    const h = await hashPassword(String(b.password || ""), u.salt);
    if (!safeEq(h, u.pass_hash)) return err("invalid credentials", 401);
    if (u.disabled) return err("account disabled", 403);
    return json({ ok: true, username: u.username, api_key: u.api_key });
  }

  const user = await auth(req, env);
  if (!user) return err("missing or invalid API key", 401);

  if (p === "/api/me" && M === "GET") {
    const { results } = await env.DB.prepare("SELECT address, created_at FROM mailboxes WHERE user_id = ? ORDER BY id").bind(user.id).all();
    return json({ ok: true, user: user.username, is_admin: !!user.is_admin, mailboxes: results });
  }

  if (p === "/api/key/rotate" && M === "POST") {
    const api_key = "mk_" + randHex(24);
    await env.DB.prepare("UPDATE users SET api_key = ? WHERE id = ?").bind(api_key, user.id).run();
    return json({ ok: true, api_key });
  }

  if (p === "/api/password" && M === "POST") {
    const b = await readJson(req);
    if (String(b.new_password || "").length < 8) return err("password must be at least 8 characters");
    const salt = randHex(16);
    await env.DB.prepare("UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?").bind(await hashPassword(b.new_password, salt), salt, user.id).run();
    return json({ ok: true });
  }

  if (p === "/api/mailboxes" && M === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT m.address, m.created_at, (SELECT COUNT(*) FROM messages WHERE mailbox_id = m.id) AS count FROM mailboxes m WHERE user_id = ? ORDER BY m.id"
    ).bind(user.id).all();
    return json({ ok: true, mailboxes: results });
  }

  if (p === "/api/mailboxes" && M === "POST") {
    const b = await readJson(req);
    const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM mailboxes WHERE user_id = ?").bind(user.id).first();
    if (c.n >= Number(env.MAX_MAILBOXES || 20)) return err("mailbox limit reached", 403);
    let name = b.name ? String(b.name).toLowerCase().trim() : `${user.username}.${randName().slice(0, 6)}`;
    if (!NAME_RE.test(name)) return err("name must be 3-32 chars: a-z 0-9 . _ -");
    if (RESERVED.has(name)) return err("name reserved");
    // names that equal another user's username are reserved for that user
    const other = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(name).first();
    if (other && other.id !== user.id) return err("address taken", 409);
    const address = `${name}@${domain}`;
    try {
      await env.DB.prepare("INSERT INTO mailboxes (user_id, address, created_at) VALUES (?,?,?)").bind(user.id, address, now()).run();
    } catch {
      return err("address taken", 409);
    }
    return json({ ok: true, address }, 201);
  }

  let m = p.match(/^\/api\/mailboxes\/([^/]+)$/);
  if (m && M === "DELETE") {
    const mb = await ownMailbox(env, user, decodeURIComponent(m[1]));
    if (!mb) return err("mailbox not found", 404);
    await env.DB.batch([
      env.DB.prepare("DELETE FROM messages WHERE mailbox_id = ?").bind(mb.id),
      env.DB.prepare("DELETE FROM mailboxes WHERE id = ?").bind(mb.id),
    ]);
    return json({ ok: true });
  }

  if (p === "/api/messages" && M === "GET") {
    const address = url.searchParams.get("address");
    const limit = Math.min(Number(url.searchParams.get("limit") || 20), 100);
    const since = Number(url.searchParams.get("since") || 0);
    let q, binds;
    if (address) {
      const mb = await ownMailbox(env, user, address);
      if (!mb) return err("mailbox not found", 404);
      q = "SELECT id, address, from_addr, subject, code, received_at FROM messages WHERE mailbox_id = ? AND received_at > ? ORDER BY received_at DESC LIMIT ?";
      binds = [mb.id, since, limit];
    } else {
      q = "SELECT g.id, g.address, g.from_addr, g.subject, g.code, g.received_at FROM messages g JOIN mailboxes b ON g.mailbox_id = b.id WHERE b.user_id = ? AND g.received_at > ? ORDER BY g.received_at DESC LIMIT ?";
      binds = [user.id, since, limit];
    }
    const { results } = await env.DB.prepare(q).bind(...binds).all();
    return json({ ok: true, messages: results });
  }

  m = p.match(/^\/api\/messages\/(\d+)$/);
  if (m) {
    const row = await env.DB.prepare(
      "SELECT g.* FROM messages g JOIN mailboxes b ON g.mailbox_id = b.id WHERE g.id = ? AND b.user_id = ?"
    ).bind(Number(m[1]), user.id).first();
    if (!row) return err("message not found", 404);
    if (M === "GET") { delete row.mailbox_id; return json({ ok: true, message: row }); }
    if (M === "DELETE") {
      await env.DB.prepare("DELETE FROM messages WHERE id = ?").bind(row.id).run();
      return json({ ok: true });
    }
  }

  if (p === "/api/code" && M === "GET") {
    const address = url.searchParams.get("address");
    const mb = await ownMailbox(env, user, address);
    if (!mb) return err("mailbox not found", 404);
    const since = Number(url.searchParams.get("since") || 0);
    const from = (url.searchParams.get("from") || "").toLowerCase();
    const wait = Math.min(Number(url.searchParams.get("wait") || 0), 25);
    const deadline = now() + wait * 1000;
    do {
      const row = await env.DB.prepare(
        "SELECT id, from_addr, subject, code, received_at FROM messages WHERE mailbox_id = ? AND received_at > ? AND code IS NOT NULL AND (? = '' OR lower(from_addr) LIKE '%' || ? || '%') ORDER BY received_at DESC LIMIT 1"
      ).bind(mb.id, since, from, from).first();
      if (row) return json({ ok: true, ...row });
      if (now() >= deadline) break;
      await new Promise((r) => setTimeout(r, 2000));
    } while (true);
    return json({ ok: false, error: "no code yet" }, 404);
  }

  if (p.startsWith("/api/admin/")) {
    if (!user.is_admin) return err("admin only", 403);
    return admin(req, env, url, p, M, user);
  }

  return err("not found", 404);
}

async function admin(req, env, url, p, M, me) {
  if (p === "/api/admin/stats" && M === "GET") {
    const r = await env.DB.prepare(
      "SELECT (SELECT COUNT(*) FROM users) AS users, (SELECT COUNT(*) FROM mailboxes) AS mailboxes, (SELECT COUNT(*) FROM messages) AS messages, (SELECT COUNT(*) FROM messages WHERE received_at > ?) AS messages_24h"
    ).bind(now() - 86400_000).first();
    return json({ ok: true, ...r, settings: await getSettings(env) });
  }
  if (p === "/api/admin/settings" && M === "POST") {
    const b = await readJson(req);
    const st = [];
    if (b.allow_register !== undefined) st.push(env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('allow_register', ?)").bind(b.allow_register ? "true" : "false"));
    if (b.invite_code !== undefined) st.push(env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('invite_code', ?)").bind(String(b.invite_code).trim()));
    if (st.length) await env.DB.batch(st);
    return json({ ok: true, settings: await getSettings(env) });
  }
  if (p === "/api/admin/users" && M === "GET") {
    const q = (url.searchParams.get("q") || "").toLowerCase();
    const { results } = await env.DB.prepare(
      `SELECT u.username, u.is_admin, u.disabled, u.created_at,
        (SELECT COUNT(*) FROM mailboxes WHERE user_id = u.id) AS mailboxes,
        (SELECT COUNT(*) FROM messages g JOIN mailboxes b ON g.mailbox_id = b.id WHERE b.user_id = u.id) AS messages,
        (SELECT MAX(g.received_at) FROM messages g JOIN mailboxes b ON g.mailbox_id = b.id WHERE b.user_id = u.id) AS last_mail
       FROM users u WHERE (? = '' OR u.username LIKE '%' || ? || '%') ORDER BY u.id DESC LIMIT 500`
    ).bind(q, q).all();
    return json({ ok: true, users: results });
  }
  const m = p.match(/^\/api\/admin\/users\/([^/]+)(?:\/(disable|enable|password|mailboxes))?$/);
  if (m) {
    const target = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(decodeURIComponent(m[1]).toLowerCase()).first();
    if (!target) return err("user not found", 404);
    const action = m[2];
    if (target.id === me.id && (action === "disable" || M === "DELETE")) return err("cannot disable or delete yourself");
    if (action === "mailboxes" && M === "GET") {
      const { results } = await env.DB.prepare("SELECT address, created_at, (SELECT COUNT(*) FROM messages WHERE mailbox_id = m.id) AS count FROM mailboxes m WHERE user_id = ?").bind(target.id).all();
      return json({ ok: true, mailboxes: results });
    }
    if (action === "disable" || action === "enable") {
      await env.DB.prepare("UPDATE users SET disabled = ? WHERE id = ?").bind(action === "disable" ? 1 : 0, target.id).run();
      return json({ ok: true });
    }
    if (action === "password" && M === "POST") {
      const b = await readJson(req);
      if (String(b.new_password || "").length < 8) return err("password must be at least 8 characters");
      const salt = randHex(16);
      await env.DB.prepare("UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?").bind(await hashPassword(b.new_password, salt), salt, target.id).run();
      return json({ ok: true });
    }
    if (!action && M === "DELETE") {
      await env.DB.batch([
        env.DB.prepare("DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = ?)").bind(target.id),
        env.DB.prepare("DELETE FROM mailboxes WHERE user_id = ?").bind(target.id),
        env.DB.prepare("DELETE FROM users WHERE id = ?").bind(target.id),
      ]);
      return json({ ok: true });
    }
  }
  return err("not found", 404);
}

// ---------- docs page ----------
function docs(env, origin) {
  const d = env.MAIL_DOMAIN;
  return `<!doctype html><html lang="zh-HK"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${d} Mail API</title><style>body{font:15px/1.6 system-ui,sans-serif;max-width:820px;margin:40px auto;padding:0 16px;color:#222}code,pre{background:#f4f4f5;border-radius:6px}pre{padding:12px;overflow:auto}code{padding:1px 5px}h2{margin-top:32px}</style>
<h1>📬 ${d} Mail API</h1>
<p>多用戶收信系統：註冊即得 <code>用戶名@${d}</code>，可加開子信箱，自動抽取驗證碼。認證：<code>Authorization: Bearer &lt;api_key&gt;</code></p>
<h2>註冊 / 登入</h2>
<pre>curl -X POST ${origin}/api/register -H 'content-type: application/json' \\
  -d '{"username":"alice","password":"secret123"}'
# → {"api_key":"mk_...","address":"alice@${d}"}

curl -X POST ${origin}/api/login -H 'content-type: application/json' \\
  -d '{"username":"alice","password":"secret123"}'</pre>
<h2>信箱</h2>
<pre>GET    /api/me
GET    /api/mailboxes
POST   /api/mailboxes          {"name":"shop1"}   # 唔填 name 就隨機
DELETE /api/mailboxes/{address}</pre>
<h2>郵件</h2>
<pre>GET    /api/messages?address=alice@${d}&amp;limit=20&amp;since=&lt;ms&gt;
GET    /api/messages/{id}
DELETE /api/messages/{id}</pre>
<h2>驗證碼</h2>
<pre># 最新驗證碼；wait=秒數 會長輪詢等新信（最多 25 秒）
GET /api/code?address=alice@${d}&amp;since=&lt;ms&gt;&amp;from=github&amp;wait=25</pre>
<h2>帳戶</h2>
<pre>POST /api/key/rotate
POST /api/password   {"new_password":"..."}</pre>
<p>郵件保留 ${env.RETENTION_DAYS} 日。</p></html>`;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    if (url.pathname.startsWith("/api/")) {
      try { return await api(req, env, url); }
      catch (e) { return err("server error: " + e.message, 500); }
    }
    if (url.pathname === "/")
      return new Response(UI.replaceAll("__DOMAIN__", env.MAIL_DOMAIN), {
        headers: { "content-type": "text/html; charset=utf-8", "x-frame-options": "DENY", "referrer-policy": "no-referrer" },
      });
    if (url.pathname === "/docs")
      return new Response(docs(env, url.origin), { headers: { "content-type": "text/html; charset=utf-8" } });
    return err("not found", 404);
  },

  async email(message, env) {
    const to = message.to.toLowerCase();
    const mb = await env.DB.prepare("SELECT m.id FROM mailboxes m JOIN users u ON m.user_id = u.id WHERE m.address = ? AND u.disabled = 0").bind(to).first();
    if (!mb) { message.setReject("Unknown recipient"); return; }
    const raw = await new Response(message.raw).arrayBuffer();
    const parsed = await PostalMime.parse(raw);
    const subject = (parsed.subject || "").slice(0, 1000);
    const text = (parsed.text || "").slice(0, MAX_BODY);
    const html = (parsed.html || "").slice(0, MAX_BODY);
    const from = parsed.from?.address ? `${parsed.from.name ? parsed.from.name + " " : ""}<${parsed.from.address}>` : message.from;
    const code = extractCode(subject, text, html);
    await env.DB.prepare(
      "INSERT INTO messages (mailbox_id, address, from_addr, subject, text, html, code, received_at) VALUES (?,?,?,?,?,?,?,?)"
    ).bind(mb.id, to, from, subject, text, html, code, now()).run();
  },

  async scheduled(event, env) {
    const cutoff = now() - Number(env.RETENTION_DAYS || 7) * 86400_000;
    await env.DB.prepare("DELETE FROM messages WHERE received_at < ?").bind(cutoff).run();
  },
};
