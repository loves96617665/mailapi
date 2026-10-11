import PostalMime from "postal-mime";
import { DurableObject } from "cloudflare:workers";
import UI from "./ui.html";

const RESERVED = new Set(["admin", "root", "postmaster", "abuse", "webmaster", "hostmaster", "noreply", "no-reply", "support", "security", "mail", "api", "www"]);
const NAME_RE = /^[a-z0-9][a-z0-9._-]{2,31}$/;
const DOMAIN_RE = /^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const EMAIL_RE = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;
const MAX_BODY = 200_000;
const MAX_ATT = 10 * 1024 * 1024;
const MAX_ATT_COUNT = 10;
const LOCK_FAILS = 5;
const LOCK_MS = 15 * 60_000;

// ---------- helpers ----------
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,PATCH,PUT,DELETE,OPTIONS",
  "access-control-allow-headers": "authorization,content-type,x-api-key",
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data, null, 2), { status, headers: { "content-type": "application/json; charset=utf-8", ...CORS } });
const err = (msg, status = 400, extra = {}) => json({ ok: false, error: msg, ...extra }, status);
const now = () => Date.now();
const day = (t = now()) => new Date(t).toISOString().slice(0, 10);
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const randHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const randName = () => {
  const a = "abcdefghijkmnpqrstuvwxyz23456789";
  return [...crypto.getRandomValues(new Uint8Array(10))].map((x) => a[x % a.length]).join("");
};
const enc = (s) => new TextEncoder().encode(s);

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", enc(password), "PBKDF2", false, ["deriveBits"]);
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
async function hmacHex(secret, data, hash = "SHA-256") {
  const k = await crypto.subtle.importKey("raw", typeof secret === "string" ? enc(secret) : secret, { name: "HMAC", hash }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, typeof data === "string" ? enc(data) : data));
}

// ---------- TOTP (RFC 6238, SHA1, 6 digits, 30s) ----------
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function b32encode(bytes) {
  let bits = 0, val = 0, out = "";
  for (const b of bytes) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
function b32decode(s) {
  s = s.replace(/=+$/, "").replace(/\s/g, "").toUpperCase();
  let bits = 0, val = 0; const out = [];
  for (const c of s) { const i = B32.indexOf(c); if (i < 0) continue; val = (val << 5) | i; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  return new Uint8Array(out);
}
async function totpAt(secret, counter) {
  const msg = new ArrayBuffer(8); const dv = new DataView(msg);
  dv.setUint32(0, Math.floor(counter / 2 ** 32)); dv.setUint32(4, counter >>> 0);
  const k = await crypto.subtle.importKey("raw", b32decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", k, msg));
  const o = h[19] & 15;
  const n = (((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1e6;
  return String(n).padStart(6, "0");
}
async function totpCheck(secret, code) {
  code = String(code || "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(code)) return false;
  const c = Math.floor(now() / 30000);
  for (const d of [-1, 0, 1]) if (safeEq(await totpAt(secret, c + d), code)) return true;
  return false;
}

export function extractCode(subject = "", text = "", html = "") {
  const plain = (text || html.replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ")).replace(/&nbsp;/g, " ");
  const hay = `${subject}\n${plain}`;
  const kw = "(?:code|otp|pin|passcode|verification|verify|security|驗證碼|验证码|驗證|验证|校驗碼|校验码|確認碼|确认码|動態碼|动态码|認證碼|认证码)";
  let m = hay.match(new RegExp(kw + "[^\\n\\dA-Za-z]{0,40}?(?:is|為|为|:|：)?\\s*([A-Z0-9]{4,8}|\\d{3}[- ]\\d{3})\\b", "i"));
  if (m && /\d/.test(m[1])) return m[1].replace(/[- ]/g, "");
  m = hay.match(new RegExp("\\b(\\d{4,8}|\\d{3}[- ]\\d{3})\\b[^\\n]{0,30}" + kw, "i"));
  if (m) return m[1].replace(/[- ]/g, "");
  m = hay.match(/(?<![\d#])(\d{6})(?!\d)/);
  if (m) return m[1];
  for (const line of hay.split(/\n/)) {
    if (new RegExp(kw, "i").test(line)) {
      const d = line.match(/(?<!\d)(\d{4,8})(?!\d)/);
      if (d) return d[1];
    }
  }
  return null;
}

async function readJson(req) { try { return await req.json(); } catch { return {}; } }
const ipOf = (req) => req?.headers?.get("cf-connecting-ip") || "";

async function audit(env, actor, action, target = "", detail = "", ip = "") {
  try {
    await env.DB.prepare("INSERT INTO audit (actor, action, target, detail, ip, created_at) VALUES (?,?,?,?,?,?)")
      .bind(actor || "", action, String(target || ""), typeof detail === "string" ? detail : JSON.stringify(detail), ip, now()).run();
  } catch {}
}
function bump(env, col) {
  return env.DB.prepare(`INSERT INTO daily_stats (day, ${col}) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET ${col} = ${col} + 1`).bind(day()).run().catch(() => {});
}

async function auth(req, env) {
  const h = req.headers.get("authorization") || "";
  const key = (h.startsWith("Bearer ") ? h.slice(7) : req.headers.get("x-api-key") || new URL(req.url).searchParams.get("key") || "").trim();
  if (!key) return null;
  return await env.DB.prepare("SELECT * FROM users WHERE api_key = ? AND disabled = 0").bind(key).first();
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
    allow_send: (o.allow_send ?? "false") === "true",
    send_limit: Number(o.send_limit ?? 20),
    send_ready: !!env.RESEND_API_KEY,
  };
}
async function getDomains(env, all = false) {
  const { results } = await env.DB.prepare(`SELECT name, enabled, created_at FROM domains ${all ? "" : "WHERE enabled = 1"} ORDER BY created_at, name`).all();
  if (!results.length && env.MAIL_DOMAIN) return [{ name: env.MAIL_DOMAIN, enabled: 1, created_at: 0 }];
  return results;
}
async function pickDomain(env, d) {
  const list = (await getDomains(env)).map((x) => x.name);
  if (!d) return list.includes(env.MAIL_DOMAIN) ? env.MAIL_DOMAIN : list[0];
  d = String(d).toLowerCase().trim();
  return list.includes(d) ? d : null;
}

// delete messages (and their attachments + FTS rows) matching a WHERE clause on messages
async function deleteMessages(env, where, binds) {
  let total = 0;
  for (let i = 0; i < 50; i++) {
    const { results } = await env.DB.prepare(`SELECT id FROM messages WHERE ${where} LIMIT 500`).bind(...binds).all();
    if (!results.length) break;
    const ids = results.map((r) => r.id);
    const ph = ids.map(() => "?").join(",");
    const att = await env.DB.prepare(`SELECT r2_key FROM attachments WHERE message_id IN (${ph})`).bind(...ids).all();
    if (att.results.length && env.R2) {
      const keys = att.results.map((a) => a.r2_key);
      for (let j = 0; j < keys.length; j += 1000) await env.R2.delete(keys.slice(j, j + 1000));
    }
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM attachments WHERE message_id IN (${ph})`).bind(...ids),
      env.DB.prepare(`DELETE FROM messages_fts WHERE rowid IN (${ph})`).bind(...ids),
      env.DB.prepare(`DELETE FROM messages WHERE id IN (${ph})`).bind(...ids),
    ]);
    total += ids.length;
    if (ids.length < 500) break;
  }
  return total;
}

function ruleMatch(rule, ctx) {
  const pat = String(rule.pattern || "");
  const hay = rule.field === "from" ? ctx.from : rule.field === "subject" ? ctx.subject : `${ctx.from}\n${ctx.subject}\n${ctx.text}`;
  if (pat.length > 2 && pat.startsWith("/") && pat.endsWith("/")) {
    try { return new RegExp(pat.slice(1, -1), "i").test(hay); } catch { return false; }
  }
  return hay.toLowerCase().includes(pat.toLowerCase());
}

const maskToken = (t) => (t ? t.slice(0, 6) + "…" + t.slice(-4) : "");

async function sendTelegram(token, chat, text) {
  const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ chat_id: chat, text, parse_mode: "HTML", disable_web_page_preview: true }),
  });
  const j = await r.json().catch(() => ({}));
  if (!j.ok) throw new Error(j.description || "telegram error " + r.status);
}
const escHtml = (s) => String(s || "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

async function sendWebhook(url, secret, payload) {
  const body = JSON.stringify(payload);
  const ts = String(Math.floor(now() / 1000));
  const sig = await hmacHex(secret || "", `${ts}.${body}`);
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": "cf-mail-webhook/2", "x-mail-timestamp": ts, "x-mail-signature": "sha256=" + sig, "x-mail-event": payload.event },
    body,
  });
  if (!r.ok) throw new Error("webhook HTTP " + r.status);
}

async function notifyHub(env, userId, payload) {
  if (!env.HUB) return;
  const stub = env.HUB.get(env.HUB.idFromName("u" + userId));
  await stub.fetch("https://hub/notify", { method: "POST", body: JSON.stringify(payload) });
}

function ftsQuery(q) {
  return q.split(/\s+/).filter(Boolean).map((t) => '"' + t.replace(/"/g, '""') + '"').join(" ");
}

// ---------- API ----------
async function api(req, env, url, ctx) {
  const p = url.pathname.replace(/\/+$/, "");
  const M = req.method;
  const ip = ipOf(req);

  if (p === "/api/domains" && M === "GET") {
    const cfg = await getSettings(env);
    return json({ ok: true, domains: (await getDomains(env)).map((d) => d.name), default: await pickDomain(env), allow_register: cfg.allow_register, need_invite: !!cfg.invite_code });
  }

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
    const domain = await pickDomain(env, b.domain);
    if (!domain) return err("unknown domain");
    const address = `${username}@${domain}`;
    const exists = await env.DB.prepare("SELECT 1 FROM users WHERE username = ? UNION SELECT 1 FROM mailboxes WHERE address = ?").bind(username, address).first();
    if (exists) return err("username taken", 409);
    const salt = randHex(16);
    const api_key = "mk_" + randHex(24);
    const r = await env.DB.prepare("INSERT INTO users (username, pass_hash, salt, api_key, created_at) VALUES (?,?,?,?,?)").bind(username, await hashPassword(password, salt), salt, api_key, now()).run();
    await env.DB.prepare("INSERT INTO mailboxes (user_id, address, created_at) VALUES (?,?,?)").bind(r.meta.last_row_id, address, now()).run();
    ctx.waitUntil(bump(env, "registered"));
    ctx.waitUntil(audit(env, username, "register", address, "", ip));
    return json({ ok: true, username, api_key, address }, 201);
  }

  if (p === "/api/login" && M === "POST") {
    const b = await readJson(req);
    const uname = String(b.username || "").toLowerCase().trim();
    const u = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(uname).first();
    if (!u) return err("invalid credentials", 401);
    if (u.lock_until > now()) return err("too many failed attempts, try again later", 429, { retry_after: Math.ceil((u.lock_until - now()) / 1000) });
    const h = await hashPassword(String(b.password || ""), u.salt);
    let fail = !safeEq(h, u.pass_hash);
    if (!fail && u.totp_on) {
      if (!b.otp) return err("2FA code required", 401, { need_otp: true });
      if (!(await totpCheck(u.totp_secret, b.otp))) fail = true;
    }
    if (fail) {
      const n = u.fail_count + 1;
      const lock = n >= LOCK_FAILS ? now() + LOCK_MS : 0;
      await env.DB.prepare("UPDATE users SET fail_count = ?, lock_until = ? WHERE id = ?").bind(lock ? 0 : n, lock, u.id).run();
      ctx.waitUntil(audit(env, uname, lock ? "login_locked" : "login_fail", uname, "", ip));
      return err(u.totp_on && b.otp ? "invalid credentials or 2FA code" : "invalid credentials", 401, u.totp_on && b.otp ? { need_otp: true } : {});
    }
    if (u.disabled) return err("account disabled", 403);
    if (u.fail_count || u.lock_until) await env.DB.prepare("UPDATE users SET fail_count = 0, lock_until = 0 WHERE id = ?").bind(u.id).run();
    if (u.is_admin) ctx.waitUntil(audit(env, uname, "admin_login", uname, "", ip));
    return json({ ok: true, username: u.username, api_key: u.api_key });
  }

  if (p === "/api/ws") {
    const user = await auth(req, env);
    if (!user) return err("missing or invalid API key", 401);
    if (req.headers.get("upgrade") !== "websocket") return err("expected websocket", 426);
    const stub = env.HUB.get(env.HUB.idFromName("u" + user.id));
    return stub.fetch("https://hub/ws", req);
  }

  const user = await auth(req, env);
  if (!user) return err("missing or invalid API key", 401);

  if (p === "/api/me" && M === "GET") {
    const { results } = await env.DB.prepare("SELECT address, created_at, expires_at FROM mailboxes WHERE user_id = ? ORDER BY id").bind(user.id).all();
    const cfg = await getSettings(env);
    return json({
      ok: true, user: user.username, is_admin: !!user.is_admin, totp_on: !!user.totp_on,
      can_send: !!(cfg.allow_send && cfg.send_ready && (user.can_send || user.is_admin)),
      domains: (await getDomains(env)).map((d) => d.name), mailboxes: results,
    });
  }

  if (p === "/api/key/rotate" && M === "POST") {
    const api_key = "mk_" + randHex(24);
    await env.DB.prepare("UPDATE users SET api_key = ? WHERE id = ?").bind(api_key, user.id).run();
    ctx.waitUntil(audit(env, user.username, "key_rotate", user.username, "", ip));
    return json({ ok: true, api_key });
  }

  if (p === "/api/password" && M === "POST") {
    const b = await readJson(req);
    if (String(b.new_password || "").length < 8) return err("password must be at least 8 characters");
    const salt = randHex(16);
    await env.DB.prepare("UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?").bind(await hashPassword(b.new_password, salt), salt, user.id).run();
    ctx.waitUntil(audit(env, user.username, "password_change", user.username, "", ip));
    return json({ ok: true });
  }

  // ----- 2FA -----
  if (p === "/api/2fa/setup" && M === "POST") {
    if (user.totp_on) return err("2FA already enabled");
    const secret = b32encode(crypto.getRandomValues(new Uint8Array(20)));
    await env.DB.prepare("UPDATE users SET totp_secret = ? WHERE id = ?").bind(secret, user.id).run();
    const issuer = encodeURIComponent(url.hostname);
    return json({ ok: true, secret, otpauth: `otpauth://totp/${issuer}:${encodeURIComponent(user.username)}?secret=${secret}&issuer=${issuer}&digits=6&period=30` });
  }
  if (p === "/api/2fa/enable" && M === "POST") {
    const b = await readJson(req);
    if (!user.totp_secret) return err("call /api/2fa/setup first");
    if (!(await totpCheck(user.totp_secret, b.otp))) return err("invalid 2FA code");
    await env.DB.prepare("UPDATE users SET totp_on = 1 WHERE id = ?").bind(user.id).run();
    ctx.waitUntil(audit(env, user.username, "2fa_enable", user.username, "", ip));
    return json({ ok: true });
  }
  if (p === "/api/2fa/disable" && M === "POST") {
    const b = await readJson(req);
    if (!user.totp_on) return json({ ok: true });
    if (!(await totpCheck(user.totp_secret, b.otp))) return err("invalid 2FA code");
    await env.DB.prepare("UPDATE users SET totp_on = 0, totp_secret = NULL WHERE id = ?").bind(user.id).run();
    ctx.waitUntil(audit(env, user.username, "2fa_disable", user.username, "", ip));
    return json({ ok: true });
  }

  // ----- notifications (webhook / telegram) -----
  if (p === "/api/settings" && M === "GET") {
    return json({ ok: true, webhook_url: user.webhook_url || "", webhook_secret: user.webhook_secret || "", tg_chat: user.tg_chat || "", tg_token: maskToken(user.tg_token), tg_set: !!user.tg_token, totp_on: !!user.totp_on });
  }
  if (p === "/api/settings" && M === "POST") {
    const b = await readJson(req);
    const sets = [], binds = [];
    if (b.webhook_url !== undefined) {
      const w = String(b.webhook_url || "").trim();
      if (w && !/^https:\/\/[^\s]+$/i.test(w)) return err("webhook_url must start with https://");
      sets.push("webhook_url = ?"); binds.push(w || null);
      if (w && !user.webhook_secret) { sets.push("webhook_secret = ?"); binds.push("whsec_" + randHex(20)); }
    }
    if (b.tg_token !== undefined) {
      const tk = String(b.tg_token || "").trim();
      if (tk && !/^\d+:[A-Za-z0-9_-]{20,}$/.test(tk)) return err("invalid Telegram bot token");
      sets.push("tg_token = ?"); binds.push(tk || null);
    }
    if (b.tg_chat !== undefined) {
      const c = String(b.tg_chat || "").trim();
      if (c && !/^-?\d+$|^@[A-Za-z0-9_]{4,}$/.test(c)) return err("invalid Telegram chat id");
      sets.push("tg_chat = ?"); binds.push(c || null);
    }
    if (sets.length) await env.DB.prepare(`UPDATE users SET ${sets.join(", ")} WHERE id = ?`).bind(...binds, user.id).run();
    const u = await env.DB.prepare("SELECT webhook_url, webhook_secret, tg_chat, tg_token FROM users WHERE id = ?").bind(user.id).first();
    return json({ ok: true, webhook_url: u.webhook_url || "", webhook_secret: u.webhook_secret || "", tg_chat: u.tg_chat || "", tg_token: maskToken(u.tg_token), tg_set: !!u.tg_token });
  }
  if (p === "/api/webhook/rotate" && M === "POST") {
    const s = "whsec_" + randHex(20);
    await env.DB.prepare("UPDATE users SET webhook_secret = ? WHERE id = ?").bind(s, user.id).run();
    return json({ ok: true, webhook_secret: s });
  }
  if (p === "/api/webhook/test" && M === "POST") {
    if (!user.webhook_url) return err("no webhook_url set");
    try {
      await sendWebhook(user.webhook_url, user.webhook_secret, { event: "test", user: user.username, sent_at: now() });
      return json({ ok: true });
    } catch (e) { return err(e.message, 502); }
  }
  if (p === "/api/telegram/test" && M === "POST") {
    if (!user.tg_token || !user.tg_chat) return err("set tg_token and tg_chat first");
    try { await sendTelegram(user.tg_token, user.tg_chat, `✅ <b>${escHtml(url.hostname)}</b> Telegram 通知已連接 / connected`); return json({ ok: true }); }
    catch (e) { return err(e.message, 502); }
  }

  // ----- rules (forward / block / allow) -----
  if (p === "/api/rules" && M === "GET") {
    const { results } = await env.DB.prepare("SELECT r.id, r.kind, r.field, r.pattern, r.target, r.created_at, m.address FROM rules r LEFT JOIN mailboxes m ON r.mailbox_id = m.id WHERE r.user_id = ? ORDER BY r.id").bind(user.id).all();
    return json({ ok: true, rules: results });
  }
  if (p === "/api/rules" && M === "POST") {
    const b = await readJson(req);
    const kind = String(b.kind || ""), field = String(b.field || "any"), pattern = String(b.pattern || "").trim();
    if (!["forward", "block", "allow"].includes(kind)) return err("kind must be forward | block | allow");
    if (!["from", "subject", "any"].includes(field)) return err("field must be from | subject | any");
    if (!pattern && kind !== "forward") return err("pattern required");
    if (pattern.length > 200) return err("pattern too long");
    let target = null;
    if (kind === "forward") {
      target = String(b.target || "").trim().toLowerCase();
      if (!EMAIL_RE.test(target)) return err("target must be an email address");
    }
    let mbId = null;
    if (b.address) { const mb = await ownMailbox(env, user, b.address); if (!mb) return err("mailbox not found", 404); mbId = mb.id; }
    const c = await env.DB.prepare("SELECT COUNT(*) n FROM rules WHERE user_id = ?").bind(user.id).first();
    if (c.n >= 50) return err("rule limit reached (50)", 403);
    const r = await env.DB.prepare("INSERT INTO rules (user_id, mailbox_id, kind, field, pattern, target, created_at) VALUES (?,?,?,?,?,?,?)").bind(user.id, mbId, kind, field, pattern, target, now()).run();
    return json({ ok: true, id: r.meta.last_row_id }, 201);
  }
  let m = p.match(/^\/api\/rules\/(\d+)$/);
  if (m && M === "DELETE") {
    await env.DB.prepare("DELETE FROM rules WHERE id = ? AND user_id = ?").bind(Number(m[1]), user.id).run();
    return json({ ok: true });
  }

  // ----- mailboxes -----
  if (p === "/api/mailboxes" && M === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT m.address, m.created_at, m.expires_at, (SELECT COUNT(*) FROM messages WHERE mailbox_id = m.id) AS count, (SELECT COUNT(*) FROM messages WHERE mailbox_id = m.id AND is_read = 0) AS unread FROM mailboxes m WHERE user_id = ? ORDER BY m.id"
    ).bind(user.id).all();
    return json({ ok: true, mailboxes: results });
  }
  if (p === "/api/mailboxes" && M === "POST") {
    const b = await readJson(req);
    const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM mailboxes WHERE user_id = ?").bind(user.id).first();
    if (c.n >= Number(env.MAX_MAILBOXES || 20)) return err("mailbox limit reached", 403);
    const name = b.name ? String(b.name).toLowerCase().trim() : `${user.username}.${randName().slice(0, 6)}`;
    if (!NAME_RE.test(name)) return err("name must be 3-32 chars: a-z 0-9 . _ -");
    if (RESERVED.has(name)) return err("name reserved");
    const other = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(name).first();
    if (other && other.id !== user.id) return err("address taken", 409);
    const domain = await pickDomain(env, b.domain);
    if (!domain) return err("unknown domain");
    let expires = null;
    if (b.ttl_hours) {
      const hrs = Number(b.ttl_hours);
      if (!(hrs >= 1 && hrs <= 720)) return err("ttl_hours must be 1-720");
      expires = now() + hrs * 3600_000;
    }
    const address = `${name}@${domain}`;
    try {
      await env.DB.prepare("INSERT INTO mailboxes (user_id, address, created_at, expires_at) VALUES (?,?,?,?)").bind(user.id, address, now(), expires).run();
    } catch { return err("address taken", 409); }
    return json({ ok: true, address, expires_at: expires }, 201);
  }
  m = p.match(/^\/api\/mailboxes\/([^/]+)$/);
  if (m && M === "DELETE") {
    const mb = await ownMailbox(env, user, decodeURIComponent(m[1]));
    if (!mb) return err("mailbox not found", 404);
    await deleteMessages(env, "mailbox_id = ?", [mb.id]);
    await env.DB.batch([
      env.DB.prepare("DELETE FROM rules WHERE mailbox_id = ?").bind(mb.id),
      env.DB.prepare("DELETE FROM mailboxes WHERE id = ?").bind(mb.id),
    ]);
    return json({ ok: true });
  }

  // ----- messages -----
  if (p === "/api/messages" && M === "GET") {
    const sp = url.searchParams;
    const address = sp.get("address");
    const limit = Math.min(Number(sp.get("limit") || 20), 100);
    const offset = Math.max(Number(sp.get("offset") || 0), 0);
    const since = Number(sp.get("since") || 0);
    const where = ["b.user_id = ?", "g.received_at > ?"], binds = [user.id, since];
    if (address) {
      const mb = await ownMailbox(env, user, address);
      if (!mb) return err("mailbox not found", 404);
      where.push("g.mailbox_id = ?"); binds.push(mb.id);
    }
    if (sp.get("starred") === "1") where.push("g.starred = 1");
    if (sp.get("unread") === "1") where.push("g.is_read = 0");
    if (sp.get("has_code") === "1") where.push("g.code IS NOT NULL");
    if (sp.get("label")) { where.push("(',' || g.labels || ',') LIKE ?"); binds.push(`%,${sp.get("label")},%`); }
    const q = (sp.get("q") || "").trim().slice(0, 100);
    if (q) {
      if ([...q].length >= 3) { where.push("g.id IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)"); binds.push(ftsQuery(q)); }
      else { where.push("(g.subject LIKE ? OR g.from_addr LIKE ? OR g.text LIKE ?)"); binds.push(`%${q}%`, `%${q}%`, `%${q}%`); }
    }
    const { results } = await env.DB.prepare(
      `SELECT g.id, g.address, g.from_addr, g.subject, g.code, g.received_at, g.is_read, g.starred, g.labels, g.att_count
       FROM messages g JOIN mailboxes b ON g.mailbox_id = b.id WHERE ${where.join(" AND ")} ORDER BY g.received_at DESC LIMIT ? OFFSET ?`
    ).bind(...binds, limit, offset).all();
    return json({ ok: true, messages: results });
  }
  if (p === "/api/messages/read-all" && M === "POST") {
    const b = await readJson(req);
    if (b.address) {
      const mb = await ownMailbox(env, user, b.address);
      if (!mb) return err("mailbox not found", 404);
      await env.DB.prepare("UPDATE messages SET is_read = 1 WHERE mailbox_id = ? AND is_read = 0").bind(mb.id).run();
    } else await env.DB.prepare("UPDATE messages SET is_read = 1 WHERE is_read = 0 AND mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = ?)").bind(user.id).run();
    return json({ ok: true });
  }
  if (p === "/api/labels" && M === "GET") {
    const { results } = await env.DB.prepare("SELECT g.labels FROM messages g JOIN mailboxes b ON g.mailbox_id = b.id WHERE b.user_id = ? AND g.labels != ''").bind(user.id).all();
    const set = new Set(); results.forEach((r) => r.labels.split(",").forEach((l) => l && set.add(l)));
    return json({ ok: true, labels: [...set].sort() });
  }
  m = p.match(/^\/api\/messages\/(\d+)$/);
  if (m) {
    const row = await env.DB.prepare("SELECT g.* FROM messages g JOIN mailboxes b ON g.mailbox_id = b.id WHERE g.id = ? AND b.user_id = ?").bind(Number(m[1]), user.id).first();
    if (!row) return err("message not found", 404);
    if (M === "GET") {
      delete row.mailbox_id;
      if (!row.is_read && url.searchParams.get("mark") !== "0") { await env.DB.prepare("UPDATE messages SET is_read = 1 WHERE id = ?").bind(row.id).run(); row.is_read = 1; }
      const { results } = await env.DB.prepare("SELECT id, filename, mime, size FROM attachments WHERE message_id = ?").bind(row.id).all();
      row.attachments = results;
      return json({ ok: true, message: row });
    }
    if (M === "PATCH") {
      const b = await readJson(req);
      const sets = [], binds = [];
      if (b.is_read !== undefined) { sets.push("is_read = ?"); binds.push(b.is_read ? 1 : 0); }
      if (b.starred !== undefined) { sets.push("starred = ?"); binds.push(b.starred ? 1 : 0); }
      if (b.labels !== undefined) {
        const arr = (Array.isArray(b.labels) ? b.labels : String(b.labels).split(","))
          .map((s) => String(s).trim().toLowerCase().replace(/[,\s]+/g, "-").slice(0, 24)).filter(Boolean);
        sets.push("labels = ?"); binds.push([...new Set(arr)].slice(0, 10).join(","));
      }
      if (sets.length) await env.DB.prepare(`UPDATE messages SET ${sets.join(", ")} WHERE id = ?`).bind(...binds, row.id).run();
      const r2 = await env.DB.prepare("SELECT id, is_read, starred, labels FROM messages WHERE id = ?").bind(row.id).first();
      return json({ ok: true, ...r2 });
    }
    if (M === "DELETE") {
      await deleteMessages(env, "id = ?", [row.id]);
      return json({ ok: true });
    }
  }
  m = p.match(/^\/api\/messages\/(\d+)\/raw$/);
  if (m && M === "GET") {
    const row = await env.DB.prepare("SELECT g.* FROM messages g JOIN mailboxes b ON g.mailbox_id = b.id WHERE g.id = ? AND b.user_id = ?").bind(Number(m[1]), user.id).first();
    if (!row) return err("message not found", 404);
    return new Response(row.text || "", { headers: { "content-type": "text/plain; charset=utf-8", ...CORS } });
  }

  m = p.match(/^\/api\/attachments\/(\d+)$/);
  if (m && M === "GET") {
    const a = await env.DB.prepare("SELECT a.* FROM attachments a JOIN messages g ON a.message_id = g.id JOIN mailboxes b ON g.mailbox_id = b.id WHERE a.id = ? AND b.user_id = ?").bind(Number(m[1]), user.id).first();
    if (!a) return err("attachment not found", 404);
    const obj = await env.R2.get(a.r2_key);
    if (!obj) return err("attachment gone", 410);
    const inline = url.searchParams.get("inline") === "1" && /^image\/(png|jpe?g|gif|webp)$/.test(a.mime || "");
    return new Response(obj.body, {
      headers: {
        "content-type": inline ? a.mime : "application/octet-stream",
        "content-disposition": `${inline ? "inline" : "attachment"}; filename*=UTF-8''${encodeURIComponent(a.filename || "file")}`,
        "x-content-type-options": "nosniff", ...CORS,
      },
    });
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

  // ----- sending -----
  if (p === "/api/send" && M === "POST") {
    const cfg = await getSettings(env);
    if (!cfg.send_ready) return err("sending not configured on this server", 503);
    if (!cfg.allow_send) return err("sending disabled by admin", 403);
    if (!user.can_send && !user.is_admin) return err("sending not enabled for this account", 403);
    const b = await readJson(req);
    const mb = await ownMailbox(env, user, b.from);
    if (!mb) return err("from must be one of your mailboxes");
    const to = (Array.isArray(b.to) ? b.to : String(b.to || "").split(",")).map((s) => s.trim()).filter(Boolean);
    if (!to.length || to.length > 5 || !to.every((x) => EMAIL_RE.test(x))) return err("to: 1-5 valid email addresses");
    const subject = String(b.subject || "").slice(0, 300);
    if (!subject) return err("subject required");
    if (!b.text && !b.html) return err("text or html required");
    const used = await env.DB.prepare("SELECT COUNT(*) n FROM sent WHERE user_id = ? AND created_at > ? AND status = 'sent'").bind(user.id, now() - 86400_000).first();
    if (!user.is_admin && used.n >= cfg.send_limit) return err(`daily send limit reached (${cfg.send_limit})`, 429);
    const payload = { from: b.from_name ? `${String(b.from_name).replace(/[<>"]/g, "").slice(0, 60)} <${mb.address}>` : mb.address, to, subject };
    if (b.text) payload.text = String(b.text).slice(0, MAX_BODY);
    if (b.html) payload.html = String(b.html).slice(0, MAX_BODY);
    if (b.reply_to && EMAIL_RE.test(b.reply_to)) payload.reply_to = b.reply_to;
    const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json" }, body: JSON.stringify(payload) });
    const j = await r.json().catch(() => ({}));
    const status = r.ok ? "sent" : "failed";
    await env.DB.prepare("INSERT INTO sent (user_id, from_addr, to_addr, subject, status, created_at) VALUES (?,?,?,?,?,?)").bind(user.id, mb.address, to.join(","), subject, status, now()).run();
    if (!r.ok) return err("send failed: " + (j.message || r.status), 502);
    ctx.waitUntil(bump(env, "sent"));
    return json({ ok: true, id: j.id });
  }
  if (p === "/api/sent" && M === "GET") {
    const { results } = await env.DB.prepare("SELECT id, from_addr, to_addr, subject, status, created_at FROM sent WHERE user_id = ? ORDER BY id DESC LIMIT 100").bind(user.id).all();
    return json({ ok: true, sent: results });
  }

  if (p.startsWith("/api/admin/")) {
    if (!user.is_admin) return err("admin only", 403);
    return admin(req, env, url, p, M, user, ctx, ip);
  }
  return err("not found", 404);
}

async function admin(req, env, url, p, M, me, ctx, ip) {
  const log = (action, target, detail) => ctx.waitUntil(audit(env, me.username, action, target, detail, ip));

  if (p === "/api/admin/stats" && M === "GET") {
    const r = await env.DB.prepare(
      `SELECT (SELECT COUNT(*) FROM users) AS users, (SELECT COUNT(*) FROM mailboxes) AS mailboxes, (SELECT COUNT(*) FROM messages) AS messages,
       (SELECT COUNT(*) FROM messages WHERE received_at > ?1) AS messages_24h,
       (SELECT COUNT(DISTINCT b.user_id) FROM messages g JOIN mailboxes b ON g.mailbox_id = b.id WHERE g.received_at > ?2) AS active_7d,
       (SELECT COUNT(*) FROM attachments) AS attachments, (SELECT COALESCE(SUM(size),0) FROM attachments) AS att_bytes`
    ).bind(now() - 86400_000, now() - 7 * 86400_000).first();
    return json({ ok: true, ...r, settings: await getSettings(env) });
  }
  if (p === "/api/admin/chart" && M === "GET") {
    const days = Math.min(Number(url.searchParams.get("days") || 30), 90);
    const start = day(now() - (days - 1) * 86400_000);
    const { results } = await env.DB.prepare("SELECT day, received, registered, sent FROM daily_stats WHERE day >= ? ORDER BY day").bind(start).all();
    const map = Object.fromEntries(results.map((r) => [r.day, r]));
    const out = [];
    for (let i = days - 1; i >= 0; i--) { const d = day(now() - i * 86400_000); out.push(map[d] || { day: d, received: 0, registered: 0, sent: 0 }); }
    const top = await env.DB.prepare(
      "SELECT u.username, COUNT(*) n FROM messages g JOIN mailboxes b ON g.mailbox_id = b.id JOIN users u ON b.user_id = u.id WHERE g.received_at > ? GROUP BY u.id ORDER BY n DESC LIMIT 10"
    ).bind(now() - 7 * 86400_000).all();
    return json({ ok: true, days: out, top_users_7d: top.results });
  }
  if (p === "/api/admin/settings" && M === "POST") {
    const b = await readJson(req);
    const st = [];
    const put = (k, v) => st.push(env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(k, v));
    if (b.allow_register !== undefined) put("allow_register", b.allow_register ? "true" : "false");
    if (b.invite_code !== undefined) put("invite_code", String(b.invite_code).trim());
    if (b.allow_send !== undefined) put("allow_send", b.allow_send ? "true" : "false");
    if (b.send_limit !== undefined) { const n = Number(b.send_limit); if (!(n >= 0 && n <= 1000)) return err("send_limit 0-1000"); put("send_limit", String(Math.floor(n))); }
    if (st.length) { await env.DB.batch(st); log("settings", "", b); }
    return json({ ok: true, settings: await getSettings(env) });
  }
  if (p === "/api/admin/audit" && M === "GET") {
    const limit = Math.min(Number(url.searchParams.get("limit") || 100), 500);
    const q = (url.searchParams.get("q") || "").toLowerCase();
    const { results } = await env.DB.prepare(
      "SELECT id, actor, action, target, detail, ip, created_at FROM audit WHERE (? = '' OR actor LIKE '%'||?||'%' OR action LIKE '%'||?||'%' OR target LIKE '%'||?||'%') ORDER BY id DESC LIMIT ?"
    ).bind(q, q, q, q, limit).all();
    return json({ ok: true, audit: results });
  }
  // domains
  if (p === "/api/admin/domains" && M === "GET") {
    const { results } = await env.DB.prepare("SELECT d.name, d.enabled, d.created_at, (SELECT COUNT(*) FROM mailboxes WHERE address LIKE '%@' || d.name) AS mailboxes FROM domains d ORDER BY d.created_at, d.name").all();
    return json({ ok: true, domains: results });
  }
  if (p === "/api/admin/domains" && M === "POST") {
    const b = await readJson(req);
    const name = String(b.name || "").toLowerCase().trim();
    if (!DOMAIN_RE.test(name)) return err("invalid domain");
    try { await env.DB.prepare("INSERT INTO domains (name, enabled, created_at) VALUES (?, 1, ?)").bind(name, now()).run(); }
    catch { return err("domain exists", 409); }
    log("domain_add", name);
    return json({ ok: true, name, note: "Enable Email Routing on this zone and add a catch-all rule → Worker cf-mail" }, 201);
  }
  let m = p.match(/^\/api\/admin\/domains\/([^/]+)(?:\/(enable|disable))?$/);
  if (m) {
    const name = decodeURIComponent(m[1]).toLowerCase();
    const d = await env.DB.prepare("SELECT * FROM domains WHERE name = ?").bind(name).first();
    if (!d) return err("domain not found", 404);
    if (m[2] && M === "POST") {
      await env.DB.prepare("UPDATE domains SET enabled = ? WHERE name = ?").bind(m[2] === "enable" ? 1 : 0, name).run();
      log("domain_" + m[2], name);
      return json({ ok: true });
    }
    if (!m[2] && M === "DELETE") {
      const c = await env.DB.prepare("SELECT COUNT(*) n FROM mailboxes WHERE address LIKE ?").bind("%@" + name).first();
      if (c.n) return err(`domain still has ${c.n} mailboxes`, 409);
      await env.DB.prepare("DELETE FROM domains WHERE name = ?").bind(name).run();
      log("domain_delete", name);
      return json({ ok: true });
    }
  }
  // users
  if (p === "/api/admin/users" && M === "GET") {
    const q = (url.searchParams.get("q") || "").toLowerCase();
    const { results } = await env.DB.prepare(
      `SELECT u.username, u.is_admin, u.disabled, u.created_at, u.totp_on, u.can_send, u.lock_until,
        (SELECT COUNT(*) FROM mailboxes WHERE user_id = u.id) AS mailboxes,
        (SELECT COUNT(*) FROM messages g JOIN mailboxes b ON g.mailbox_id = b.id WHERE b.user_id = u.id) AS messages,
        (SELECT MAX(g.received_at) FROM messages g JOIN mailboxes b ON g.mailbox_id = b.id WHERE b.user_id = u.id) AS last_mail
       FROM users u WHERE (? = '' OR u.username LIKE '%' || ? || '%') ORDER BY u.id DESC LIMIT 500`
    ).bind(q, q).all();
    return json({ ok: true, users: results });
  }
  m = p.match(/^\/api\/admin\/users\/([^/]+)(?:\/(disable|enable|password|mailboxes|send|2fa|unlock))?$/);
  if (m) {
    const target = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(decodeURIComponent(m[1]).toLowerCase()).first();
    if (!target) return err("user not found", 404);
    const action = m[2];
    if (target.id === me.id && (action === "disable" || M === "DELETE")) return err("cannot disable or delete yourself");
    if (action === "mailboxes" && M === "GET") {
      const { results } = await env.DB.prepare("SELECT address, created_at, expires_at, (SELECT COUNT(*) FROM messages WHERE mailbox_id = m.id) AS count FROM mailboxes m WHERE user_id = ?").bind(target.id).all();
      return json({ ok: true, mailboxes: results });
    }
    if (action === "disable" || action === "enable") {
      await env.DB.prepare("UPDATE users SET disabled = ? WHERE id = ?").bind(action === "disable" ? 1 : 0, target.id).run();
      log("user_" + action, target.username);
      return json({ ok: true });
    }
    if (action === "unlock" && M === "POST") {
      await env.DB.prepare("UPDATE users SET fail_count = 0, lock_until = 0 WHERE id = ?").bind(target.id).run();
      log("user_unlock", target.username);
      return json({ ok: true });
    }
    if (action === "send" && M === "POST") {
      const b = await readJson(req);
      await env.DB.prepare("UPDATE users SET can_send = ? WHERE id = ?").bind(b.on ? 1 : 0, target.id).run();
      log(b.on ? "user_send_on" : "user_send_off", target.username);
      return json({ ok: true });
    }
    if (action === "2fa" && M === "DELETE") {
      await env.DB.prepare("UPDATE users SET totp_on = 0, totp_secret = NULL WHERE id = ?").bind(target.id).run();
      log("user_2fa_reset", target.username);
      return json({ ok: true });
    }
    if (action === "password" && M === "POST") {
      const b = await readJson(req);
      if (String(b.new_password || "").length < 8) return err("password must be at least 8 characters");
      const salt = randHex(16);
      await env.DB.prepare("UPDATE users SET pass_hash = ?, salt = ?, fail_count = 0, lock_until = 0 WHERE id = ?").bind(await hashPassword(b.new_password, salt), salt, target.id).run();
      log("user_password_reset", target.username);
      return json({ ok: true });
    }
    if (!action && M === "DELETE") {
      await deleteMessages(env, "mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = ?)", [target.id]);
      await env.DB.batch([
        env.DB.prepare("DELETE FROM rules WHERE user_id = ?").bind(target.id),
        env.DB.prepare("DELETE FROM sent WHERE user_id = ?").bind(target.id),
        env.DB.prepare("DELETE FROM mailboxes WHERE user_id = ?").bind(target.id),
        env.DB.prepare("DELETE FROM users WHERE id = ?").bind(target.id),
      ]);
      log("user_delete", target.username);
      return json({ ok: true });
    }
  }
  return err("not found", 404);
}

// ---------- docs page ----------
function docs(env, origin) {
  const d = env.MAIL_DOMAIN;
  return `<!doctype html><html lang="zh-HK"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${d} Mail API</title><style>body{font:15px/1.6 system-ui,sans-serif;max-width:860px;margin:40px auto;padding:0 16px;color:#222}code,pre{background:#f4f4f5;border-radius:6px}pre{padding:12px;overflow:auto}code{padding:1px 5px}h2{margin-top:32px}</style>
<h1>📬 ${d} Mail API</h1>
<p>多用戶收信系統：註冊即得 <code>用戶名@域名</code>，可加開子信箱（可設自動過期），自動抽取驗證碼，附件、Webhook、Telegram、即時推送、轉寄／過濾規則、搜尋、發信。認證：<code>Authorization: Bearer &lt;api_key&gt;</code></p>
<h2>註冊 / 登入</h2>
<pre>GET  /api/domains                       # 可用域名
POST /api/register {"username":"alice","password":"secret123","domain":"${d}"}
POST /api/login    {"username":"alice","password":"secret123","otp":"123456"}   # otp 只喺開咗 2FA 時需要
# 連續錯 5 次會鎖 15 分鐘（429）</pre>
<h2>信箱</h2>
<pre>GET    /api/me
GET    /api/mailboxes
POST   /api/mailboxes   {"name":"shop1","domain":"${d}","ttl_hours":24}   # name 留空隨機；ttl_hours 1-720 到期自動刪除
DELETE /api/mailboxes/{address}</pre>
<h2>郵件</h2>
<pre>GET    /api/messages?address=&amp;limit=20&amp;offset=0&amp;since=&lt;ms&gt;&amp;q=關鍵字&amp;starred=1&amp;unread=1&amp;label=work&amp;has_code=1
GET    /api/messages/{id}            # 會自動標記已讀（?mark=0 唔標記），包含 attachments[]
PATCH  /api/messages/{id}  {"is_read":true,"starred":true,"labels":["work","otp"]}   # 有星標嘅信唔會被定期清理
DELETE /api/messages/{id}
POST   /api/messages/read-all {"address":"..."}
GET    /api/labels
GET    /api/attachments/{id}          # 下載附件（?inline=1 圖片直接顯示）</pre>
<h2>驗證碼</h2>
<pre>GET /api/code?address=alice@${d}&amp;since=&lt;ms&gt;&amp;from=github&amp;wait=25</pre>
<h2>即時推送</h2>
<pre># WebSocket：收到新信即刻推送 {"type":"message", ...}
wss://${new URL(origin).host}/api/ws?key=&lt;api_key&gt;      # 送 "ping" 會回 "pong"</pre>
<h2>Webhook / Telegram</h2>
<pre>GET  /api/settings
POST /api/settings {"webhook_url":"https://example.com/hook","tg_token":"123:ABC...","tg_chat":"123456789"}
POST /api/webhook/test     POST /api/webhook/rotate     POST /api/telegram/test
# Webhook：POST JSON {event:"message.received",id,address,from,subject,code,received_at,preview,attachments}
# 標頭 X-Mail-Timestamp、X-Mail-Signature: sha256=HMAC_SHA256(secret, timestamp + "." + body)</pre>
<h2>規則（轉寄 / 黑名單 / 白名單）</h2>
<pre>GET    /api/rules
POST   /api/rules {"kind":"forward|block|allow","field":"from|subject|any","pattern":"github","target":"me@gmail.com","address":"可選，只套用某信箱"}
DELETE /api/rules/{id}
# pattern 係唔分大小寫子字串；/regex/ 寫法用正則。block 命中即拒收；有 allow 規則時只收命中嘅信。
# forward 目標必須係 Cloudflare Email Routing 已驗證嘅地址。</pre>
<h2>雙重認證（TOTP）</h2>
<pre>POST /api/2fa/setup            # → secret, otpauth URI
POST /api/2fa/enable  {"otp":"123456"}
POST /api/2fa/disable {"otp":"123456"}</pre>
<h2>發信（需管理員開啟）</h2>
<pre>POST /api/send {"from":"alice@${d}","from_name":"Alice","to":["x@example.com"],"subject":"Hi","text":"...","html":"..."}
GET  /api/sent</pre>
<h2>帳戶</h2>
<pre>POST /api/key/rotate
POST /api/password   {"new_password":"..."}</pre>
<p>未加星標嘅郵件保留 ${env.RETENTION_DAYS} 日。</p></html>`;
}

// ---------- realtime hub (one per user) ----------
export class Hub extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }
  async fetch(req) {
    const u = new URL(req.url);
    if (u.pathname === "/ws") {
      const pair = new WebSocketPair();
      this.ctx.acceptWebSocket(pair[1]);
      pair[1].send(JSON.stringify({ type: "hello", t: now() }));
      return new Response(null, { status: 101, webSocket: pair[0] });
    }
    if (u.pathname === "/notify") {
      const msg = await req.text();
      let n = 0;
      for (const ws of this.ctx.getWebSockets()) { try { ws.send(msg); n++; } catch {} }
      return new Response(String(n));
    }
    return new Response("not found", { status: 404 });
  }
  async webSocketMessage() {}
  async webSocketClose(ws, code) { try { ws.close(code, "bye"); } catch {} }
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    if (url.pathname.startsWith("/api/")) {
      try { return await api(req, env, url, ctx); }
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

  async email(message, env, ctx) {
    const to = message.to.toLowerCase();
    const dom = to.split("@")[1] || "";
    const domOk = await env.DB.prepare("SELECT 1 FROM domains WHERE name = ? AND enabled = 1").bind(dom).first();
    if (!domOk && dom !== env.MAIL_DOMAIN) { message.setReject("Domain not accepted"); return; }
    const mb = await env.DB.prepare(
      "SELECT m.id, m.expires_at, u.id AS uid, u.username, u.webhook_url, u.webhook_secret, u.tg_token, u.tg_chat FROM mailboxes m JOIN users u ON m.user_id = u.id WHERE m.address = ? AND u.disabled = 0"
    ).bind(to).first();
    if (!mb || (mb.expires_at && mb.expires_at < now())) { message.setReject("Unknown recipient"); return; }

    const raw = await new Response(message.raw).arrayBuffer();
    const parsed = await PostalMime.parse(raw);
    const subject = (parsed.subject || "").slice(0, 1000);
    const text = (parsed.text || "").slice(0, MAX_BODY);
    const html = (parsed.html || "").slice(0, MAX_BODY);
    const from = parsed.from?.address ? `${parsed.from.name ? parsed.from.name + " " : ""}<${parsed.from.address}>` : message.from;

    // rules
    const { results: rules } = await env.DB.prepare("SELECT * FROM rules WHERE user_id = ? AND (mailbox_id IS NULL OR mailbox_id = ?)").bind(mb.uid, mb.id).all();
    const rc = { from: `${from} ${message.from}`, subject, text: text || html.replace(/<[^>]+>/g, " ") };
    if (rules.some((r) => r.kind === "block" && ruleMatch(r, rc))) { message.setReject("Blocked by recipient"); return; }
    const allows = rules.filter((r) => r.kind === "allow");
    if (allows.length && !allows.some((r) => ruleMatch(r, rc))) { message.setReject("Sender not allowed"); return; }

    const code = extractCode(subject, text, html);
    const atts = (parsed.attachments || []).filter((a) => a.content && (a.content.byteLength ?? a.content.length) <= MAX_ATT).slice(0, MAX_ATT_COUNT);
    const ts = now();
    const ins = await env.DB.prepare(
      "INSERT INTO messages (mailbox_id, address, from_addr, subject, text, html, code, received_at, att_count) VALUES (?,?,?,?,?,?,?,?,?)"
    ).bind(mb.id, to, from, subject, text, html, code, ts, env.R2 ? atts.length : 0).run();
    const id = ins.meta.last_row_id;
    const stmts = [env.DB.prepare("INSERT INTO messages_fts (rowid, subject, from_addr, body) VALUES (?,?,?,?)").bind(id, subject, from, (text || html.replace(/<[^>]+>/g, " ")).slice(0, 20000))];
    const attMeta = [];
    if (env.R2 && atts.length) {
      for (let i = 0; i < atts.length; i++) {
        const a = atts[i];
        const fname = (a.filename || `attachment-${i + 1}`).slice(0, 200);
        const key = `att/${id}/${i}-${fname.replace(/[^\w.-]+/g, "_").slice(0, 80)}`;
        const size = a.content.byteLength ?? a.content.length;
        await env.R2.put(key, a.content, { httpMetadata: { contentType: a.mimeType || "application/octet-stream" } });
        stmts.push(env.DB.prepare("INSERT INTO attachments (message_id, filename, mime, size, r2_key) VALUES (?,?,?,?,?)").bind(id, fname, a.mimeType || "", size, key));
        attMeta.push({ filename: fname, mime: a.mimeType || "", size });
      }
    }
    await env.DB.batch(stmts);
    ctx.waitUntil(bump(env, "received"));

    // forwards
    for (const r of rules.filter((r) => r.kind === "forward" && r.target && (!r.pattern || ruleMatch(r, rc)))) {
      try { await message.forward(r.target); }
      catch (e) { ctx.waitUntil(audit(env, mb.username, "forward_fail", r.target, e.message)); }
    }

    const evt = { event: "message.received", id, address: to, from, subject, code, received_at: ts, preview: (text || "").slice(0, 300), attachments: attMeta };
    ctx.waitUntil(notifyHub(env, mb.uid, { type: "message", ...evt }).catch(() => {}));
    if (mb.webhook_url) ctx.waitUntil(sendWebhook(mb.webhook_url, mb.webhook_secret, evt).catch((e) => audit(env, mb.username, "webhook_fail", mb.webhook_url, e.message)));
    if (mb.tg_token && mb.tg_chat) {
      const msg = `📬 <b>${escHtml(to)}</b>\n<b>${escHtml(from)}</b>\n${escHtml(subject)}` + (code ? `\n\n🔑 <code>${escHtml(code)}</code>` : "") + (attMeta.length ? `\n📎 ${attMeta.length}` : "");
      ctx.waitUntil(sendTelegram(mb.tg_token, mb.tg_chat, msg).catch((e) => audit(env, mb.username, "telegram_fail", "", e.message)));
    }
  },

  async scheduled(event, env, ctx) {
    const cutoff = now() - Number(env.RETENTION_DAYS || 7) * 86400_000;
    await deleteMessages(env, "received_at < ? AND starred = 0", [cutoff]);
    // expired temporary mailboxes
    const { results } = await env.DB.prepare("SELECT id FROM mailboxes WHERE expires_at IS NOT NULL AND expires_at < ? LIMIT 200").bind(now()).all();
    for (const mb of results) {
      await deleteMessages(env, "mailbox_id = ?", [mb.id]);
      await env.DB.batch([env.DB.prepare("DELETE FROM rules WHERE mailbox_id = ?").bind(mb.id), env.DB.prepare("DELETE FROM mailboxes WHERE id = ?").bind(mb.id)]);
    }
    await env.DB.prepare("DELETE FROM audit WHERE created_at < ?").bind(now() - 90 * 86400_000).run();
  },
};
