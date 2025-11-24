// api/webhook-protector.js

// ========= RATE LIMIT ===========
// 3 request / 60s / key  -> block 24h (memory)
const rateUserMap = new Map(); // theo user_id
const rateIpMap   = new Map(); // theo IP

function checkRateLimit(map, identifier) {
  const now = Date.now();
  const key = identifier || "unknown";

  let entry = map.get(key);
  if (!entry) {
    entry = {
      count: 0,
      windowStart: now,
      blockUntil: 0,
    };
  }

  // đang bị block 24h
  if (entry.blockUntil && entry.blockUntil > now) {
    map.set(key, entry);
    return { allowed: false, reason: "blocked", blockedUntil: entry.blockUntil };
  }

  // qua 60s thì reset window
  if (now - entry.windowStart > 60_000) {
    entry.count = 0;
    entry.windowStart = now;
  }

  entry.count += 1;

  if (entry.count > 3) {
    entry.blockUntil = now + 24 * 60 * 60 * 1000; // 24h
    map.set(key, entry);
    return { allowed: false, reason: "rate_exceeded", blockedUntil: entry.blockUntil };
  }

  map.set(key, entry);
  return { allowed: true };
}

// ========== MAIN HANDLER ==========
export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // Lua đôi khi gửi body dạng string → parse lại
  let body = req.body;
  if (!body || typeof body === "string") {
    try {
      body = JSON.parse(body || "{}");
    } catch (e) {
      body = {};
    }
  }

  const { public_embeds, top_embeds, user_id } = body || {};

  // Lấy IP
  const ip =
    req.headers["x-real-ip"] ||
    req.headers["x-forwarded-for"] ||
    req.socket?.remoteAddress ||
    "unknown";

  // ===== RATE LIMIT THEO USER_ID =====
  if (user_id) {
    const rlUser = checkRateLimit(rateUserMap, `user:${user_id}`);
    if (!rlUser.allowed) {
      return res.status(429).json({
        ok: false,
        error: "Rate limited (user)",
        reason: rlUser.reason,
        blocked_until: rlUser.blockedUntil,
      });
    }
  }

  // ===== RATE LIMIT THEO IP =====
  if (ip) {
    const rlIp = checkRateLimit(rateIpMap, `ip:${ip}`);
    if (!rlIp.allowed) {
      return res.status(429).json({
        ok: false,
        error: "Rate limited (ip)",
        reason: rlIp.reason,
        blocked_until: rlIp.blockedUntil,
      });
    }
  }

  async function postToDiscord(url, embeds) {
    if (!url || !Array.isArray(embeds) || embeds.length === 0) return;

    try {
      await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: "",                    // KHÔNG cho text
          embeds,                         // embed từ script gửi
          allowed_mentions: { parse: [] } // KHÔNG ping được ai
        }),
      });
    } catch (err) {
      console.error("Error sending to Discord:", err);
    }
  }

  // 1) PUBLIC
  await postToDiscord(process.env.PUBLIC_WEBHOOK, public_embeds);

  // 2) TOP HIT (nếu có dữ liệu)
  await postToDiscord(process.env.TOP_HIT_WEBHOOK, top_embeds);

  return res.status(200).json({ ok: true });
}
