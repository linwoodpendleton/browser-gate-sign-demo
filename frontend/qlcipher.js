// ─────────────────────────────────────────────────────────────────────────────
// qlcipher.js —— 用浏览器原生 WebCrypto 对请求做 HMAC-SHA256 签名(DEMO 版)
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ 仅用于研究 / 教学。生产请自行实现,勿照抄。
//
// 配合 qlvm_source.js 使用:
//   1. 向 __qlKey() 要「当天(经环境门禁后的)key」和日期版本 v
//   2. 用这把 key 对 (body + "|t|n|v") 做 HMAC-SHA256 —— 和后端完全一致的拼接顺序
//   3. 把签名和元数据放进请求头,随请求发给后端
//
// 后端只验:HMAC(当天真key, body|t|n|v) === X-Ql-S ?  对则放行,错则拒。
// 脚本环境拿到的是被污染的错 key,算出来的签名永远对不上 -> 被拒。
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 为一次请求生成签名头。
 * @param {string} bodyStr  —— 请求体原文(JSON 字符串),与实际发送的 body 字节必须一致。
 * @returns {Promise<{headers: object, body: string}>}
 */
async function qlSign(bodyStr) {
  if (typeof window.__qlKey !== "function") {
    throw new Error("__qlKey 未就绪:请先加载 qlvm_source.js");
  }

  const { v, k } = window.__qlKey();      // k: 门禁后的 key(真浏览器=真 key)
  const t = Date.now().toString();        // 毫秒时间戳(后端用 ±5min 防重放窗)
  const n = randomNonce();                // 一次性 nonce(后端 SetNX 去重)

  // 签名消息:body 在前,再跟 "|t|n|v" —— 顺序必须和后端逐字节一致。
  const msg = bodyStr + "|" + t + "|" + n + "|" + v;

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(k),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(msg));
  const sigHex = [...new Uint8Array(sigBuf)].map((b) => b.toString(16).padStart(2, "0")).join("");

  return {
    body: bodyStr,
    headers: {
      "Content-Type": "application/json",
      "X-Ql-T": t,   // 时间戳
      "X-Ql-N": n,   // nonce
      "X-Ql-V": v,   // key 版本(日期)
      "X-Ql-S": sigHex, // 签名
    },
  };
}

function randomNonce() {
  if (crypto.randomUUID) return crypto.randomUUID().replace(/-/g, "");
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// 便捷封装:带签名地 POST 一个 JSON 对象。
async function qlFetch(url, obj) {
  const bodyStr = JSON.stringify(obj);
  const { headers, body } = await qlSign(bodyStr);
  return fetch(url, { method: "POST", headers, body });
}

if (typeof window !== "undefined") {
  window.qlSign = qlSign;
  window.qlFetch = qlFetch;
}
