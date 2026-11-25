// ─────────────────────────────────────────────────────────────────────────────
// qlvm_source.js —— 浏览器环境门禁 + 每日 key 的「源模板」(DEMO 版)
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ 本文件仅用于研究 / 教学。生产请自行实现,请勿照抄本仓库任何代码。详见根目录 README。
//
// 作用:只对外暴露一个函数
//     window.__qlKey() -> { v: "YYYYMMDD", k: [32 字节] }
//
//   k = 当天 key「经浏览器环境门禁异或(xor)」后的结果:
//     · 真浏览器   -> 环境检查全过 -> mask 全 0 -> k === 真 key      -> 后端验签通过
//     · node/jsdom/curl 等脚本 -> 某些检查失败 -> mask ≠ 0 -> k 被污染 -> 后端验签失败
//
// 关键点:**后端完全不需要知道任何环境信息**。环境门禁整个发生在前端这份代码里 ——
// 脚本环境拿到的是一把「被污染的错 key」,于是它签出来的 HMAC 永远对不上,后端直接拒。
// curl_cffi 之类根本不跑 JS,连 document 都没有,连签名都产生不了。
//
// 为什么 HMAC 不在这里算:在重度混淆的字节码 VM 里跑 SHA-256 每次要好几秒,会卡死主线程。
// 所以本文件只做「轻量 env 检测 + 返回门禁后的 key」,真正的 HMAC-SHA256 交给 qlcipher.js
// 用浏览器原生 WebCrypto(subtle.sign)毫秒级完成。
//
// 生产怎么用这份文件(本 demo 不含这步,仅说明):
//   构建时把「当天随机 32 字节 key」和「当天日期」注入占位符,整份再过 js-confuser-vm 编成
//   **每天不同、操作码每日随机洗牌(randomizeOpcodes)**的字节码。env 逻辑与 key 常量都藏进
//   字节码里,明文不落地。参见 build.mjs。
//
//   DEMO 里为了能直接跑,直接写死了一把演示 key 和演示日期(明文),**不经过混淆**。
//   这在生产中是绝对不可接受的 —— 明文 key + 明文 env 逻辑 = 零防护。
// ─────────────────────────────────────────────────────────────────────────────

(function () {
  // DEMO：写死的演示 key 与日期。生产由 build.mjs 每日注入随机值后编成字节码。
  // 这把 key 必须与后端 backend/src/main.rs 里 demo_keys() 中同一日期的 key 完全一致。
  var K = [
    0x9a, 0x3c, 0x51, 0x08, 0xd7, 0x2e, 0x44, 0xbf,
    0x11, 0x6d, 0xaa, 0x90, 0x3f, 0xe2, 0x7c, 0x05,
    0x88, 0x1b, 0x6e, 0xc4, 0x39, 0x52, 0xa0, 0xfd,
    0x47, 0x93, 0x0c, 0x5a, 0xe8, 0x21, 0x76, 0xbc
  ];
  var V = "20260101"; // 演示日期(key 版本)。生产 = 当天 UTC 日期。

  // ── 浏览器环境门禁 ─────────────────────────────────────────────────────────
  // 真浏览器:全部检查通过 -> mask 全 0。
  // 脚本/无头/被 hook 的环境:对应检查失败 -> 往 mask 里混入与「失败项」相关的噪声,
  // 使 mask ≠ 0,最终把 key 异或污染。
  //
  // ⚠️ 本 demo 的「检测清单」与「污染算法」是**特意挑的一套示意实现,与任何生产实现都不同**。
  // 它只传达一个思路:env 检测失败 -> 确定性地污染 key。真要防住现代无头浏览器
  // (puppeteer-stealth 等),检测项远不止这些、要持续迭代,且污染算法应保密并自行设计。
  // 请勿照抄这里的项目列表或扩散函数。
  function envMask() {
    var m = new Array(32);
    for (var i = 0; i < 32; i++) m[i] = 0;

    // 某项检测失败时调用:把一个 32 位 xorshift 序列(以失败项 code 为种子)扩散进整个 mask。
    // 这与「线性 s*k+b」式扩散不同,仅作示意;生产请换成自己的、且保密的派生方式。
    function taint(code) {
      var h = (code * 0x9e3779b1) >>> 0;
      for (var i = 0; i < 32; i++) {
        h ^= h << 13; h >>>= 0;
        h ^= h >>> 17;
        h ^= h << 5;  h >>>= 0;
        m[i] = (m[i] ^ (h & 0xff)) & 0xff;
      }
    }
    // 判断一个函数是否是浏览器原生实现(未被 JS 重写 / hook)。
    function isNative(fn) {
      try { return /\{\s*\[native code\]\s*\}/.test("" + fn); } catch (e) { return false; }
    }

    // A) 顶层宿主对象(node/curl 根本没有)
    try { if (typeof window === "undefined") taint(0x11); } catch (e) { taint(0x11); }
    try { if (typeof document === "undefined") taint(0x12); } catch (e) { taint(0x12); }
    try { if (typeof navigator === "undefined" || !navigator) taint(0x13); } catch (e) { taint(0x13); }
    try { if (typeof location === "undefined" || !location.href) taint(0x14); } catch (e) { taint(0x14); }

    // B) 自动化 / 无头指纹
    try { if (navigator.webdriver) taint(0x21); } catch (e) { taint(0x21); }
    try { if (!navigator.languages || navigator.languages.length === 0) taint(0x22); } catch (e) { taint(0x22); }
    try { if (!navigator.userAgent) taint(0x23); } catch (e) { taint(0x23); }
    try { if (navigator.msCrypto) taint(0x24); } catch (e) {}

    // C) 原生函数完整性(被重写 / jsdom 垫片的会露馅)——换一组不同的受检函数
    try { if (!isNative(window.fetch)) taint(0x31); } catch (e) { taint(0x31); }
    try { if (!isNative(window.setTimeout)) taint(0x32); } catch (e) { taint(0x32); }
    try { if (!isNative(Array.prototype.map)) taint(0x33); } catch (e) { taint(0x33); }
    try { if (!isNative(JSON.stringify)) taint(0x34); } catch (e) { taint(0x34); }
    try { if (!isNative(document.createElement)) taint(0x35); } catch (e) { taint(0x35); }
    try { if (!isNative(window.matchMedia)) taint(0x36); } catch (e) { taint(0x36); }

    // D) 原型链 / 构造器真实性
    try { if (typeof Navigator === "undefined" || !(navigator instanceof Navigator)) taint(0x41); } catch (e) { taint(0x41); }
    try { if (typeof Window === "undefined" || !(window instanceof Window)) taint(0x42); } catch (e) { taint(0x42); }

    // E) 真浏览器才具备的能力面——换一组不同的能力点
    try { if (typeof WebGLRenderingContext === "undefined") taint(0x51); } catch (e) { taint(0x51); }
    try { if (!window.crypto || !window.crypto.subtle) taint(0x52); } catch (e) { taint(0x52); }
    try { if (typeof Intl === "undefined" || !Intl.DateTimeFormat) taint(0x53); } catch (e) { taint(0x53); }
    try { if (!window.performance || !isNative(window.performance.now)) taint(0x54); } catch (e) { taint(0x54); }
    try { if (!isNative(window.requestAnimationFrame)) taint(0x55); } catch (e) { taint(0x55); }
    try { var cv = document.createElement("canvas"); if (!cv.getContext || !cv.getContext("2d")) taint(0x56); } catch (e) { taint(0x56); }

    return m;
  }

  // 用 mask 异或污染 key:真浏览器 mask=0 -> 原样返回真 key。
  function effKey() {
    var mm = envMask(), k = K.slice();
    for (var i = 0; i < 32; i++) k[i] = (k[i] ^ mm[i]) & 0xff;
    return k;
  }

  // 一次会话内环境不变:只算一次并缓存,后续调用瞬时返回。
  var cached = null;
  var g = typeof window !== "undefined" ? window
        : (typeof globalThis !== "undefined" ? globalThis : this);

  g.__qlKey = function () {
    if (!cached) cached = effKey();
    return { v: V, k: cached.slice() };
  };
})();
