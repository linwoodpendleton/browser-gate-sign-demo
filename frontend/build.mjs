// ─────────────────────────────────────────────────────────────────────────────
// build.mjs —— 「每日字节码 VM」生成器(DEMO 版 / 仅示意)
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ 仅用于研究 / 教学。生产请自行实现,勿照抄。
//
// 这一步在本 demo 里是**可选的**:demo.html 直接加载明文 qlvm_source.js 就能跑通。
// 本文件只演示生产中「如何把源模板编成每日轮换的字节码」这一思路:
//
//   每天:
//     1) 生成随机 32 字节 K_day
//     2) 把 K_day / 日期注入 qlvm_source.js 的占位符
//     3) 整份过 js-confuser-vm,randomizeOpcodes 使**每日操作码映射都不同** ->
//        就算有人为今天写好了字节码反汇编器,明天也得重做
//     4) stdout 打印 { date, keyB64, file } —— 供上层脚本:
//          · 把 keyB64 写进后端(demo 里就是 backend 的 key 表 / 生产里是 Redis)
//          · 把 qlVM.<date>.js 发布到 CDN
//
// 注意:js-confuser-vm 是**公开的开源库**,它的解释器结构/操作码语义本来就是公开的。
// 本方案真正依赖的不是「VM 保密」,而是:
//     (a) 操作码每日随机 -> 抬高「每天」逆向成本
//     (b) env 门禁把脚本的 key 污染掉 -> 脚本签名天然无效
// 所以把 VM 这层开源不构成额外泄露;真正的 know-how 在 qlvm_source.js 的 env 逻辑里。
//
// 用法:  node build.mjs [--date YYYYMMDD] [--out DIR]
// 依赖:  npm i js-confuser-vm   (本 demo 未把它列进 package.json 的硬依赖,按需安装)
// ─────────────────────────────────────────────────────────────────────────────

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dir = path.dirname(fileURLToPath(import.meta.url));

function arg(name, def) {
  const i = process.argv.indexOf("--" + name);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : def;
}
function utcDate() {
  const d = new Date();
  return "" + d.getUTCFullYear() + String(d.getUTCMonth() + 1).padStart(2, "0") + String(d.getUTCDate()).padStart(2, "0");
}

const date = arg("date", utcDate());
const outDir = arg("out", path.join(__dir, "dist"));

// 生产会用 crypto.randomBytes(32);demo 为可复现用固定种子派生(仅示意)。
const key = crypto.randomBytes(32);

// 源模板:这里用占位符版本的 qlvm_source.js。若你把本 demo 的 qlvm_source.js 改成
// 带 __KEYBYTES__ / __DATE__ 占位符,这段才能真正注入;当前 demo 版是明文直跑版。
const tplPath = path.join(__dir, "qlvm_source.js");
let src = fs.readFileSync(tplPath, "utf8");
src = src
  .replaceAll("__KEYBYTES__", Array.from(key).join(","))
  .replaceAll("__DATE__", date);

let code = src;
try {
  // 可选:装了 js-confuser-vm 才会真正混淆成字节码。
  const { default: JsConfuserVM } = await import("js-confuser-vm");
  const r = await JsConfuserVM.obfuscate(src, {
    target: "browser",
    randomizeOpcodes: true,  // 每次构建操作码随机 -> 每日字节码不同
    shuffleOpcodes: true,
    encodeBytecode: true,
    concealConstants: true,  // 藏内嵌 key 常量
    stringConcealing: true,  // 藏 "webdriver" / "[native code]" 等检测字符串
    dispatcher: true,
    controlFlowFlattening: false, // 字节码解释器里开它太慢,关掉
    minify: false,
  });
  code = r.code;
  console.error("[build] js-confuser-vm 已混淆");
} catch (e) {
  console.error("[build] 未安装 js-confuser-vm,输出未混淆源码(demo 可接受):", e.message);
}

fs.mkdirSync(outDir, { recursive: true });
const file = path.join(outDir, `qlVM.${date}.js`);
fs.writeFileSync(file, code);
process.stdout.write(JSON.stringify({ date, keyB64: key.toString("base64"), file, size: code.length }) + "\n");
