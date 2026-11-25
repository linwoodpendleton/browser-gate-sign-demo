# 协议约定(PROTOCOL)

> 仅用于研究 / 教学。生产请自行实现,勿照抄。

## 角色

| 组件 | 职责 |
| --- | --- |
| `frontend/qlvm_source.js` | 浏览器环境门禁 → 返回「门禁后的当天 key」。真浏览器=真 key,脚本=被污染的错 key。 |
| `frontend/qlcipher.js` | 用 WebCrypto 对请求做 HMAC-SHA256,组装签名头。 |
| `frontend/build.mjs` | (可选/示意)把源模板编成每日轮换的字节码 VM。 |
| `backend` (Rust) | 只验签:`HMAC(当天真key, body\|t\|n\|v) == X-Ql-S ?` |

## 请求头

| 头 | 含义 |
| --- | --- |
| `X-Ql-T` | 毫秒时间戳。后端用 ±5 分钟窗防重放。 |
| `X-Ql-N` | 一次性 nonce。后端去重(demo 进程内 / 生产 Redis SETNX+TTL)。 |
| `X-Ql-V` | 日期 `YYYYMMDD`,即 key 版本。生产只接受 今天/昨天(UTC)。 |
| `X-Ql-S` | 签名,HMAC-SHA256 的 hex。 |

## 签名消息(拼接顺序,前后端必须逐字节一致)

```
message = <body 原文字节> + "|" + t + "|" + n + "|" + v
key     = __qlKey().k            // 门禁后的当天 key
sig     = hex( HMAC_SHA256(key, message) )
```

`body` 必须是实际发送的请求体字节,前后端不得有任何再序列化差异(空格、字段顺序都要一致)。

## 验签流程(后端)

1. 四个头齐全?否 → 拒。
2. 时间戳在 ±5min 内?否 → 拒。
3. nonce 未见过?否(重放)→ 拒。
4. 该日期有 key?否 → 拒。
5. 重算 HMAC,恒定时间比较 == `X-Ql-S`?否 → 拒。
6. 全过 → 放行业务。

## 为什么脚本签不出有效签名

环境门禁(`envMask`)在真浏览器里返回全 0 mask,`key ^ 0 = 真 key`;在 node/jsdom/无头/被 hook 的环境里,某些检查失败 → mask ≠ 0 → `key ^ mask = 错 key`。错 key 算出的 HMAC 永远对不上后端用真 key 算的期望值。curl 之类根本不跑 JS,连签名都产生不了。

**后端全程不需要知道任何环境信息**——这是该设计的核心优点:服务端无状态、逻辑极简、没有「环境判断规则」可被抄走或绕过。

## 生产与 demo 的差异(自行补齐)

- key:demo 写死;生产每天随机 32 字节,定时任务写 Redis,并注入当天前端字节码。
- 混淆:demo 明文直跑;生产整份过 `js-confuser-vm`(`randomizeOpcodes` 每日洗牌操作码)。
- nonce / 日期 / 鉴权 / 限流 / CORS:demo 全部简化,生产必须加固。
- env 检测清单与污染算法:demo 用的是一套**与任何生产实现不同的示意版**(xorshift 扩散 + 一组示例检测点),
  只传达思路;**远不足以**防住现代 stealth 无头浏览器。生产请自行设计检测项与污染算法并保密,勿照抄。
