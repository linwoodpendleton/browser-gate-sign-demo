// ─────────────────────────────────────────────────────────────────────────────
// qlvm-backend-demo —— /getQueryList 的「环境门禁验签」后端(Rust / DEMO)
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ 仅用于研究 / 教学。生产请自行实现,勿照抄本仓库任何代码。
//
// 后端只做一件事:验证每个请求带的签名。
//     HMAC_SHA256(当天真 key, body || "|t|n|v") == 请求头 X-Ql-S ?
//   对 -> 放行业务;错/缺 -> 拒。
//
// 后端**完全不关心浏览器环境**:环境门禁全在前端 qlvm_source.js 里完成(脚本会拿到被
// 污染的错 key,于是签名永远对不上)。这正是该方案的要点——服务端逻辑极简且无状态可抄。
//
// 本 demo 与生产的差异(务必自行补齐):
//   · key:demo 用写死的演示 key 表;生产是「每天随机 32 字节」,由定时任务写入 Redis,
//     并与前端当天字节码里的 key 对应。demo 没有 Redis。
//   · nonce 去重:demo 用进程内 HashSet(重启即失效、且不是分布式安全);生产用 Redis SETNX+TTL。
//   · 日期校验:demo 放宽为「key 表里有该日期即可」;生产只接受 今天/昨天(UTC)。
//   · 没有鉴权、限流、CORS 收敛等一切生产必需项。
//
// 请求头约定:
//   X-Ql-T 毫秒时间戳   X-Ql-N 一次性 nonce   X-Ql-V 日期(key 版本)   X-Ql-S 签名 hex
// 签名消息拼接顺序(必须与前端逐字节一致): body 原文字节 ++ "|" ++ t ++ "|" ++ n ++ "|" ++ v
// ─────────────────────────────────────────────────────────────────────────────

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use tower_http::cors::CorsLayer;

type HmacSha256 = Hmac<Sha256>;

const REPLAY_WINDOW_MS: i64 = 5 * 60 * 1000; // ±5 分钟

struct AppState {
    keys: HashMap<String, [u8; 32]>, // date(YYYYMMDD) -> 当天 key
    seen_nonces: Mutex<HashSet<String>>,
}

/// DEMO key 表。必须与前端 qlvm_source.js 里同一日期的 K 完全一致。
/// 生产:改为从 Redis 读 `ql:key:<date>`,由每日定时任务写入随机值。
fn demo_keys() -> HashMap<String, [u8; 32]> {
    let mut m = HashMap::new();
    m.insert(
        "20260101".to_string(),
        [
            0x9a, 0x3c, 0x51, 0x08, 0xd7, 0x2e, 0x44, 0xbf, 0x11, 0x6d, 0xaa, 0x90, 0x3f, 0xe2,
            0x7c, 0x05, 0x88, 0x1b, 0x6e, 0xc4, 0x39, 0x52, 0xa0, 0xfd, 0x47, 0x93, 0x0c, 0x5a,
            0xe8, 0x21, 0x76, 0xbc,
        ],
    );
    m
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

/// 验签核心。返回 Ok(()) 表示通过,Err(原因) 表示拒绝。
fn verify(state: &AppState, headers: &HeaderMap, body: &[u8]) -> Result<(), String> {
    let get = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let t = get("x-ql-t");
    let n = get("x-ql-n");
    let v = get("x-ql-v");
    let sig = get("x-ql-s");

    if t.is_empty() || n.is_empty() || v.is_empty() || sig.is_empty() {
        return Err("缺少签名头".into());
    }

    // 时间窗(防重放)
    let ms: i64 = t.parse().map_err(|_| "时间戳非法".to_string())?;
    let diff = now_ms() - ms;
    if diff > REPLAY_WINDOW_MS || diff < -REPLAY_WINDOW_MS {
        return Err(format!("时间戳越窗 {}ms", diff));
    }

    // nonce 一次性(demo:进程内;生产:Redis SETNX + TTL)
    {
        let mut seen = state.seen_nonces.lock().unwrap();
        if !seen.insert(n.clone()) {
            return Err("nonce 重放".into());
        }
    }

    // 取当天 key(demo:表里有即可;生产:校验只接受今天/昨天 UTC)
    let key = state.keys.get(&v).ok_or_else(|| format!("无当日 key {}", v))?;

    // 计算 HMAC(key, body || "|t|n|v"),与前端拼接顺序逐字节一致
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(body);
    mac.update(format!("|{}|{}|{}", t, n, v).as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // 恒定时间比较
    if !constant_time_eq(expected.as_bytes(), sig.as_bytes()) {
        return Err("签名不匹配".into());
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

async fn get_query_list(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    match verify(&state, &headers, &body) {
        Ok(()) => {
            // 业务:这里只回显。真实接口在此之后才查数据。
            let parsed: serde_json::Value =
                serde_json::from_slice(&body).unwrap_or(json!({}));
            (
                StatusCode::OK,
                Json(json!({
                    "code": 0,
                    "msg": "ok (签名通过)",
                    "echo": parsed,
                })),
            )
        }
        Err(reason) => {
            eprintln!("[qlCrypto] 验签失败: {}", reason);
            (
                StatusCode::OK,
                Json(json!({ "code": -1, "msg": "请求校验失败" })),
            )
        }
    }
}

#[tokio::main]
async fn main() {
    let state = std::sync::Arc::new(AppState {
        keys: demo_keys(),
        seen_nonces: Mutex::new(HashSet::new()),
    });

    let app = Router::new()
        .route("/getQueryList", post(get_query_list))
        .layer(CorsLayer::permissive()) // demo 放开跨域;生产请收敛
        .with_state(state);

    let addr = "127.0.0.1:8080";
    println!("qlvm-backend-demo 监听 http://{addr}  (POST /getQueryList)");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
