//! `paddock-server` — thin HTTP front-end over a [`paddock_core::Db`].
//!
//! Built for one purpose: stand up the engine behind an HTTP port so it
//! can be deployed to platforms like Railway / Fly.io / Render / a bare
//! VM and exercised remotely. The protocol is intentionally minimal — a
//! handful of JSON routes — and reads its configuration from environment
//! variables so the same binary works on every `PaaS` without a custom
//! flag spec:
//!
//! | Var                   | Default      | Meaning                                                   |
//! |-----------------------|--------------|-----------------------------------------------------------|
//! | `PORT`                | `8080`       | TCP port to bind on `0.0.0.0`                             |
//! | `DATA_DIR`            | `./data`     | Filesystem path the engine uses for WAL + SSTables        |
//! | `PADDOCK_MASTER_KEY`  | _(unset)_    | Optional 64-char hex string (32 bytes) — enables encryption-at-rest |
//! | `RUST_LOG`            | `info`       | Standard `tracing-subscriber` filter                      |
//!
//! ## API
//!
//! - `GET /health` — liveness probe. Always returns 200 OK.
//! - `PUT /kv/:key` — body is the raw value bytes. Stores `key → value`.
//! - `GET /kv/:key` — returns the value bytes on hit, `404` on miss.
//! - `DELETE /kv/:key` — removes `key` (writes a tombstone).
//! - `GET /scan?start=...&end=...` — returns JSON
//!   `{"records": [{"key": "<b64>", "value": "<b64>"}]}`. Both bounds
//!   are base64-encoded; both are optional.
//! - `POST /flush` — drain pending memtables to SSTables.
//! - `POST /compact` — merge every SSTable into one.
//! - `GET /stats` — JSON snapshot of engine telemetry.
//!
//! Keys and values flow as raw bytes; arbitrary binary data is fine. Keys
//! over 1 KiB and values over 1 MiB are rejected at the HTTP layer to
//! keep the body-buffer bounded on the demo path. Production deployments
//! should add authentication and adjust the limits before exposing this
//! server to the internet.

#![allow(clippy::missing_docs_in_private_items)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use paddock_core::crypto::MasterKey;
use paddock_core::engine::DbConfig;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

#[cfg(target_os = "linux")]
type ProductionVfs = paddock_core::io::LinuxVfs;
#[cfg(not(target_os = "linux"))]
type ProductionVfs = paddock_core::io::vfs::MemVfs;

type Db = paddock_core::Db<ProductionVfs>;

/// Engine + diagnostics shared with every request.
struct AppState {
    db: Db,
    encrypted: bool,
}

const MAX_KEY_LEN: usize = 1024; // 1 KiB
const MAX_VALUE_LEN: usize = 1024 * 1024; // 1 MiB
const REQUEST_TIMEOUT_SECS: u64 = 30;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,paddock_server=debug,tower_http=info".into()),
        )
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);
    let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_owned());

    info!(port, %data_dir, "starting paddock-server");

    let vfs = build_vfs(&data_dir).expect("VFS init");
    let cfg = build_config().expect("config");
    let encrypted = cfg.master_key.is_some();

    let db = Db::open_with(vfs, ".", cfg).expect("db open");
    info!(encrypted, "engine open");

    let state = Arc::new(AppState { db, encrypted });
    let app = Router::new()
        .route("/health", get(health))
        .route("/stats", get(stats))
        .route("/kv/:key", get(get_kv))
        .route("/kv/:key", put(put_kv))
        .route("/kv/:key", delete(delete_kv))
        .route("/scan", get(scan))
        .route("/flush", post(flush))
        .route("/compact", post(compact))
        .layer(RequestBodyLimitLayer::new(MAX_VALUE_LEN + 1024))
        .layer(TimeoutLayer::new(Duration::from_secs(REQUEST_TIMEOUT_SECS)))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind TCP listener");
    info!(?addr, "listening");
    axum::serve(listener, app).await.expect("serve");
}

#[cfg(target_os = "linux")]
fn build_vfs(data_dir: &str) -> Result<ProductionVfs, std::io::Error> {
    paddock_core::io::LinuxVfs::create_at(data_dir).map_err(|e| match e {
        paddock_core::Error::Io(io) => io,
        other => std::io::Error::other(other.to_string()),
    })
}

#[cfg(not(target_os = "linux"))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "shape mirrors the Linux branch so the call site stays uniform"
)]
fn build_vfs(_data_dir: &str) -> std::result::Result<ProductionVfs, std::io::Error> {
    // Non-Linux hosts (developer workstations) get an in-memory VFS. The
    // server still serves the full API; data does not persist across
    // restarts. This keeps `cargo run -p paddock-server` working without
    // forcing Windows/macOS users into WSL.
    tracing::warn!("non-Linux host: using in-memory VFS (data will NOT persist across restarts)");
    Ok(paddock_core::io::vfs::MemVfs::new())
}

fn build_config() -> std::result::Result<DbConfig, String> {
    let mut cfg = DbConfig::default();
    if let Ok(hex) = std::env::var("PADDOCK_MASTER_KEY") {
        let raw = decode_hex_32(&hex)
            .ok_or_else(|| "PADDOCK_MASTER_KEY must be 64 hex chars (32 bytes)".to_owned())?;
        cfg.master_key = Some(MasterKey::from_bytes(raw));
    }
    Ok(cfg)
}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

// ----- route handlers -----

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

#[derive(Serialize)]
struct StatsResponse {
    sstable_count: usize,
    current_seqno: u64,
    encrypted: bool,
}

async fn stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let body = StatsResponse {
        sstable_count: state.db.sstable_count(),
        current_seqno: state.db.current_seqno(),
        encrypted: state.encrypted,
    };
    (StatusCode::OK, axum::Json(body))
}

async fn get_kv(State(state): State<Arc<AppState>>, Path(key): Path<String>) -> impl IntoResponse {
    if key.len() > MAX_KEY_LEN {
        return (StatusCode::BAD_REQUEST, "key too long").into_response();
    }
    match state.db.get(key.as_bytes()) {
        Ok(Some(value)) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            value,
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "not found\n").into_response(),
        Err(e) => engine_err(&e),
    }
}

async fn put_kv(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    if key.len() > MAX_KEY_LEN {
        return (StatusCode::BAD_REQUEST, "key too long").into_response();
    }
    if body.len() > MAX_VALUE_LEN {
        return (StatusCode::PAYLOAD_TOO_LARGE, "value too large").into_response();
    }
    match state.db.put(key.as_bytes(), &body) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => engine_err(&e),
    }
}

async fn delete_kv(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    if key.len() > MAX_KEY_LEN {
        return (StatusCode::BAD_REQUEST, "key too long").into_response();
    }
    match state.db.delete(key.as_bytes()) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => engine_err(&e),
    }
}

#[derive(Deserialize)]
struct ScanQuery {
    start: Option<String>,
    end: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct ScanRecord {
    key: String,
    value: String,
    seqno: u64,
}

#[derive(Serialize)]
struct ScanResponse {
    records: Vec<ScanRecord>,
    truncated: bool,
}

async fn scan(State(state): State<Arc<AppState>>, Query(q): Query<ScanQuery>) -> impl IntoResponse {
    let start_bytes = match q.start.as_deref() {
        Some(b64) => match BASE64.decode(b64) {
            Ok(b) => Some(b),
            Err(_) => return (StatusCode::BAD_REQUEST, "start: invalid base64").into_response(),
        },
        None => None,
    };
    let end_bytes = match q.end.as_deref() {
        Some(b64) => match BASE64.decode(b64) {
            Ok(b) => Some(b),
            Err(_) => return (StatusCode::BAD_REQUEST, "end: invalid base64").into_response(),
        },
        None => None,
    };

    let start_bound = start_bytes
        .as_ref()
        .map_or(std::ops::Bound::Unbounded, |b| {
            std::ops::Bound::Included(b.as_slice())
        });
    let end_bound = end_bytes.as_ref().map_or(std::ops::Bound::Unbounded, |b| {
        std::ops::Bound::Excluded(b.as_slice())
    });
    let limit = q.limit.unwrap_or(1000).min(10_000);
    let snap = state.db.snapshot();
    let iter = match state.db.range_bounds(start_bound, end_bound, snap) {
        Ok(it) => it,
        Err(e) => return engine_err(&e),
    };

    let mut records = Vec::new();
    let mut truncated = false;
    for (i, rec) in iter.enumerate() {
        if i >= limit {
            truncated = true;
            break;
        }
        let rec = match rec {
            Ok(r) => r,
            Err(e) => return engine_err(&e),
        };
        records.push(ScanRecord {
            key: BASE64.encode(&rec.key),
            value: BASE64.encode(&rec.value),
            seqno: rec.seqno,
        });
    }
    (
        StatusCode::OK,
        axum::Json(ScanResponse { records, truncated }),
    )
        .into_response()
}

async fn flush(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.flush() {
        Ok(()) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({"sstable_count": state.db.sstable_count()})),
        )
            .into_response(),
        Err(e) => engine_err(&e),
    }
}

async fn compact(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.compact_all() {
        Ok(()) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({"sstable_count": state.db.sstable_count()})),
        )
            .into_response(),
        Err(e) => engine_err(&e),
    }
}

fn engine_err(e: &paddock_core::Error) -> axum::response::Response {
    error!(error = %e, "engine error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("engine error: {e}\n"),
    )
        .into_response()
}
