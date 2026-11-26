//! Bounded request handling over a real socket: a stalled client cannot hold a worker slot, the concurrency limit does not
//! block health, an oversized body is refused, and a normal event still succeeds afterwards.
//!
//! One test function, because the configuration is process-wide and the phases share one server.

mod common;

use aigov_audit::{build_app_state, build_router};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const KEY: &str = "limits-agent-k";

/// Send raw bytes and read until the server closes the connection or `wait` elapses. Returns what was read.
fn exchange(addr: SocketAddr, bytes: &[u8], wait: Duration) -> (String, Duration) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(wait)).unwrap();
    s.write_all(bytes).expect("write");
    let start = Instant::now();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    (String::from_utf8_lossy(&out).into_owned(), start.elapsed())
}

fn status_line(resp: &str) -> &str {
    resp.lines().next().unwrap_or("")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_requests_over_a_real_socket() {
    let ledger = tempfile::tempdir().unwrap();
    for k in ["AIGOV_POLICY_FILE", "AIGOV_POLICY_DIR", "AIGOV_KEY_REGISTRY_PATH", "GOVAI_KEY_REGISTRY_PATH", "AIGOV_ENVIRONMENT", "AIGOV_ENV", "GOVAI_DATABASE_URL", "DATABASE_URL", "GOVAI_PRINCIPALS_JSON"] {
        std::env::remove_var(k);
    }
    std::env::set_var("GOVAI_ENV", "dev");
    std::env::set_var("GOVAI_LEDGER_DIR", ledger.path());
    std::env::set_var("GOVAI_API_KEYS", KEY);
    std::env::set_var("GOVAI_API_KEYS_JSON", format!(r#"{{"{KEY}":"t1"}}"#));
    // Small, deliberately tight limits so each phase is quick and deterministic.
    // LIMITS_TEST_TIMEOUT exists so the negative control can run with the limit effectively removed.
    let timeout = std::env::var("LIMITS_TEST_TIMEOUT").unwrap_or_else(|_| "1".to_string());
    std::env::set_var("AIGOV_REQUEST_TIMEOUT_SECS", timeout);
    std::env::set_var("AIGOV_MAX_CONCURRENT_REQUESTS", "2");
    std::env::set_var("AIGOV_MAX_BODY_BYTES", "1024");

    let state = build_app_state().await.expect("core state");
    assert_eq!(state.request_limits.max_concurrent, 2);
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });
    // The blocking helpers run on their own threads so they never block the server.
    let blocking = |f: Box<dyn FnOnce() -> (String, Duration) + Send>| tokio::task::spawn_blocking(f);

    // Phase 1: a client that sends headers and stalls the body. The time limit must end it, not the client.
    let stall_head = format!(
        "POST /evidence HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {KEY}\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{{\"event_id\":"
    );
    let stalled = blocking(Box::new({
        let head = stall_head.clone();
        move || exchange(addr, head.as_bytes(), Duration::from_secs(8))
    }));
    let (resp, took) = stalled.await.unwrap();
    assert!(
        status_line(&resp).contains("408") || resp.is_empty(),
        "a stalled body must end with 408 or a close, got {:?}",
        status_line(&resp)
    );
    assert!(took < Duration::from_secs(6), "stalled request held on for {took:?}");

    // Phase 2: two stalled clients hold both permits. Health is outside the limit and must still answer promptly.
    let holders: Vec<_> = (0..2)
        .map(|_| {
            let head = stall_head.clone();
            blocking(Box::new(move || exchange(addr, head.as_bytes(), Duration::from_secs(8))))
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let health = blocking(Box::new(move || {
        exchange(addr, b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", Duration::from_secs(4))
    }));
    let (resp, took) = health.await.unwrap();
    assert!(status_line(&resp).contains("200"), "health under load: {:?}", status_line(&resp));
    assert!(took < Duration::from_secs(2), "health waited {took:?} behind the request limit");
    // A third request finds both permits taken. It is refused at once with 503 OVERLOADED, before any handler runs, so it
    // records nothing. The ledger's record count must not change.
    let ledger_file = ledger.path().join("audit_log__t1.jsonl");
    let records_before = std::fs::read_to_string(&ledger_file).map(|s| s.lines().count()).unwrap_or(0);
    let third_body = r#"{"event_id":"lim-3","event_type":"ai_discovery_reported","ts_utc":"2026-11-26T10:00:00Z","actor":"a","system":"s","run_id":"lim-run","payload":{"openai":false}}"#;
    let third_req = format!(
        "POST /evidence HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {KEY}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{third_body}",
        third_body.len()
    );
    let third = blocking(Box::new(move || exchange(addr, third_req.as_bytes(), Duration::from_secs(6))));
    let (resp, took) = third.await.unwrap();
    assert!(status_line(&resp).contains("503"), "a request over the limit must be refused at once, got {:?}", status_line(&resp));
    assert!(resp.contains("OVERLOADED"), "refusal must carry the OVERLOADED code: {resp}");
    assert!(took < Duration::from_millis(900), "the refusal must not wait: {took:?}");
    let records_after_refusal = std::fs::read_to_string(&ledger_file).map(|s| s.lines().count()).unwrap_or(0);
    assert_eq!(records_after_refusal, records_before, "a refused request must not be recorded");
    for h in holders {
        let _ = h.await;
    }

    // Phase 3: an oversized body is refused with 413 (limit 1024 bytes).
    let big = format!(r#"{{"event_id":"lim-big","event_type":"ai_discovery_reported","ts_utc":"2026-11-26T10:00:00Z","actor":"a","system":"s","run_id":"lim-run","payload":{{"pad":"{}"}}}}"#, "x".repeat(4096));
    let big_req = format!(
        "POST /evidence HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {KEY}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{big}",
        big.len()
    );
    let oversized = blocking(Box::new(move || exchange(addr, big_req.as_bytes(), Duration::from_secs(6))));
    let (resp, _) = oversized.await.unwrap();
    assert!(status_line(&resp).contains("413"), "oversized body must be 413, got {:?}", status_line(&resp));

    // Phase 4: a normal event still succeeds after all of the above.
    let fresh_body = third_body.replace("lim-3", "lim-4");
    let ok_req = format!(
        "POST /evidence HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {KEY}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{fresh_body}",
        fresh_body.len()
    );
    let ok = blocking(Box::new(move || exchange(addr, ok_req.as_bytes(), Duration::from_secs(6))));
    let (resp, _) = ok.await.unwrap();
    assert!(status_line(&resp).contains("200"), "normal event after limits: {:?}", status_line(&resp));
}
