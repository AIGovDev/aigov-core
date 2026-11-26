//! HTTP-level OIDC gate tests. A loopback JWKS server acts as the test identity provider, and requests go through the
//! real Core router. Test-only RSA key: it signs nothing outside these tests. Each scenario checks the verdict code.
//!
//! One process-wide configuration (OIDC is a process global), so all scenarios run from one test function.

use aigov_audit::{build_app_state, build_router};
use base64::Engine;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::routing::get;
use axum::Json;
use http_body_util::BodyExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use tower::ServiceExt;

const ISSUER_PATH: &str = "/realm";
const AUDIENCE: &str = "govai-audit";

/// A throwaway RSA key pair, generated at test time in a temporary directory. Nothing is committed to the repository.
fn generated_key() -> &'static (String, String, String) {
    static KEY: std::sync::OnceLock<(String, String, String)> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let dir = tempfile::tempdir().expect("temp dir");
        let key = dir.path().join("k.pem");
        let public = dir.path().join("pub.pem");
        let key_s = key.to_str().unwrap();
        let pub_s = public.to_str().unwrap();
        let run = |args: &[&str]| {
            let st = std::process::Command::new("openssl")
                .args(args)
                .status()
                .expect("openssl must be installed to run the OIDC tests");
            assert!(st.success(), "openssl {args:?} failed");
        };
        run(&["genrsa", "-out", key_s, "2048"]);
        run(&["rsa", "-in", key_s, "-pubout", "-out", pub_s]);
        let out = std::process::Command::new("openssl")
            .args(["rsa", "-in", key_s, "-noout", "-modulus"])
            .output()
            .expect("openssl rsa -modulus");
        let hex = String::from_utf8(out.stdout).unwrap();
        let hex = hex.trim().trim_start_matches("Modulus=");
        let n_bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n_bytes);
        (
            std::fs::read_to_string(&key).unwrap(),
            n,
            std::fs::read_to_string(&public).unwrap(),
        )
    })
}

fn private_pem() -> &'static str {
    &generated_key().0
}

fn modulus() -> &'static str {
    &generated_key().1
}

fn public_pem() -> &'static str {
    &generated_key().2
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn token(kid: &str, issuer: &str, claims: Value) -> String {
    let mut h = Header::new(Algorithm::RS256);
    h.kid = Some(kid.into());
    let mut c = claims;
    c["iss"] = issuer.into();
    c["aud"] = AUDIENCE.into();
    c["iat"] = now().into();
    c["nbf"] = (now() - 5).into();
    c["exp"] = (now() + 300).into();
    encode(&h, &c, &EncodingKey::from_rsa_pem(private_pem().as_bytes()).unwrap()).unwrap()
}

fn event(event_type: &str) -> Value {
    json!({
        "event_id": format!("evt-oidc-{}", now()),
        "event_type": event_type,
        "ts_utc": "2026-11-26T10:00:00Z",
        "actor": "test",
        "system": "oidc-http-test",
        "run_id": "run-oidc-http",
        "payload": {},
    })
}

async fn post(app: &axum::Router, bearer: Option<&str>, body: &Value) -> (StatusCode, Value) {
    let mut b = Request::builder().method("POST").uri("/evidence").header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let resp = app.clone().oneshot(b.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn code_of(body: &Value) -> String {
    body.pointer("/error/code")
        .or_else(|| body.get("code"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn oidc_gate_refuses_workload_approval_and_confused_tokens() {
    // Loopback JWKS: the test identity provider.
    let jwks = json!({"keys": [{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":modulus(),"e":"AQAB"}]});
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let idp = format!("http://127.0.0.1:{port}{ISSUER_PATH}");
    let jwks_app = axum::Router::new().route("/jwks", get(move || { let j = jwks.clone(); async move { Json(j) } }));
    tokio::spawn(async move { axum::serve(listener, jwks_app).await.unwrap(); });

    let ledger = tempfile::Builder::new().prefix("oidc-http-ledger-").tempdir().unwrap();
    std::env::set_var("GOVAI_LEDGER_DIR", ledger.path());
    std::env::set_var("GOVAI_OIDC_ISSUER", &idp);
    std::env::set_var("GOVAI_OIDC_AUDIENCE", AUDIENCE);
    std::env::set_var("GOVAI_OIDC_JWKS_URL", format!("http://127.0.0.1:{port}/jwks"));
    std::env::set_var("GOVAI_OIDC_ALLOW_LOOPBACK_JWKS", "1");
    std::env::set_var(
        "GOVAI_OIDC_RULES_JSON",
        json!([
            {"issuer": idp, "kind": "human", "match": "alice", "principal": "alice-approver",
              "identity": "alice@example.test", "role": "approver", "tenant": "tenant-a"},
            {"issuer": idp, "kind": "workload", "match": "svc-executor", "principal": "svc-executor",
              "identity": "svc-executor", "role": "executor", "tenant": "tenant-a"},
            {"issuer": idp, "kind": "workload", "match": "svc-agent", "principal": "svc-agent",
              "identity": "svc-agent", "role": "agent", "tenant": "tenant-a"}
        ])
        .to_string(),
    );
    std::env::remove_var("GOVAI_API_KEYS");

    let state = build_app_state().await.expect("core state with OIDC configured");
    let app = build_router(state);

    // 1. A human approver may post an approval.
    let alice = token("k1", &idp, json!({"sub": "alice"}));
    let (status, body) = post(&app, Some(&alice), &event("human_approved")).await;
    assert_ne!(code_of(&body), "ROLE_NOT_PERMITTED", "human approver refused: {status} {body}");
    assert_ne!(status, StatusCode::UNAUTHORIZED, "valid human token refused: {body}");

    // 2. A workload may never post an approval, however its claims are shaped.
    let shapes = [
        json!({"sub": "svc-executor", "client_id": "svc-executor"}),
        json!({"sub": "svc-executor", "azp": "svc-executor"}),
        json!({"sub": "alice", "client_id": "svc-executor"}),
        json!({"sub": "alice", "azp": "svc-executor"}),
        json!({"sub": "svc-agent", "client_id": "svc-agent"}),
    ];
    for claims in shapes {
        let t = token("k1", &idp, claims.clone());
        let (status, body) = post(&app, Some(&t), &event("human_approved")).await;
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
            "claims {claims} reached ingest with {status}: {body}"
        );
        assert_ne!(code_of(&body), "", "claims {claims} must carry a stable refusal code");
        assert!(
            matches!(code_of(&body).as_str(), "ROLE_NOT_PERMITTED" | "JWT_UNMAPPED_IDENTITY"),
            "claims {claims} refused with an unexpected code {}",
            code_of(&body)
        );
    }

    // 3. Algorithm confusion over HTTP: HS256 keyed with the public key is refused before it reaches ingest.
    let hs = {
        let h = Header::new(Algorithm::HS256);
        let mut c = json!({"sub": "alice"});
        c["iss"] = idp.clone().into();
        c["aud"] = AUDIENCE.into();
        c["iat"] = now().into();
        c["exp"] = (now() + 300).into();
        encode(&h, &c, &EncodingKey::from_secret(public_pem().as_bytes()).unwrap()).unwrap()
    };
    let (status, body) = post(&app, Some(&hs), &event("human_approved")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(code_of(&body), "JWT_ALGORITHM_NOT_PERMITTED");

    // 4. Wrong audience and wrong issuer are refused with their own codes.
    let h = Header { alg: Algorithm::RS256, kid: Some("k1".into()), ..Header::default() };
    let wrong_aud = encode(&h, &json!({"sub":"alice","iss":idp,"aud":"other-api","iat":now(),"nbf":now()-5,"exp":now()+300}), &EncodingKey::from_rsa_pem(private_pem().as_bytes()).unwrap()).unwrap();
    let (status, body) = post(&app, Some(&wrong_aud), &event("human_approved")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code_of(&body), "JWT_INVALID_AUDIENCE");

    let wrong_iss = token("k1", "https://evil.test.invalid/realm", json!({"sub": "alice"}));
    let (status, body) = post(&app, Some(&wrong_iss), &event("human_approved")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code_of(&body), "JWT_INVALID_ISSUER");

    // 5. Unknown signing key is refused.
    let unknown = token("not-trusted", &idp, json!({"sub": "alice"}));
    let (status, body) = post(&app, Some(&unknown), &event("human_approved")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code_of(&body), "JWT_UNKNOWN_KEY");

    // 6. No credential, and a non-JWT credential, are both refused. There is no API-key fallback when OIDC is configured.
    let (status, body) = post(&app, None, &event("human_approved")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (status, body) = post(&app, Some("sk_live_not_a_jwt"), &event("human_approved")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    // In dev the API-key map is initialized (empty), so a non-JWT credential reaches the API-key lookup, which refuses it.
    // Either refusal code is acceptable: the request fails with 401, and no fallback can succeed.
    assert!(
        matches!(code_of(&body).as_str(), "INVALID_AUTH_TOKEN" | "INVALID_API_KEY"),
        "unexpected refusal code {}",
        code_of(&body)
    );
}
