//! OIDC/JWT authentication for human and workload identities.
//!
//! A bearer token that looks like a JWT is verified here when OIDC is configured. Verification either succeeds with a
//! principal taken from an explicitly configured rule, or fails with a stable error code. There is no fallback to API-key
//! authentication after a JWT fails verification, and no role comes from a token claim.
//!
//! What is checked, in order:
//!
//! 1. Shape: three segments; a non-empty signature. An unsigned (`alg: none`) token is refused before anything else.
//! 2. Algorithm: the header's `alg` must be exactly `RS256`, which is checked before any key is looked up. This refuses
//!    algorithm confusion (an HMAC token made with the public key as its secret) and every other algorithm.
//! 3. Key: the header's `kid` must name a key in the trusted JWKS. The JWKS comes only from the configured URL.
//! 4. Signature, `exp`, `nbf` (leeway at most 60 seconds), `iss` (exact match), `aud` (must contain the configured
//!    audience), and `sub`, `iss`, `aud`, `exp` must be present. `iat` must not be in the future beyond the leeway.
//! 5. Mapping: exactly one configured rule must match the token's issuer and identity. Human rules match `sub`; workload
//!    rules match the client (`client_id`, else `azp`) and require the token to be issued to that client (`sub` equals
//!    the client). A human token therefore cannot match a workload rule, and a workload token cannot match a human rule.
//!
//! JWKS handling: the cache is refreshed when older than five minutes. An unknown `kid` triggers at most one refresh per
//! 30 seconds, so a flood of unknown keys cannot force fetches. If a refresh is needed and fails, verification fails
//! (fail closed); stale keys are not used. Fetches have a timeout, a size limit, and no redirects.
//!
//! Not provided: validation of the provider's own security. Trusting the issuer is a configuration decision.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use once_cell::sync::OnceCell;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::govai_environment::GovaiEnvironment;
use crate::principals::{Principal, Role};

pub const ALGORITHM: Algorithm = Algorithm::RS256;
pub const MAX_LEEWAY_SECONDS: u64 = 60;
pub const DEFAULT_LEEWAY_SECONDS: u64 = 30;
pub const JWKS_MAX_AGE: Duration = Duration::from_secs(300);
pub const JWKS_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
pub const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
pub const JWKS_MAX_BYTES: usize = 64 * 1024;
pub const JWKS_MAX_KEYS: usize = 32;

/// The principal a verified OIDC token maps to. Set by the gate as a request extension; handlers read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal(pub Principal);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityKind {
    Human,
    Workload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcRule {
    pub issuer: String,
    pub kind: IdentityKind,
    /// Human: the token's `sub`. Workload: the client id (`client_id`, else `azp`), which must also equal `sub`.
    pub match_value: String,
    pub principal: Principal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
    pub leeway_seconds: u64,
    /// How long a fetched key set is used before it must be refreshed (bounded, see `JWKS_MAX_AGE_BOUNDS`).
    pub jwks_max_age: Duration,
    /// The shortest interval between refreshes triggered by an unknown key id (bounded).
    pub jwks_min_refresh: Duration,
    pub rules: Vec<OidcRule>,
}

/// The bounds for the JWKS timing settings, in seconds.
pub const JWKS_MAX_AGE_BOUNDS: (u64, u64) = (10, 3600);
pub const JWKS_MIN_REFRESH_BOUNDS: (u64, u64) = (1, 300);

#[derive(Debug, Deserialize)]
struct RuleDoc {
    issuer: String,
    kind: String,
    #[serde(rename = "match")]
    match_value: String,
    principal: String,
    identity: String,
    role: String,
    tenant: String,
}

fn parse_role(raw: &str) -> Result<Role, String> {
    match raw.trim() {
        "agent" => Ok(Role::Agent),
        "approver" => Ok(Role::Approver),
        "executor" => Ok(Role::Executor),
        other => Err(format!("unknown role {other:?} in GOVAI_OIDC_RULES_JSON")),
    }
}

/// An endpoint is https, or plain http to a loopback host when the test-only exception is explicitly enabled.
pub fn validate_endpoint(label: &str, url: &str, allow_loopback: bool) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("{label} is not a valid URL: {e}"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = matches!(parsed.host_str(), Some("127.0.0.1") | Some("localhost") | Some("[::1]") | Some("::1"));
            if loopback && allow_loopback {
                Ok(())
            } else {
                Err(format!("{label} must use https"))
            }
        }
        _ => Err(format!("{label} must use https")),
    }
}

impl OidcConfig {
    /// Read the configuration. `None` when no OIDC variable is set. A partial configuration is an error, not a fallback.
    pub fn from_env(deployment_env: GovaiEnvironment) -> Result<Option<Self>, String> {
        let get = |name: &str| std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let issuer = get("GOVAI_OIDC_ISSUER");
        let audience = get("GOVAI_OIDC_AUDIENCE");
        let jwks_url = get("GOVAI_OIDC_JWKS_URL");
        let rules_json = get("GOVAI_OIDC_RULES_JSON");
        let loopback = get("GOVAI_OIDC_ALLOW_LOOPBACK_JWKS").as_deref() == Some("1");
        let leeway = get("GOVAI_OIDC_LEEWAY_SECONDS");

        if issuer.is_none() && audience.is_none() && jwks_url.is_none() && rules_json.is_none() {
            return Ok(None);
        }
        let (Some(issuer), Some(audience), Some(jwks_url), Some(rules_json)) = (issuer, audience, jwks_url, rules_json)
        else {
            return Err(
                "OIDC is partially configured: set GOVAI_OIDC_ISSUER, GOVAI_OIDC_AUDIENCE, GOVAI_OIDC_JWKS_URL and GOVAI_OIDC_RULES_JSON together"
                    .to_string(),
            );
        };
        if loopback && deployment_env == GovaiEnvironment::Prod {
            return Err("GOVAI_OIDC_ALLOW_LOOPBACK_JWKS is a test-only setting and is refused in production".to_string());
        }
        let leeway_seconds = match leeway {
            None => DEFAULT_LEEWAY_SECONDS,
            Some(raw) => raw
                .parse::<u64>()
                .ok()
                .filter(|v| *v <= MAX_LEEWAY_SECONDS)
                .ok_or_else(|| format!("GOVAI_OIDC_LEEWAY_SECONDS must be an integer from 0 to {MAX_LEEWAY_SECONDS}"))?,
        };
        let bounded = |name: &str, default: u64, bounds: (u64, u64)| -> Result<u64, String> {
            match get(name) {
                None => Ok(default),
                Some(raw) => raw
                    .parse::<u64>()
                    .ok()
                    .filter(|v| (bounds.0..=bounds.1).contains(v))
                    .ok_or_else(|| format!("{name} must be an integer from {} to {}", bounds.0, bounds.1)),
            }
        };
        let jwks_max_age = Duration::from_secs(bounded(
            "GOVAI_OIDC_JWKS_MAX_AGE_SECONDS",
            JWKS_MAX_AGE.as_secs(),
            JWKS_MAX_AGE_BOUNDS,
        )?);
        let jwks_min_refresh = Duration::from_secs(bounded(
            "GOVAI_OIDC_JWKS_MIN_REFRESH_SECONDS",
            JWKS_MIN_REFRESH_INTERVAL.as_secs(),
            JWKS_MIN_REFRESH_BOUNDS,
        )?);
        let docs: Vec<RuleDoc> =
            serde_json::from_str(&rules_json).map_err(|e| format!("GOVAI_OIDC_RULES_JSON is not valid: {e}"))?;
        let mut rules = Vec::with_capacity(docs.len());
        for d in docs {
            let kind = match d.kind.trim() {
                "human" => IdentityKind::Human,
                "workload" => IdentityKind::Workload,
                other => return Err(format!("unknown identity kind {other:?} in GOVAI_OIDC_RULES_JSON")),
            };
            let principal_id = d.principal.trim().to_string();
            let identity = d.identity.trim().to_string();
            let tenant = d.tenant.trim().to_string();
            let match_value = d.match_value.trim().to_string();
            if principal_id.is_empty() || identity.is_empty() || tenant.is_empty() || match_value.is_empty() {
                return Err("every OIDC rule needs match, principal, identity, and tenant".to_string());
            }
            rules.push(OidcRule {
                issuer: d.issuer.trim().to_string(),
                kind,
                match_value,
                principal: Principal {
                    principal_id,
                    identity,
                    role: parse_role(&d.role)?,
                    tenant,
                },
            });
        }
        let cfg = Self { issuer, audience, jwks_url, leeway_seconds, jwks_max_age, jwks_min_refresh, rules };
        cfg.validate(loopback && deployment_env != GovaiEnvironment::Prod)?;
        Ok(Some(cfg))
    }

    pub fn validate(&self, allow_loopback: bool) -> Result<(), String> {
        validate_endpoint("GOVAI_OIDC_ISSUER", &self.issuer, allow_loopback)?;
        validate_endpoint("GOVAI_OIDC_JWKS_URL", &self.jwks_url, allow_loopback)?;
        if self.audience.is_empty() {
            return Err("GOVAI_OIDC_AUDIENCE must not be empty".to_string());
        }
        if self.leeway_seconds > MAX_LEEWAY_SECONDS {
            return Err(format!("leeway must be at most {MAX_LEEWAY_SECONDS} seconds"));
        }
        let mut seen = std::collections::HashSet::new();
        for r in &self.rules {
            if r.kind == IdentityKind::Workload && r.principal.role == Role::Approver {
                return Err(format!(
                    "workload identity {:?} may not hold the approver role: approval is for humans only",
                    r.match_value
                ));
            }
            if r.issuer != self.issuer {
                return Err(format!("an OIDC rule names issuer {:?}, which is not the configured issuer", r.issuer));
            }
            if !seen.insert((r.kind, r.match_value.clone())) {
                return Err(format!("duplicate OIDC rule for {:?}", r.match_value));
            }
        }
        Ok(())
    }
}

/// Stable, machine-readable reasons. Never includes token contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcError {
    Malformed,
    Unsigned,
    AlgorithmNotPermitted,
    UnknownKey,
    InvalidSignature,
    Expired,
    NotYetValid,
    IssuedInFuture,
    InvalidIssuer,
    InvalidAudience,
    MissingClaim(String),
    UnmappedIdentity,
    JwksUnavailable(&'static str),
}

impl OidcError {
    pub fn code(&self) -> &'static str {
        match self {
            OidcError::Malformed => "JWT_MALFORMED",
            OidcError::Unsigned => "JWT_UNSIGNED",
            OidcError::AlgorithmNotPermitted => "JWT_ALGORITHM_NOT_PERMITTED",
            OidcError::UnknownKey => "JWT_UNKNOWN_KEY",
            OidcError::InvalidSignature => "JWT_INVALID_SIGNATURE",
            OidcError::Expired => "JWT_EXPIRED",
            OidcError::NotYetValid => "JWT_NOT_YET_VALID",
            OidcError::IssuedInFuture => "JWT_ISSUED_IN_FUTURE",
            OidcError::InvalidIssuer => "JWT_INVALID_ISSUER",
            OidcError::InvalidAudience => "JWT_INVALID_AUDIENCE",
            OidcError::MissingClaim(_) => "JWT_MISSING_CLAIM",
            OidcError::UnmappedIdentity => "JWT_UNMAPPED_IDENTITY",
            OidcError::JwksUnavailable(_) => "JWKS_UNAVAILABLE",
        }
    }
}

/// A token that passed every check, and the principal it maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub issuer: String,
    pub subject: String,
    pub kind: IdentityKind,
    pub kid: String,
    pub principal: Principal,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: String,
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(rename = "use", default)]
    use_: Option<String>,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    iat: Option<i64>,
}

#[derive(Default)]
struct JwksState {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
}

pub struct OidcVerifier {
    cfg: OidcConfig,
    client: reqwest::Client,
    state: Mutex<JwksState>,
    /// Keys supplied directly (tests). When set, nothing is fetched.
    fixed: bool,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn jwt_header_alg_and_kid(token: &str) -> Result<(String, Option<String>), OidcError> {
    let header_b64 = token.split('.').next().ok_or(OidcError::Malformed)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| OidcError::Malformed)?;
    let v: Value = serde_json::from_slice(&raw).map_err(|_| OidcError::Malformed)?;
    let alg = v.get("alg").and_then(|a| a.as_str()).ok_or(OidcError::Malformed)?.to_string();
    let kid = v.get("kid").and_then(|k| k.as_str()).map(str::to_string);
    Ok((alg, kid))
}

fn map_jwt_error(e: jsonwebtoken::errors::Error) -> OidcError {
    use jsonwebtoken::errors::ErrorKind;
    match e.kind() {
        ErrorKind::ExpiredSignature => OidcError::Expired,
        ErrorKind::ImmatureSignature => OidcError::NotYetValid,
        ErrorKind::InvalidIssuer => OidcError::InvalidIssuer,
        ErrorKind::InvalidAudience => OidcError::InvalidAudience,
        ErrorKind::InvalidSignature => OidcError::InvalidSignature,
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => OidcError::AlgorithmNotPermitted,
        ErrorKind::MissingRequiredClaim(c) => OidcError::MissingClaim(c.clone()),
        _ => OidcError::Malformed,
    }
}

impl OidcVerifier {
    pub fn new(cfg: OidcConfig) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(JWKS_FETCH_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("OIDC HTTP client: {e}"))?;
        Ok(Self { cfg, client, state: Mutex::new(JwksState::default()), fixed: false })
    }

    /// For tests and for a controlled deployment that pins keys directly: no network, the given keys only.
    pub fn with_fixed_keys(cfg: OidcConfig, keys: HashMap<String, DecodingKey>) -> Self {
        let client = reqwest::Client::new();
        let state = JwksState { keys, fetched_at: Some(Instant::now()), last_attempt: None };
        Self { cfg, client, state: Mutex::new(state), fixed: true }
    }

    pub fn config(&self) -> &OidcConfig {
        &self.cfg
    }

    async fn refresh(&self, st: &mut JwksState) -> Result<(), OidcError> {
        st.last_attempt = Some(Instant::now());
        let resp = self
            .client
            .get(&self.cfg.jwks_url)
            .send()
            .await
            .map_err(|_| OidcError::JwksUnavailable("fetch failed"))?;
        if !resp.status().is_success() {
            return Err(OidcError::JwksUnavailable("provider returned an error status"));
        }
        if resp.content_length().is_some_and(|n| n as usize > JWKS_MAX_BYTES) {
            return Err(OidcError::JwksUnavailable("key set too large"));
        }
        let bytes = resp.bytes().await.map_err(|_| OidcError::JwksUnavailable("read failed"))?;
        if bytes.len() > JWKS_MAX_BYTES {
            return Err(OidcError::JwksUnavailable("key set too large"));
        }
        let doc: Jwks = serde_json::from_slice(&bytes).map_err(|_| OidcError::JwksUnavailable("malformed key set"))?;
        let mut keys = HashMap::new();
        for jwk in doc.keys.into_iter().take(JWKS_MAX_KEYS) {
            if jwk.kty != "RSA" || jwk.kid.is_empty() {
                continue;
            }
            if jwk.use_.as_deref().is_some_and(|u| u != "sig") {
                continue;
            }
            if jwk.alg.as_deref().is_some_and(|a| a != "RS256") {
                continue;
            }
            if let Ok(k) = DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
                keys.insert(jwk.kid, k);
            }
        }
        if keys.is_empty() {
            return Err(OidcError::JwksUnavailable("no usable RSA keys"));
        }
        st.keys = keys;
        st.fetched_at = Some(Instant::now());
        Ok(())
    }

    async fn key_for(&self, kid: &str) -> Result<DecodingKey, OidcError> {
        let mut st = self.state.lock().await;
        if self.fixed {
            return st.keys.get(kid).cloned().ok_or(OidcError::UnknownKey);
        }
        let fresh = st.fetched_at.is_some_and(|t| t.elapsed() < self.cfg.jwks_max_age);
        if !fresh {
            self.refresh(&mut st).await?;
        }
        if let Some(k) = st.keys.get(kid) {
            return Ok(k.clone());
        }
        let may_refresh = st.last_attempt.is_none_or(|t| t.elapsed() >= self.cfg.jwks_min_refresh);
        if may_refresh {
            self.refresh(&mut st).await?;
            if let Some(k) = st.keys.get(kid) {
                return Ok(k.clone());
            }
        }
        Err(OidcError::UnknownKey)
    }

    /// Verify a token and map it to a principal. `now` is unix seconds (injectable for tests).
    pub async fn verify_at(&self, token: &str, now: i64) -> Result<Verified, OidcError> {
        if token.split('.').count() != 3 {
            return Err(OidcError::Malformed);
        }
        let signature_segment = token.rsplit('.').next().unwrap_or("");
        let (alg, kid) = jwt_header_alg_and_kid(token)?;
        if alg.eq_ignore_ascii_case("none") || signature_segment.is_empty() {
            return Err(OidcError::Unsigned);
        }
        if alg != "RS256" {
            return Err(OidcError::AlgorithmNotPermitted);
        }
        let kid = kid.ok_or(OidcError::UnknownKey)?;
        let key = self.key_for(&kid).await?;

        let header = decode_header(token).map_err(|_| OidcError::Malformed)?;
        if header.alg != ALGORITHM {
            return Err(OidcError::AlgorithmNotPermitted);
        }
        let mut validation = Validation::new(ALGORITHM);
        validation.leeway = self.cfg.leeway_seconds;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.validate_aud = true;
        validation.required_spec_claims = ["exp", "iss", "aud", "sub"].iter().map(|s| s.to_string()).collect();
        validation.set_issuer(&[self.cfg.issuer.as_str()]);
        validation.set_audience(&[self.cfg.audience.as_str()]);
        let data = decode::<Value>(token, &key, &validation).map_err(map_jwt_error)?;
        let claims: Claims = serde_json::from_value(data.claims.clone()).map_err(|_| OidcError::MissingClaim("sub".into()))?;

        if let Some(iat) = claims.iat {
            if iat > now + self.cfg.leeway_seconds as i64 {
                return Err(OidcError::IssuedInFuture);
            }
        }
        let client = claims.client_id.as_deref().or(claims.azp.as_deref());
        let subject = claims.sub.clone();
        // A token issued to a configured workload client is never a human token, whatever its subject says. Otherwise a
        // service could name a human in `sub` and take that human's role.
        let is_workload_client = |c: &str| {
            self.cfg.rules.iter().any(|r| r.kind == IdentityKind::Workload && r.match_value == c)
        };
        let issued_to_workload = claims.client_id.as_deref().is_some_and(is_workload_client)
            || claims.azp.as_deref().is_some_and(is_workload_client);
        let matches: Vec<&OidcRule> = self
            .cfg
            .rules
            .iter()
            .filter(|r| match r.kind {
                IdentityKind::Human => {
                    r.match_value == subject && !issued_to_workload && client != Some(subject.as_str())
                }
                IdentityKind::Workload => r.match_value == subject && client == Some(subject.as_str()),
            })
            .collect();
        let rule = match matches.as_slice() {
            [one] => *one,
            _ => return Err(OidcError::UnmappedIdentity),
        };
        Ok(Verified {
            issuer: self.cfg.issuer.clone(),
            subject,
            kind: rule.kind,
            kid,
            principal: rule.principal.clone(),
        })
    }

    pub async fn verify(&self, token: &str) -> Result<Verified, OidcError> {
        self.verify_at(token, now_unix()).await
    }
}

static VERIFIER: OnceCell<Option<OidcVerifier>> = OnceCell::new();

/// Load OIDC at startup. Fails the startup on a partial or invalid configuration.
pub fn init_from_env(deployment_env: GovaiEnvironment) -> Result<(), String> {
    let cfg = OidcConfig::from_env(deployment_env)?;
    let verifier = match cfg {
        None => None,
        Some(c) => Some(OidcVerifier::new(c)?),
    };
    let _ = VERIFIER.set(verifier);
    Ok(())
}

pub fn verifier() -> Option<&'static OidcVerifier> {
    VERIFIER.get().and_then(|v| v.as_ref())
}

pub fn configured() -> bool {
    verifier().is_some()
}

/// True when the value has the shape of a compact JWS: three base64url segments. The signature segment may be empty:
/// an unsigned token (`alg: none`) is JWT-shaped too, so it reaches the verifier and is refused with its own code rather
/// than falling through to the API-key path.
pub fn looks_like_jwt(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 3
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && parts
            .iter()
            .all(|p| p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

/// The bearer token from the Authorization header, if any.
pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    let auth = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    auth.strip_prefix("Bearer ").map(str::trim).filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    //! Test-only RSA key. It signs nothing outside these tests and was generated for them.
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

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

    fn test_private_pem() -> &'static str {
        &generated_key().0
    }

    fn test_modulus() -> &'static str {
        &generated_key().1
    }

    fn test_public_pem() -> &'static str {
        &generated_key().2
    }


    const TEST_EXPONENT_B64URL: &str = "AQAB";
    const ISSUER: &str = "https://idp.test.invalid/realm";
    const AUDIENCE: &str = "govai-audit";

    fn cfg() -> OidcConfig {
        OidcConfig {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            jwks_url: "https://idp.test.invalid/jwks".into(),
            leeway_seconds: 30,
            jwks_max_age: Duration::from_secs(300),
            jwks_min_refresh: Duration::from_secs(30),
            rules: vec![
                OidcRule {
                    issuer: ISSUER.into(),
                    kind: IdentityKind::Human,
                    match_value: "alice".into(),
                    principal: Principal {
                        principal_id: "alice-approver".into(),
                        identity: "alice@example.test".into(),
                        role: Role::Approver,
                        tenant: "tenant-a".into(),
                    },
                },
                OidcRule {
                    issuer: ISSUER.into(),
                    kind: IdentityKind::Workload,
                    match_value: "svc-executor".into(),
                    principal: Principal {
                        principal_id: "svc-executor".into(),
                        identity: "svc-executor".into(),
                        role: Role::Executor,
                        tenant: "tenant-a".into(),
                    },
                },
            ],
        }
    }

    fn verifier() -> OidcVerifier {
        let mut keys = HashMap::new();
        keys.insert(
            "k1".to_string(),
            DecodingKey::from_rsa_components(test_modulus(), TEST_EXPONENT_B64URL).unwrap(),
        );
        OidcVerifier::with_fixed_keys(cfg(), keys)
    }

    fn now() -> i64 {
        now_unix()
    }

    fn rs256(kid: &str, claims: Value) -> String {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some(kid.into());
        encode(&h, &claims, &EncodingKey::from_rsa_pem(test_private_pem().as_bytes()).unwrap()).unwrap()
    }

    fn base_claims(sub: &str) -> Value {
        let n = now();
        serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": sub,
            "iat": n, "nbf": n - 5, "exp": n + 300,
        })
    }

    fn hs256_with_public_key_as_secret(claims: Value) -> String {
        // The classic algorithm-confusion attack: an HMAC token keyed with the public key material.
        let h = Header::new(Algorithm::HS256);
        let key = EncodingKey::from_secret(test_public_pem().as_bytes()).unwrap();
        encode(&h, &claims, &key).unwrap()
    }

    fn unsigned(claims: &Value) -> String {
        let b = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        format!(
            "{}.{}.",
            b(br#"{"alg":"none","typ":"JWT","kid":"k1"}"#),
            b(claims.to_string().as_bytes())
        )
    }

    #[tokio::test]
    async fn valid_human_token_maps_to_its_rule() {
        let v = verifier().verify_at(&rs256("k1", base_claims("alice")), now()).await.unwrap();
        assert_eq!(v.kind, IdentityKind::Human);
        assert_eq!(v.principal.principal_id, "alice-approver");
        assert_eq!(v.principal.role, Role::Approver);
        assert_eq!(v.principal.tenant, "tenant-a");
    }

    #[tokio::test]
    async fn valid_workload_token_requires_client_to_equal_subject() {
        let mut c = base_claims("svc-executor");
        c["client_id"] = "svc-executor".into();
        let v = verifier().verify_at(&rs256("k1", c), now()).await.unwrap();
        assert_eq!(v.kind, IdentityKind::Workload);
        assert_eq!(v.principal.role, Role::Executor);
    }

    #[tokio::test]
    async fn delegated_human_token_from_another_client_maps_to_the_human_rule() {
        // alice's session issued to a front-end client: sub differs from the client, so it is a human token.
        let mut c = base_claims("alice");
        c["azp"] = "some-frontend-client".into();
        let v = verifier().verify_at(&rs256("k1", c), now()).await.unwrap();
        assert_eq!(v.kind, IdentityKind::Human);
    }

    #[tokio::test]
    async fn workload_token_with_a_human_subject_matches_no_rule() {
        // sub = alice, client = svc-executor: a client-issued token claiming a human subject. No rule matches it.
        let mut c = base_claims("alice");
        c["client_id"] = "svc-executor".into();
        let err = verifier().verify_at(&rs256("k1", c), now()).await.unwrap_err();
        assert_eq!(err, OidcError::UnmappedIdentity);
    }

    #[tokio::test]
    async fn workload_rule_never_matches_a_human_token() {
        let err = verifier().verify_at(&rs256("k1", base_claims("svc-executor")), now()).await.unwrap_err();
        assert_eq!(err, OidcError::UnmappedIdentity);
    }

    #[tokio::test]
    async fn expired_token_is_refused() {
        let n = now();
        let mut c = base_claims("alice");
        c["exp"] = (n - 1000).into();
        let err = verifier().verify_at(&rs256("k1", c), n).await.unwrap_err();
        assert_eq!(err, OidcError::Expired);
    }

    #[tokio::test]
    async fn not_yet_valid_token_is_refused() {
        let n = now();
        let mut c = base_claims("alice");
        c["nbf"] = (n + 600).into();
        let err = verifier().verify_at(&rs256("k1", c), n).await.unwrap_err();
        assert_eq!(err, OidcError::NotYetValid);
    }

    #[tokio::test]
    async fn token_issued_in_the_future_is_refused() {
        let n = now();
        let mut c = base_claims("alice");
        c["iat"] = (n + 3600).into();
        let err = verifier().verify_at(&rs256("k1", c), n).await.unwrap_err();
        assert_eq!(err, OidcError::IssuedInFuture);
    }

    #[tokio::test]
    async fn wrong_issuer_is_refused() {
        let mut c = base_claims("alice");
        c["iss"] = "https://evil.test.invalid".into();
        let err = verifier().verify_at(&rs256("k1", c), now()).await.unwrap_err();
        assert_eq!(err, OidcError::InvalidIssuer);
    }

    #[tokio::test]
    async fn wrong_audience_is_refused() {
        let mut c = base_claims("alice");
        c["aud"] = "some-other-api".into();
        let err = verifier().verify_at(&rs256("k1", c), now()).await.unwrap_err();
        assert_eq!(err, OidcError::InvalidAudience);
    }

    #[tokio::test]
    async fn missing_audience_is_refused() {
        let mut c = base_claims("alice");
        c.as_object_mut().unwrap().remove("aud");
        let err = verifier().verify_at(&rs256("k1", c), now()).await.unwrap_err();
        assert!(matches!(err, OidcError::MissingClaim(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn unsigned_token_is_refused_before_any_key_lookup() {
        let err = verifier().verify_at(&unsigned(&base_claims("alice")), now()).await.unwrap_err();
        assert_eq!(err, OidcError::Unsigned);
    }

    #[tokio::test]
    async fn hs256_algorithm_confusion_is_refused() {
        let err = verifier()
            .verify_at(&hs256_with_public_key_as_secret(base_claims("alice")), now())
            .await
            .unwrap_err();
        assert_eq!(err, OidcError::AlgorithmNotPermitted);
    }

    #[tokio::test]
    async fn unknown_signing_key_is_refused() {
        let err = verifier().verify_at(&rs256("not-trusted", base_claims("alice")), now()).await.unwrap_err();
        assert_eq!(err, OidcError::UnknownKey);
    }

    #[tokio::test]
    async fn tampered_payload_is_refused() {
        let token = rs256("k1", base_claims("alice"));
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        let forged = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(base_claims("svc-executor").to_string().as_bytes());
        parts[1] = forged;
        let err = verifier().verify_at(&parts.join("."), now()).await.unwrap_err();
        assert_eq!(err, OidcError::InvalidSignature);
    }

    #[tokio::test]
    async fn malformed_token_is_refused() {
        let err = verifier().verify_at("not-a-jwt", now()).await.unwrap_err();
        assert_eq!(err, OidcError::Malformed);
    }

    #[test]
    fn config_rejects_a_rule_for_another_issuer() {
        let mut c = cfg();
        c.rules[0].issuer = "https://other.test.invalid".into();
        assert!(c.validate(false).is_err());
    }

    #[test]
    fn config_rejects_plain_http_unless_loopback_test_mode() {
        assert!(validate_endpoint("x", "http://idp.example.com/jwks", true).is_err());
        assert!(validate_endpoint("x", "http://127.0.0.1:9000/jwks", false).is_err());
        assert!(validate_endpoint("x", "http://127.0.0.1:9000/jwks", true).is_ok());
    }

    #[test]
    fn looks_like_jwt_requires_three_segments() {
        assert!(looks_like_jwt("aaa.bbb.ccc"));
        assert!(looks_like_jwt("aaa.bbb."), "an unsigned token must reach the verifier");
        assert!(!looks_like_jwt("sk_live_abc"));
        assert!(!looks_like_jwt("a.b"));
    }

    // --- identity-type confusion -------------------------------------------------------------------------------

    fn with_claim(mut c: Value, k: &str, v: Value) -> Value {
        c[k] = v;
        c
    }

    #[tokio::test]
    async fn audience_array_with_only_foreign_audiences_is_refused() {
        let c = with_claim(base_claims("alice"), "aud", serde_json::json!(["other-api", "third-api"]));
        let err = verifier().verify_at(&rs256("k1", c), now()).await.unwrap_err();
        assert_eq!(err, OidcError::InvalidAudience);
    }

    #[tokio::test]
    async fn audience_array_containing_ours_is_accepted() {
        let c = with_claim(base_claims("alice"), "aud", serde_json::json!(["other-api", AUDIENCE]));
        let v = verifier().verify_at(&rs256("k1", c), now()).await.unwrap();
        assert_eq!(v.kind, IdentityKind::Human);
    }

    #[tokio::test]
    async fn token_from_a_different_issuer_with_a_trusted_key_is_refused() {
        // Same key, same audience, foreign issuer: trusting the key does not trust the issuer.
        let c = with_claim(base_claims("alice"), "iss", "https://idp.other.test.invalid".into());
        let err = verifier().verify_at(&rs256("k1", c), now()).await.unwrap_err();
        assert_eq!(err, OidcError::InvalidIssuer);
    }

    #[tokio::test]
    async fn subject_mapping_is_exact_and_case_sensitive() {
        for sub in ["Alice", "alice ", "ALICE", "alice@example.test"] {
            let err = verifier().verify_at(&rs256("k1", base_claims(sub)), now()).await.unwrap_err();
            assert_eq!(err, OidcError::UnmappedIdentity, "sub {sub:?} must not map to alice");
        }
    }

    #[tokio::test]
    async fn workload_subject_without_a_client_claim_is_not_a_workload() {
        // sub equals a workload client id but no client claim is present: a workload identity needs proof of issuance.
        let err = verifier().verify_at(&rs256("k1", base_claims("svc-executor")), now()).await.unwrap_err();
        assert_eq!(err, OidcError::UnmappedIdentity);
    }

    #[tokio::test]
    async fn workload_client_in_azp_alone_is_treated_as_workload() {
        let c = with_claim(base_claims("svc-executor"), "azp", "svc-executor".into());
        let v = verifier().verify_at(&rs256("k1", c), now()).await.unwrap();
        assert_eq!(v.kind, IdentityKind::Workload);
        assert_eq!(v.principal.role, Role::Executor);
    }

    #[tokio::test]
    async fn human_subject_issued_to_a_workload_through_azp_is_refused() {
        // The guard must look at azp too, not only client_id.
        let c = with_claim(base_claims("alice"), "azp", "svc-executor".into());
        let err = verifier().verify_at(&rs256("k1", c), now()).await.unwrap_err();
        assert_eq!(err, OidcError::UnmappedIdentity);
    }

    #[tokio::test]
    async fn human_subject_with_workload_client_id_and_benign_azp_is_refused() {
        let mut c = base_claims("alice");
        c["client_id"] = "svc-executor".into();
        c["azp"] = "frontend".into();
        let err = verifier().verify_at(&rs256("k1", c), now()).await.unwrap_err();
        assert_eq!(err, OidcError::UnmappedIdentity);
    }

    #[tokio::test]
    async fn no_workload_credential_ever_yields_the_approver_role() {
        // Every claim shape a workload can present, with a human subject, a workload subject, and mixed claims.
        // Plain human tokens (no client claim, subject alice) are excluded: they are legitimately approvers.
        let shapes: Vec<Value> = vec![
            with_claim(base_claims("alice"), "client_id", "svc-executor".into()),
            with_claim(base_claims("alice"), "azp", "svc-executor".into()),
            with_claim(base_claims("svc-executor"), "client_id", "svc-executor".into()),
            with_claim(base_claims("svc-executor"), "azp", "svc-executor".into()),
            with_claim(base_claims("svc-executor"), "azp", "alice".into()),
            base_claims("svc-executor"),
        ];
        for c in shapes {
            if let Ok(v) = verifier().verify_at(&rs256("k1", c.clone()), now()).await {
                assert_ne!(v.principal.role, Role::Approver, "claims {c} granted approver");
                // Every shape here names the workload client somewhere, so a human mapping would be a confusion.
                assert_eq!(v.kind, IdentityKind::Workload, "claims {c} mapped a workload token as human");
            }
        }
    }

    #[test]
    fn config_refuses_a_workload_rule_with_the_approver_role() {
        let mut c = cfg();
        c.rules.push(OidcRule {
            issuer: ISSUER.into(),
            kind: IdentityKind::Workload,
            match_value: "svc-approver".into(),
            principal: Principal {
                principal_id: "svc-approver".into(),
                identity: "svc-approver".into(),
                role: Role::Approver,
                tenant: "tenant-a".into(),
            },
        });
        let err = c.validate(false).unwrap_err();
        assert!(err.contains("approver"), "{err}");
    }

    #[test]
    fn config_refuses_duplicate_rules_for_the_same_identity() {
        let mut c = cfg();
        let dup = c.rules[0].clone();
        c.rules.push(dup);
        assert!(c.validate(false).is_err());
    }
}
