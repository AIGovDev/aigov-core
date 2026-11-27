//! Experimental storage primitive; not yet wired into HTTP authorization.
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

#[derive(Debug, PartialEq, Eq)]
pub struct AppendResult {
    pub sequence: i64,
    pub record_hash: String,
    pub replay: bool,
}

pub async fn append(
    pool: &PgPool,
    tenant: &str,
    event_id: &str,
    event_json: &str,
) -> Result<AppendResult, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let result = append_in_transaction(&mut tx, tenant, event_id, event_json).await?;
    tx.commit().await?;
    Ok(result)
}

/// Caller must commit only after all policy and authorization checks succeed.
/// A failed operation requires rollback of the entire transaction.
pub async fn append_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    event_id: &str,
    event_json: &str,
) -> Result<AppendResult, sqlx::Error> {
    let invalid = |message: &str| sqlx::Error::Protocol(message.to_owned());
    let event: serde_json::Value = serde_json::from_str(event_json)
        .map_err(|_| invalid("invalid event JSON"))?;
    if tenant.is_empty() || event_id.is_empty()
        || event.get("event_id").and_then(|v| v.as_str()) != Some(event_id)
    {
        return Err(invalid("invalid tenant or event identity"));
    }
    sqlx::query("INSERT INTO core_ledger_heads VALUES ($1, 0, 'GENESIS') ON CONFLICT DO NOTHING")
        .bind(tenant)
        .execute(&mut **tx)
        .await?;
    let head = sqlx::query("SELECT seq, head_hash FROM core_ledger_heads WHERE tenant_id=$1 FOR UPDATE")
        .bind(tenant)
        .fetch_one(&mut **tx)
        .await?;
    if let Some(row) = sqlx::query("SELECT seq, event_json, record_hash FROM core_ledger_records WHERE tenant_id=$1 AND event_id=$2")
        .bind(tenant)
        .bind(event_id)
        .fetch_optional(&mut **tx)
        .await?
    {
        if row.get::<String, _>("event_json") != event_json {
            return Err(invalid("conflicting event replay"));
        }
        let result = AppendResult {
            sequence: row.get("seq"),
            record_hash: row.get("record_hash"),
            replay: true,
        };
        return Ok(result);
    }
    let sequence = head.get::<i64, _>("seq").checked_add(1)
        .ok_or_else(|| invalid("ledger sequence overflow"))?;
    let previous: String = head.get("head_hash");
    let mut hasher = Sha256::new();
    hasher.update(previous.as_bytes());
    hasher.update(b"\n");
    hasher.update(event_json.as_bytes());
    let record_hash = hex::encode(hasher.finalize());
    sqlx::query("INSERT INTO core_ledger_records (tenant_id,seq,event_id,event_json,prev_hash,record_hash) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(tenant).bind(sequence).bind(event_id).bind(event_json)
        .bind(&previous).bind(&record_hash).execute(&mut **tx).await?;
    sqlx::query("UPDATE core_ledger_heads SET seq=$2, head_hash=$3 WHERE tenant_id=$1")
        .bind(tenant).bind(sequence).bind(&record_hash).execute(&mut **tx).await?;
    Ok(AppendResult { sequence, record_hash, replay: false })
}

/// Storage-only reservation. The caller must independently validate approval
/// identity, role, action binding and policy revision before invoking this.
/// Both referenced events must exist in the same tenant ledger.
/// A conflict aborts the transaction; do not issue authorization on failure.
pub async fn reserve_validated_approval(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    approval_event_id: &str,
    decision_event_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO core_approval_consumptions (tenant_id, approval_event_id, decision_event_id) VALUES ($1,$2,$3)",
    )
    .bind(tenant)
    .bind(approval_event_id)
    .bind(decision_event_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Lock the tenant head before reading policy evidence. All writers must use
/// this same lock; the caller owns the transaction and must not release it
/// between policy evaluation and append.
pub async fn lock_tenant_and_read(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
) -> Result<Vec<String>, sqlx::Error> {
    if tenant.is_empty() {
        return Err(sqlx::Error::Protocol("empty tenant".to_owned()));
    }
    sqlx::query("INSERT INTO core_ledger_heads VALUES ($1, 0, 'GENESIS') ON CONFLICT DO NOTHING")
        .bind(tenant)
        .execute(&mut **tx)
        .await?;
    sqlx::query("SELECT seq FROM core_ledger_heads WHERE tenant_id=$1 FOR UPDATE")
        .bind(tenant)
        .fetch_one(&mut **tx)
        .await?;
    sqlx::query_scalar("SELECT event_json FROM core_ledger_records WHERE tenant_id=$1 ORDER BY seq")
        .bind(tenant)
        .fetch_all(&mut **tx)
        .await
}

/// Read only the requested run while holding the tenant serialization lock.
/// This does not replace tenant-wide checks such as global event uniqueness.
pub async fn lock_tenant_and_read_run(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    run_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
    if tenant.is_empty() || run_id.is_empty() {
        return Err(sqlx::Error::Protocol("empty tenant or run".to_owned()));
    }
    sqlx::query("INSERT INTO core_ledger_heads VALUES ($1, 0, 'GENESIS') ON CONFLICT DO NOTHING")
        .bind(tenant)
        .execute(&mut **tx)
        .await?;
    sqlx::query("SELECT seq FROM core_ledger_heads WHERE tenant_id=$1 FOR UPDATE")
        .bind(tenant)
        .fetch_one(&mut **tx)
        .await?;
    sqlx::query_scalar("SELECT event_json FROM core_ledger_records WHERE tenant_id=$1 AND event_json::jsonb->>'run_id'=$2 ORDER BY seq")
        .bind(tenant)
        .bind(run_id)
        .fetch_all(&mut **tx)
        .await
}

/// Export a consistent tenant chain and verify it against the caller's trusted
/// checkpoint. A database head alone is not an independent trust anchor.
pub async fn verify_checkpoint(
    pool: &PgPool,
    tenant: &str,
    expected_sequence: i64,
    expected_hash: &str,
) -> Result<(), sqlx::Error> {
    validate_snapshot(pool, tenant, expected_sequence, expected_hash, false)
        .await
        .map(|_| ())
}

/// Export a consistent snapshot against an independently supplied checkpoint.
/// No bytes are returned unless the entire snapshot validates.
pub async fn export_checkpoint_jsonl(
    pool: &PgPool,
    tenant: &str,
    expected_sequence: i64,
    expected_hash: &str,
) -> Result<Vec<u8>, sqlx::Error> {
    validate_snapshot(pool, tenant, expected_sequence, expected_hash, true).await
}

async fn validate_snapshot(
    pool: &PgPool,
    tenant: &str,
    expected_sequence: i64,
    expected_hash: &str,
    export: bool,
) -> Result<Vec<u8>, sqlx::Error> {
    let invalid = || sqlx::Error::Protocol("ledger export checkpoint mismatch".to_owned());
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx).await?;
    let head = sqlx::query("SELECT seq, head_hash FROM core_ledger_heads WHERE tenant_id=$1")
        .bind(tenant).fetch_one(&mut *tx).await?;
    if head.get::<i64, _>("seq") != expected_sequence
        || head.get::<String, _>("head_hash") != expected_hash {
        return Err(invalid());
    }
    let mut output = Vec::new();
    let mut previous = "GENESIS".to_owned();
    let mut sequence = 0i64;
    loop {
        let rows = sqlx::query("SELECT seq,event_id,event_json,prev_hash,record_hash FROM core_ledger_records WHERE tenant_id=$1 AND seq>$2 ORDER BY seq LIMIT 1024")
            .bind(tenant).bind(sequence).fetch_all(&mut *tx).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
        sequence = sequence.checked_add(1).ok_or_else(invalid)?;
        let event: String = row.get("event_json");
        let id: String = row.get("event_id");
        let parsed: serde_json::Value = serde_json::from_str(&event).map_err(|_| invalid())?;
        let hash = hex::encode(Sha256::digest(format!("{previous}\n{event}").as_bytes()));
        if row.get::<i64, _>("seq") != sequence
            || row.get::<String, _>("prev_hash") != previous
            || row.get::<String, _>("record_hash") != hash
            || parsed.get("event_id").and_then(|v| v.as_str()) != Some(id.as_str()) {
            return Err(invalid());
        }
        if export {
            serde_json::to_writer(&mut output, &serde_json::json!({
            "event_json": event, "prev_hash": previous, "record_hash": hash
        })).map_err(|_| invalid())?;
            output.push(b'\n');
        }
        previous = hash;
        }
    }
    if sequence != expected_sequence || previous != expected_hash {
        return Err(invalid());
    }
    tx.commit().await?;
    Ok(output)
}
