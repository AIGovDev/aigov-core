# Two Core processes on one ledger: negative control and fix

Procedure: start two `aigov_audit` processes on the same `GOVAI_LEDGER_DIR` (ports 18101, 18102, dev mode, an agent principal),
send 200 concurrent `POST /evidence` requests alternating between the two ports (`load.py`), then verify the chain on disk
(`verify_chain.py <ledger file>`).

## Before: `origin/staging` (commit 652714f), release binary, no cross-process lock

    statuses Counter({500: 181, 200: 19})
    records=17 unique_event_ids=16 duplicate_ids=0 chain_violations=9

A later read of the same ledger failed:

    {"error":{"code":"LEDGER_READ_ERROR","message":"ledger corruption before EOF at line 5 (offset 2156): trailing characters at line 1 column 569"},"ok":false}

## After: this branch (commit 16b0191), release binary, `flock` on `<ledger>.lock`

    statuses Counter({200: 200})
    records=200 unique_event_ids=200 duplicate_ids=0 chain_violations=0

The same two-instance duplicate test (one identical event id sent to both instances, 20 trials) gave exactly one 200 and one 409 in
every trial. The automated version is `python/tests/test_distributed_core_ledger.py`.

Notes: the `load.py` and `verify_chain.py` files are the scripts used. `load.py` is a demonstration script with the port and key
constants at its top; it is not part of the test suite.
