import unittest
from nacl.signing import SigningKey
from checkpoint_attestation import canonical_statement, verify_attestation

class AttestationTests(unittest.TestCase):
    def test_scope_and_integrity(self):
        key = SigningKey.generate()
        statement = {"schema":"aigov.checkpoint.v1","issuer":"org-a","tenant":"tenant-a","count":3,"head":"a"*64}
        signature = key.sign(canonical_statement(statement)).signature.hex()
        trust = {("org-a","tenant-a"): key.verify_key.encode().hex()}
        def check(value=statement, sig=signature, anchors=trust, tenant="tenant-a", floor=3):
            return verify_attestation(value,sig,anchors,expected_issuer="org-a",expected_tenant=tenant,minimum_count=floor)
        self.assertTrue(check())
        self.assertFalse(check(dict(statement,head="b"*64)))
        self.assertFalse(check(tenant="tenant-b"))
        self.assertFalse(check(floor=4))
        self.assertFalse(check(anchors={}))
        self.assertFalse(check(sig="00"*64))
        self.assertFalse(check(dict(statement,count=True)))

    def test_signed_chain_and_prior_anchor(self):
        import hashlib
        import io
        import json
        from checkpoint_attestation import verify_attested_ledger
        key = SigningKey.generate()
        trust = {("org-a","tenant-a"): key.verify_key.encode().hex()}
        event = '{"event_id":"a"}'
        head = hashlib.sha256(("GENESIS\n"+event).encode()).hexdigest()
        line = (json.dumps({"event_json":event,"prev_hash":"GENESIS","record_hash":head})+"\n").encode()
        statement = {"schema":"aigov.checkpoint.v1","issuer":"org-a","tenant":"tenant-a","count":1,"head":head}
        sig = key.sign(canonical_statement(statement)).signature.hex()
        def check(data=line, prior=head):
            return verify_attested_ledger(io.BytesIO(data),statement,sig,trust,expected_issuer="org-a",expected_tenant="tenant-a",previous_count=1,previous_head=prior)
        self.assertTrue(check()["verified"])
        with self.assertRaises(ValueError):
            check(prior="b"*64)
        with self.assertRaises(ValueError):
            check(data=b"")
