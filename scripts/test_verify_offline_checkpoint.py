import hashlib
import io
import json
import unittest
from verify_offline_checkpoint import verify

class CheckpointTests(unittest.TestCase):
    def test_checkpoint(self):
        event = '{"event_id":"a"}'
        head = hashlib.sha256(("GENESIS\n" + event).encode()).hexdigest()
        line = (json.dumps({"event_json":event,"prev_hash":"GENESIS","record_hash":head})+"\n").encode()
        self.assertTrue(verify(io.BytesIO(line),1,head)["verified"])
        for bad in (line[:-1], b"", line+line, line.replace(b'GENESIS',b'ALTERED')):
            with self.assertRaises(ValueError):
                verify(io.BytesIO(bad),1,head)
        with self.assertRaises(ValueError):
            verify(io.BytesIO(line),1,"0"*64)
