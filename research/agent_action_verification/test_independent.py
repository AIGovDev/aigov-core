import unittest
from agent import Sandbox,run_agent
from independent import verify
KEYS={x:(x+'-test-secret').encode() for x in ('proposal','approval','execution','observer')}
OP={'target':'tender-1','value':'2027-06-30'}
class TestIndependent(unittest.TestCase):
 def test_authorized(self):
  self.assertEqual(verify(*run_agent(Sandbox(),OP,KEYS),KEYS),(True,'verified'))
 def test_changed_after_approval(self):
  self.assertEqual(verify(*run_agent(Sandbox(),OP,KEYS,mutation='post_approval_change'),KEYS)[1],'operation_changed')
 def test_tampered_observation(self):
  self.assertEqual(verify(*run_agent(Sandbox(),OP,KEYS,observer_tamper=True),KEYS)[1],'observation_signature')
 def test_missing_receipt(self):
  r,o=run_agent(Sandbox(),OP,KEYS); self.assertEqual(verify(r[:2],o,KEYS)[1],'sequence')
 def test_bad_key(self):
  r,o=run_agent(Sandbox(),OP,KEYS); k=dict(KEYS); k['approval']=b'wrong'; self.assertEqual(verify(r,o,k)[1],'signature')
 def test_replay(self):
  r,o=run_agent(Sandbox(),OP,KEYS); self.assertEqual(verify(r+[r[-1]],o,KEYS)[1],'sequence')
 def test_state_divergence(self):
  r,o=run_agent(Sandbox(),OP,KEYS); o['state']='wrong'; self.assertFalse(verify(r,o,KEYS)[0])
 def test_missing_observation(self):
  r,o=run_agent(Sandbox(),OP,KEYS); self.assertEqual(verify(r,None,KEYS)[1],'untrusted_observation')
if __name__=='__main__': unittest.main()
