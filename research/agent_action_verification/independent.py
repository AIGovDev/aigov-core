"""Independent receipt and observed-state verifier."""
import hashlib,hmac,json
def canonical(x): return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def digest(x): return hashlib.sha256(canonical(x)).hexdigest()
def signature(key,x): return hmac.new(key,canonical(x),hashlib.sha256).hexdigest()
def verify(receipts,observation,keys):
    if [r.get('stage') for r in receipts]!=['proposal','approval','execution']: return False,'sequence'
    prev='0'*64
    for r in receipts:
        key=keys.get(r['stage']); body={k:v for k,v in r.items() if k!='signature'}
        if not key or not hmac.compare_digest(signature(key,body),r.get('signature','')): return False,'signature'
        if r['previous']!=prev: return False,'chain'
        prev=digest(r)
    proposal,approval,execution=[r['data'] for r in receipts]
    if approval.get('approved') is not True or approval.get('proposal_digest')!=digest(proposal): return False,'approval'
    if execution.get('proposal_digest')!=digest(proposal): return False,'execution_binding'
    if execution.get('operation')!=proposal: return False,'operation_changed'
    if not observation or observation.get('source')!='sandbox_state_reader': return False,'untrusted_observation'
    body={k:v for k,v in observation.items() if k!='signature'}
    key=keys.get('observer')
    if not key or not hmac.compare_digest(signature(key,body),observation.get('signature','')): return False,'observation_signature'
    if observation.get('execution_digest')!=digest(execution): return False,'observation_binding'
    if observation.get('state')!=proposal['value']: return False,'state_mismatch'
    return True,'verified'
