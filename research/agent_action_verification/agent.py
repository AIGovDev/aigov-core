"""Deterministic sandbox agent; no LLM or external API."""
from independent import digest,signature
class Sandbox:
    def __init__(self): self.state={}
    def execute(self,operation): self.state[operation['target']]=operation['value']
    def read(self,target): return self.state.get(target)
def receipt(stage,data,previous,key):
    body={'stage':stage,'data':data,'previous':previous}
    return {**body,'signature':signature(key,body)}
def run_agent(sandbox,operation,keys,mutation=None,observer_tamper=False):
    p=receipt('proposal',operation,'0'*64,keys['proposal'])
    a=receipt('approval',{'approved':True,'proposal_digest':digest(operation)},digest(p),keys['approval'])
    applied=dict(operation)
    if mutation=='post_approval_change': applied['value']='2027-07-02'
    execution={'operation':applied,'proposal_digest':digest(operation)}
    e=receipt('execution',execution,digest(a),keys['execution'])
    sandbox.execute(applied)
    body={'source':'sandbox_state_reader','execution_digest':digest(execution),'state':sandbox.read(operation['target'])}
    observation={**body,'signature':signature(keys['observer'],body)}
    if observer_tamper: observation['state']='forged'
    return [p,a,e],observation
