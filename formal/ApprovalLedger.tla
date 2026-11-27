---- MODULE ApprovalLedger ----
EXTENDS Naturals, FiniteSets
CONSTANTS Tenants, Approvals, Decisions
VARIABLES issued, consumed, ledger
vars == <<issued, consumed, ledger>>
Init == /\ issued = {}
        /\ consumed = {}
        /\ ledger = {}
Issue(t,a) == /\ <<t,a>> \notin issued
              /\ issued' = issued \cup {<<t,a>>}
              /\ UNCHANGED <<consumed,ledger>>
Commit(t,a,d) ==
    /\ <<t,a>> \in issued
    /\ <<t,a>> \notin consumed
    /\ \A x \in Approvals: <<t,x,d>> \notin ledger
    /\ consumed' = consumed \cup {<<t,a>>}
    /\ ledger' = ledger \cup {<<t,a,d>>}
    /\ UNCHANGED issued
Next == \/ \E t \in Tenants, a \in Approvals: Issue(t,a)
        \/ \E t \in Tenants, a \in Approvals, d \in Decisions: Commit(t,a,d)
Spec == Init /\ [][Next]_vars
TypeOK == /\ issued \subseteq (Tenants \X Approvals)
          /\ consumed \subseteq (Tenants \X Approvals)
          /\ ledger \subseteq (Tenants \X Approvals \X Decisions)
Authorized == \A t \in Tenants, a \in Approvals, d \in Decisions:
    <<t,a,d>> \in ledger => <<t,a>> \in issued
SingleUse == \A t \in Tenants, a \in Approvals:
    Cardinality({d \in Decisions: <<t,a,d>> \in ledger}) <= 1
Atomic == \A t \in Tenants, a \in Approvals:
    (<<t,a>> \in consumed) <=> (\E d \in Decisions: <<t,a,d>> \in ledger)
UniqueDecision == \A t \in Tenants, d \in Decisions:
    Cardinality({a \in Approvals: <<t,a,d>> \in ledger}) <= 1
====
