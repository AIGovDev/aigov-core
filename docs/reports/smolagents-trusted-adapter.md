# smolagents trusted execution bridge

## Evaluation gate
Bridge delegates to the existing agent actor and trusted executor. Mock regression tests cover refusals and approval requests. Real smolagents compatibility and signed execution integration remain pending.

## Human approval gate
Maintainer review required; approval pending.

## Boundary
Expose only a host-owned wrapper to a ToolCallingAgent. Never expose the performer, approver credentials or approval identifiers to model-controlled arguments. This is not a sandbox for CodeAgent or arbitrary Python execution. Results currently expose execution status only. The existing executor verifies signatures, argument bindings and replay state.
