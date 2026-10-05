#!/usr/bin/env bash
# Beat D — live, one command, still offline. Renders the delegation graph
# from the same export file used in Beat C — nothing new is read from the
# server (it's still dead).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

EXPORT="examples/talk-demo/.exports/export.json"
if [ ! -f "$EXPORT" ]; then
  echo "No export found at $EXPORT — run 04-export-run.sh first." >&2
  exit 1
fi

(cd rust && cargo run --quiet --bin lineage_graph_once --locked -- --mermaid "../$EXPORT")
