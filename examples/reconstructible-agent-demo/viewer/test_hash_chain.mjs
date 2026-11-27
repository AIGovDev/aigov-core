import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";

const html = await readFile(new URL("./index.html", import.meta.url), "utf8");
const start = html.indexOf("    function hex(bytes)");
const end = html.indexOf("    function renderReasons(", start);
assert.notEqual(start, -1, "viewer hash functions must exist");
assert.notEqual(end, -1, "viewer hash functions must end before rendering code");
const source = `const MAX_ROWS = 5000;\n${html.slice(start, end)}\nreturn verifyHashChain;`;
const makeVerifier = new Function("crypto", "TextEncoder", "Uint8Array", source);
const verifyHashChain = makeVerifier(webcrypto, TextEncoder, Uint8Array);

const eventJson = JSON.stringify({ event_type: "run_started", event_id: "demo-1" });
const recordHash = createHash("sha256")
  .update(`GENESIS\n${eventJson}`, "utf8")
  .digest("hex");
const record = { prev_hash: "GENESIS", event_json: eventJson, record_hash: recordHash };

const valid = await verifyHashChain([record], recordHash);
assert.equal(valid.ok, true, valid.message);

const tampered = await verifyHashChain(
  [{ ...record, event_json: JSON.stringify({ event_type: "tampered" }) }],
  recordHash,
);
assert.equal(tampered.ok, false, "changed event JSON must fail the hash check");

const brokenLink = await verifyHashChain(
  [{ ...record, prev_hash: "0".repeat(64) }],
  recordHash,
);
assert.equal(brokenLink.ok, false, "a wrong genesis link must fail the chain check");

console.log("Replay viewer hash-chain tests passed.");
