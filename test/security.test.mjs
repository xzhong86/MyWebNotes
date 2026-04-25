import test from "node:test";
import assert from "node:assert/strict";
import {
  buildCanonicalString,
  computeBodyHash,
  deriveAuthKey,
  signRequest,
  verifySignature
} from "../lib/security.mjs";

test("signature should verify for matching payload", () => {
  const authKey = deriveAuthKey("sample-access-key");
  const body = JSON.stringify({ hello: "world" });
  const canonical = buildCanonicalString({
    timestamp: "1700000000000",
    nonce: "nonce-1",
    method: "POST",
    path: "/api/note/get",
    bodyHash: computeBodyHash(body)
  });
  const signed = signRequest(authKey, canonical);
  assert.equal(verifySignature(signed, signed), true);
});

test("signature should fail when payload changes", () => {
  const authKey = deriveAuthKey("sample-access-key");
  const canonicalA = buildCanonicalString({
    timestamp: "1700000000000",
    nonce: "nonce-1",
    method: "POST",
    path: "/api/note/get",
    bodyHash: computeBodyHash("{}")
  });
  const canonicalB = buildCanonicalString({
    timestamp: "1700000000000",
    nonce: "nonce-1",
    method: "POST",
    path: "/api/note/get",
    bodyHash: computeBodyHash('{"x":1}')
  });
  const signedA = signRequest(authKey, canonicalA);
  const signedB = signRequest(authKey, canonicalB);
  assert.equal(verifySignature(signedA, signedB), false);
});
