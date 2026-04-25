import { createHash, createHmac, hkdfSync, timingSafeEqual } from "node:crypto";

export const KDF_SALT = "notes-sync-salt-v1";
export const AUTH_INFO = "auth-sign-v1";
export const ENC_INFO = "note-encryption-v1";

export function deriveKeyMaterial(accessKey, info) {
  return hkdfSync(
    "sha256",
    Buffer.from(accessKey, "utf8"),
    Buffer.from(KDF_SALT, "utf8"),
    Buffer.from(info, "utf8"),
    32
  );
}

export function deriveAuthKey(accessKey) {
  return deriveKeyMaterial(accessKey, AUTH_INFO);
}

export function computeBodyHash(rawBody) {
  return createHash("sha256").update(rawBody ?? "", "utf8").digest("hex");
}

export function buildCanonicalString({
  timestamp,
  nonce,
  method,
  path,
  bodyHash
}) {
  return `${timestamp}\n${nonce}\n${method.toUpperCase()}\n${path}\n${bodyHash}`;
}

export function signRequest(authKey, canonicalString) {
  return createHmac("sha256", authKey).update(canonicalString, "utf8").digest("hex");
}

export function verifySignature(expectedHex, receivedHex) {
  const expected = Buffer.from(expectedHex, "hex");
  const received = Buffer.from(receivedHex, "hex");
  if (expected.length !== received.length) {
    return false;
  }
  return timingSafeEqual(expected, received);
}
