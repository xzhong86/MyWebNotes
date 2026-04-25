import { createServer, STATUS_CODES } from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  AUTH_INFO,
  ENC_INFO,
  KDF_SALT,
  buildCanonicalString,
  computeBodyHash,
  deriveAuthKey,
  signRequest,
  verifySignature
} from "./lib/security.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, "data");
const PUBLIC_DIR = path.join(__dirname, "public");
const CONFIG_DIR = path.join(__dirname, "config");
const USERS_FILE = process.env.USERS_FILE_PATH ?? path.join(CONFIG_DIR, "users.json");
const NOTES_FILE = path.join(DATA_DIR, "notes.json");

const HOST = process.env.HOST ?? "0.0.0.0";
const PORT = Number(process.env.PORT ?? 8080);
const MAX_BODY_SIZE = 1024 * 1024;
const MAX_SKEW_MS = 90_000;
const NONCE_TTL_MS = 120_000;

const nonceCache = new Map();

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8"
};

ensureStorageFiles();

console.log(`Users file: ${USERS_FILE}`);
console.log(`Server listening on http://${HOST}:${PORT}`);

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const pathname = decodeURIComponent(url.pathname);

    if (pathname.startsWith("/api/")) {
      await handleApi(req, res, pathname);
      return;
    }

    if (req.method !== "GET" && req.method !== "HEAD") {
      sendJson(res, 405, { error: "Method not allowed" });
      return;
    }

    await serveStatic(res, pathname);
  } catch (error) {
    sendJson(res, 500, { error: "Internal server error", detail: String(error?.message ?? error) });
  }
});

server.listen(PORT, HOST);

async function handleApi(req, res, pathname) {
  if (pathname === "/api/config" && req.method === "GET") {
    sendJson(res, 200, {
      kdfSalt: KDF_SALT,
      authInfo: AUTH_INFO,
      encInfo: ENC_INFO,
      maxSkewMs: MAX_SKEW_MS,
      serverTime: Date.now()
    });
    return;
  }

  if (pathname === "/api/me" && req.method === "POST") {
    const rawBody = await readBody(req);
    const auth = authorizeRequest(req, pathname, rawBody);
    if (!auth) {
      sendJson(res, 401, { error: "Unauthorized" });
      return;
    }
    sendJson(res, 200, {
      user: {
        id: auth.user.id,
        username: auth.user.username
      }
    });
    return;
  }

  if (pathname === "/api/note/get" && req.method === "POST") {
    const rawBody = await readBody(req);
    const auth = authorizeRequest(req, pathname, rawBody);
    if (!auth) {
      sendJson(res, 401, { error: "Unauthorized" });
      return;
    }
    const note = readNoteForUser(auth.user.id);
    sendJson(res, 200, { note });
    return;
  }

  if (pathname === "/api/note/put" && req.method === "POST") {
    const rawBody = await readBody(req);
    const auth = authorizeRequest(req, pathname, rawBody);
    if (!auth) {
      sendJson(res, 401, { error: "Unauthorized" });
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(rawBody || "{}");
    } catch {
      sendJson(res, 400, { error: "Invalid JSON payload" });
      return;
    }

    if (
      typeof parsed.ciphertext !== "string" ||
      typeof parsed.iv !== "string" ||
      typeof parsed.updatedAt !== "number"
    ) {
      sendJson(res, 400, { error: "Missing or invalid fields" });
      return;
    }

    if (parsed.ciphertext.length > 2_000_000 || parsed.iv.length > 128) {
      sendJson(res, 413, { error: "Payload too large" });
      return;
    }

    const current = readNoteForUser(auth.user.id);
    const next = {
      ciphertext: parsed.ciphertext,
      iv: parsed.iv,
      updatedAt: parsed.updatedAt,
      version: current.version + 1
    };

    writeNoteForUser(auth.user.id, next);
    sendJson(res, 200, { note: next });
    return;
  }

  sendJson(res, 404, { error: "Not found" });
}

function ensureStorageFiles() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  if (!fs.existsSync(NOTES_FILE)) {
    fs.writeFileSync(
      NOTES_FILE,
      JSON.stringify({ byUser: {} }, null, 2),
      "utf8"
    );
  }
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(
      USERS_FILE,
      JSON.stringify({ version: 1, users: [] }, null, 2),
      { encoding: "utf8", mode: 0o600 }
    );
  }
}

function authorizeRequest(req, pathname, rawBody) {
  cleanupExpiredNonces();

  const signature = req.headers["x-signature"];
  const timestamp = req.headers["x-timestamp"];
  const nonce = req.headers["x-nonce"];

  if (typeof signature !== "string" || typeof timestamp !== "string" || typeof nonce !== "string") {
    return null;
  }

  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) {
    return null;
  }

  if (Math.abs(Date.now() - ts) > MAX_SKEW_MS) {
    return null;
  }

  if (nonceCache.has(nonce)) {
    return null;
  }

  const bodyHash = computeBodyHash(rawBody);
  const canonical = buildCanonicalString({
    timestamp,
    nonce,
    method: req.method ?? "GET",
    path: pathname,
    bodyHash
  });
  const usersDb = readUsersDb();
  let matchedUser = null;

  for (const user of usersDb.users) {
    if (!isValidAccessKey(user.accessKey)) {
      continue;
    }
    const authKey = deriveAuthKey(user.accessKey);
    const expected = signRequest(authKey, canonical);
    if (verifySignature(expected, signature)) {
      matchedUser = user;
      break;
    }
  }

  if (!matchedUser) {
    return null;
  }

  nonceCache.set(nonce, Date.now() + NONCE_TTL_MS);
  return { user: matchedUser };
}

function readUsersDb() {
  const parsed = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.users)) {
    throw new Error("Invalid users DB format");
  }
  return parsed;
}

function writeUsersDb(usersDb) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(usersDb, null, 2), { encoding: "utf8", mode: 0o600 });
}

function isValidAccessKey(value) {
  return typeof value === "string" && value.length >= 16;
}

function readNotesDb() {
  const parsed = JSON.parse(fs.readFileSync(NOTES_FILE, "utf8"));
  if (!parsed || typeof parsed !== "object" || typeof parsed.byUser !== "object" || parsed.byUser === null) {
    throw new Error("Invalid notes DB format");
  }
  return parsed;
}

function emptyNote() {
  return { ciphertext: "", iv: "", updatedAt: 0, version: 0 };
}

function readNoteForUser(userId) {
  const notesDb = readNotesDb();
  return notesDb.byUser[userId] ?? emptyNote();
}

function writeNoteForUser(userId, note) {
  const notesDb = readNotesDb();
  notesDb.byUser[userId] = note;
  fs.writeFileSync(NOTES_FILE, JSON.stringify(notesDb, null, 2), "utf8");
}

function cleanupExpiredNonces() {
  const now = Date.now();
  for (const [nonce, expiry] of nonceCache.entries()) {
    if (expiry <= now) {
      nonceCache.delete(nonce);
    }
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let data = "";

    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_SIZE) {
        reject(new Error("Request body too large"));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

async function serveStatic(res, pathname) {
  const requested = pathname === "/" ? "/index.html" : pathname;
  const safePath = path.normalize(requested).replace(/^(\.\.[/\\])+/, "");
  const fullPath = path.join(PUBLIC_DIR, safePath);

  if (!fullPath.startsWith(PUBLIC_DIR)) {
    sendJson(res, 403, { error: "Forbidden" });
    return;
  }

  if (!fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) {
    sendJson(res, 404, { error: "Not found" });
    return;
  }

  const ext = path.extname(fullPath);
  const contentType = MIME_TYPES[ext] ?? "application/octet-stream";
  const fileContent = fs.readFileSync(fullPath);
  sendRaw(res, 200, fileContent, contentType);
}

function sendJson(res, statusCode, payload) {
  sendRaw(res, statusCode, Buffer.from(JSON.stringify(payload)), "application/json; charset=utf-8");
}

function sendRaw(res, statusCode, payload, contentType) {
  res.writeHead(statusCode, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(payload),
    "X-Content-Type-Options": "nosniff"
  });
  res.end(payload);
}

process.on("uncaughtException", (error) => {
  console.error("uncaughtException:", error);
  process.exit(1);
});

process.on("unhandledRejection", (error) => {
  console.error("unhandledRejection:", error);
  process.exit(1);
});

server.on("clientError", (err, socket) => {
  const message = `HTTP/1.1 400 ${STATUS_CODES[400]}\r\n\r\n`;
  socket.end(message);
  console.error("clientError:", err.message);
});
