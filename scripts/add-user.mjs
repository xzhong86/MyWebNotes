import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, "..");
const CONFIG_DIR = path.join(ROOT_DIR, "config");
const USERS_FILE = process.env.USERS_FILE_PATH ?? path.join(CONFIG_DIR, "users.json");

const args = parseArgs(process.argv.slice(2));
const username = args.username;
const accessKey = args.accessKey || randomBytes(24).toString("hex");

if (!username) {
  console.error("Usage: node scripts/add-user.mjs -u <name> [-k <key>]");
  console.error("Also supported: --username / --access-key");
  process.exit(1);
}

if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) {
  console.error("username must match /^[a-zA-Z0-9_-]{3,32}$/");
  process.exit(1);
}

fs.mkdirSync(CONFIG_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(
    USERS_FILE,
    JSON.stringify({ version: 1, users: [] }, null, 2),
    { encoding: "utf8", mode: 0o600 }
  );
}

const usersDb = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
if (!usersDb || typeof usersDb !== "object" || !Array.isArray(usersDb.users)) {
  console.error("Invalid users.json format");
  process.exit(1);
}

const normalized = username.toLowerCase();
if (usersDb.users.some((x) => String(x.username || "").toLowerCase() === normalized)) {
  console.error(`User '${username}' already exists`);
  process.exit(1);
}

if (usersDb.users.some((x) => x.accessKey === accessKey)) {
  console.error("This access key already belongs to another user");
  process.exit(1);
}

const user = {
  id: randomBytes(8).toString("hex"),
  username,
  accessKey,
  createdAt: Date.now()
};
usersDb.users.push(user);

fs.writeFileSync(USERS_FILE, JSON.stringify(usersDb, null, 2), { encoding: "utf8", mode: 0o600 });

console.log(`Added user: ${username}`);
console.log(`User ID: ${user.id}`);
console.log(`Access key (save now): ${accessKey}`);
console.log(`Users file: ${USERS_FILE}`);

function parseArgs(argv) {
  const out = { username: "", accessKey: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--username" || token === "-u") {
      out.username = argv[i + 1] ?? "";
      i += 1;
      continue;
    }
    if (token === "--access-key" || token === "-k") {
      out.accessKey = argv[i + 1] ?? "";
      i += 1;
      continue;
    }
  }
  return out;
}
