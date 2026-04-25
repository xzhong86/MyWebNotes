import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, "..");
const CONFIG_DIR = path.join(ROOT_DIR, "config");
const DATA_DIR = path.join(ROOT_DIR, "data");
const USERS_FILE = process.env.USERS_FILE_PATH ?? path.join(CONFIG_DIR, "users.json");
const NOTES_FILE = process.env.NOTES_FILE_PATH ?? path.join(DATA_DIR, "notes.json");

const args = parseArgs(process.argv.slice(2));
const username = args.username;

if (!username) {
  console.error("Usage: node scripts/del-user.mjs -u <name>");
  console.error("Also supported: --username");
  process.exit(1);
}

if (!fs.existsSync(USERS_FILE)) {
  console.error(`users file not found: ${USERS_FILE}`);
  process.exit(1);
}

const usersDb = readJsonFile(USERS_FILE, "users.json");
if (!Array.isArray(usersDb.users)) {
  console.error("Invalid users.json format");
  process.exit(1);
}

const normalized = username.toLowerCase();
const index = usersDb.users.findIndex((u) => String(u.username || "").toLowerCase() === normalized);
if (index < 0) {
  console.error(`User '${username}' not found`);
  process.exit(1);
}

const target = usersDb.users[index];
const hasNotes = hasUserNotes(target.id);

const rl = readline.createInterface({ input, output });
try {
  console.log(`About to delete user '${target.username}' (id=${target.id}).`);
  if (hasNotes) {
    console.log("This will also delete this user's notes from notes.json.");
  }
  const answer = await rl.question(`Type DELETE to confirm deleting '${target.username}': `);
  if (answer.trim() !== "DELETE") {
    console.log("Aborted.");
    process.exit(1);
  }
} finally {
  rl.close();
}

usersDb.users.splice(index, 1);
writeJsonFile(USERS_FILE, usersDb);

if (fs.existsSync(NOTES_FILE)) {
  const notesDb = readJsonFile(NOTES_FILE, "notes.json");
  if (!notesDb.byUser || typeof notesDb.byUser !== "object") {
    console.error("Invalid notes.json format");
    process.exit(1);
  }
  if (Object.prototype.hasOwnProperty.call(notesDb.byUser, target.id)) {
    delete notesDb.byUser[target.id];
    writeJsonFile(NOTES_FILE, notesDb);
  }
}

console.log(`Deleted user: ${target.username}`);
console.log(`Users file: ${USERS_FILE}`);
console.log(`Notes file: ${NOTES_FILE}`);

function hasUserNotes(userId) {
  if (!fs.existsSync(NOTES_FILE)) {
    return false;
  }
  const notesDb = readJsonFile(NOTES_FILE, "notes.json");
  return Boolean(notesDb.byUser && Object.prototype.hasOwnProperty.call(notesDb.byUser, userId));
}

function readJsonFile(filePath, label) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    console.error(`Failed to parse ${label}: ${filePath}`);
    process.exit(1);
  }
}

function writeJsonFile(filePath, payload) {
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), {
    encoding: "utf8",
    mode: 0o600
  });
}

function parseArgs(argv) {
  const out = { username: "" };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--username" || token === "-u") {
      out.username = argv[i + 1] ?? "";
      i += 1;
    }
  }
  return out;
}
