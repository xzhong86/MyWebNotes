const unlockCard = document.getElementById("unlock-card");
const noteCard = document.getElementById("note-card");
const accessKeyInput = document.getElementById("access-key");
const unlockBtn = document.getElementById("unlock-btn");
const unlockStatus = document.getElementById("unlock-status");
const noteStatus = document.getElementById("note-status");
const noteText = document.getElementById("note-text");
const saveBtn = document.getElementById("save-btn");
const refreshBtn = document.getElementById("refresh-btn");
const lockBtn = document.getElementById("lock-btn");
const currentUserEl = document.getElementById("current-user");

const enc = new TextEncoder();
const dec = new TextDecoder();

let config = null;
let authCryptoKey = null;
let encCryptoKey = null;
let unlocked = false;
let currentUser = null;

init().catch((error) => {
  setStatus(unlockStatus, `初始化失败: ${error.message}`, true);
});

unlockBtn.addEventListener("click", async () => {
  const accessKey = accessKeyInput.value.trim();
  if (!accessKey) {
    setStatus(unlockStatus, "请输入访问密钥。", true);
    return;
  }

  try {
    const me = await deriveKeys(accessKey);
    currentUser = me.user;
    currentUserEl.textContent = currentUser.username;
    unlocked = true;
    setStatus(unlockStatus, `解锁成功，欢迎 ${currentUser.username}。`, false, true);
    unlockCard.classList.add("hidden");
    noteCard.classList.remove("hidden");
    await loadNote();
  } catch (error) {
    setStatus(unlockStatus, `解锁失败: ${error.message}`, true);
  }
});

saveBtn.addEventListener("click", async () => {
  if (!unlocked) return;
  try {
    setStatus(noteStatus, "保存中...");
    const encrypted = await encryptText(noteText.value);
    await authedPost("/api/note/put", {
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      updatedAt: Date.now()
    });
    setStatus(noteStatus, "保存成功。", false, true);
  } catch (error) {
    setStatus(noteStatus, `保存失败: ${error.message}`, true);
  }
});

refreshBtn.addEventListener("click", async () => {
  if (!unlocked) return;
  await loadNote();
});

lockBtn.addEventListener("click", () => {
  unlocked = false;
  authCryptoKey = null;
  encCryptoKey = null;
  currentUser = null;
  currentUserEl.textContent = "-";
  noteText.value = "";
  accessKeyInput.value = "";
  noteCard.classList.add("hidden");
  unlockCard.classList.remove("hidden");
  setStatus(unlockStatus, "已锁定。");
  setStatus(noteStatus, "");
});

async function init() {
  const resp = await fetch("/api/config");
  if (!resp.ok) {
    throw new Error("无法读取服务器配置");
  }
  config = await resp.json();
  setStatus(unlockStatus, "输入访问密钥后可读取便签。");
}

async function deriveKeys(accessKey) {
  const sourceKey = await crypto.subtle.importKey("raw", enc.encode(accessKey), "HKDF", false, [
    "deriveKey"
  ]);
  const salt = enc.encode(config.kdfSalt);

  authCryptoKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: enc.encode(config.authInfo)
    },
    sourceKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"]
  );

  encCryptoKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: enc.encode(config.encInfo)
    },
    sourceKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  return authedPost("/api/me", {});
}

async function loadNote() {
  try {
    setStatus(noteStatus, "拉取最新内容...");
    const payload = await authedPost("/api/note/get", {});
    if (!payload.note?.ciphertext) {
      noteText.value = "";
      setStatus(noteStatus, "当前还没有保存内容。");
      return;
    }
    const plaintext = await decryptText({
      ciphertext: payload.note.ciphertext,
      iv: payload.note.iv
    });
    noteText.value = plaintext;
    const date = new Date(payload.note.updatedAt || 0);
    setStatus(noteStatus, `已同步，更新时间: ${date.toLocaleString()}`, false, true);
  } catch (error) {
    setStatus(noteStatus, `同步失败: ${error.message}`, true);
  }
}

async function authedPost(path, body) {
  const bodyStr = JSON.stringify(body ?? {});
  const bodyHash = await sha256Hex(bodyStr);
  const timestamp = String(Date.now());
  const nonce = crypto.randomUUID();
  const canonical = `${timestamp}\n${nonce}\nPOST\n${path}\n${bodyHash}`;
  const signature = await hmacHex(canonical);

  const resp = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Timestamp": timestamp,
      "X-Nonce": nonce,
      "X-Signature": signature
    },
    body: bodyStr
  });

  const payload = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(payload.error || "请求失败");
  }
  return payload;
}

async function encryptText(text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plainBytes = enc.encode(text);
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encCryptoKey,
    plainBytes
  );
  return {
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(cipherBuffer))
  };
}

async function decryptText({ iv, ciphertext }) {
  const ivBytes = fromBase64(iv);
  const cipherBytes = fromBase64(ciphertext);
  const plainBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes },
    encCryptoKey,
    cipherBytes
  );
  return dec.decode(plainBuffer);
}

async function hmacHex(message) {
  const signature = await crypto.subtle.sign("HMAC", authCryptoKey, enc.encode(message));
  return toHex(new Uint8Array(signature));
}

async function sha256Hex(message) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(message));
  return toHex(new Uint8Array(digest));
}

function toHex(bytes) {
  return [...bytes].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function toBase64(bytes) {
  let raw = "";
  for (const b of bytes) {
    raw += String.fromCharCode(b);
  }
  return btoa(raw);
}

function fromBase64(value) {
  const raw = atob(value);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    out[i] = raw.charCodeAt(i);
  }
  return out;
}

function setStatus(el, message, isError = false, isSuccess = false) {
  el.textContent = message;
  el.classList.remove("error", "success");
  if (isError) {
    el.classList.add("error");
  } else if (isSuccess) {
    el.classList.add("success");
  }
}
