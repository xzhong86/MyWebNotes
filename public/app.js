const unlockCard = document.getElementById("unlock-card");
const noteCard = document.getElementById("note-card");
const accessKeyInput = document.getElementById("access-key");
const unlockBtn = document.getElementById("unlock-btn");
const unlockStatus = document.getElementById("unlock-status");
const noteStatus = document.getElementById("note-status");
const refreshBtn = document.getElementById("refresh-btn");
const lockBtn = document.getElementById("lock-btn");
const currentUserEl = document.getElementById("current-user");
const createNoteBtn = document.getElementById("create-note-btn");
const notesStreamEl = document.getElementById("notes-stream");

const enc = new TextEncoder();
const dec = new TextDecoder();
const ACCESS_KEY_STORAGE = "ssn_access_key_v1";

let config = null;
let authCryptoKey = null;
let encCryptoKey = null;
let unlocked = false;
let currentUser = null;
let notes = [];
let activeEditNoteId = null;

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
    localStorage.setItem(ACCESS_KEY_STORAGE, accessKey);
    unlocked = true;
    setStatus(unlockStatus, `解锁成功，欢迎 ${currentUser.username}。`, false, true);
    unlockCard.classList.add("hidden");
    noteCard.classList.remove("hidden");
    await loadNotes();
  } catch (error) {
    setStatus(unlockStatus, `解锁失败: ${error.message}`, true);
  }
});

accessKeyInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    unlockBtn.click();
  }
});

createNoteBtn.addEventListener("click", async () => {
  if (!unlocked) return;
  try {
    setStatus(noteStatus, "正在创建便签...");
    const payload = await authedPost("/api/notes/create", {});
    await loadNotes(payload.note.id);
    setStatus(noteStatus, "已创建新便签。", false, true);
  } catch (error) {
    setStatus(noteStatus, `创建失败: ${error.message}`, true);
  }
});

refreshBtn.addEventListener("click", async () => {
  if (!unlocked) return;
  await loadNotes(activeEditNoteId);
});

lockBtn.addEventListener("click", async () => {
  try {
    await authedPost("/api/logout", {}, { useSignature: false });
  } catch {
    // ignore logout failure and continue local lock
  }
  unlocked = false;
  authCryptoKey = null;
  encCryptoKey = null;
  currentUser = null;
  notes = [];
  activeEditNoteId = null;
  currentUserEl.textContent = "-";
  accessKeyInput.value = "";
  localStorage.removeItem(ACCESS_KEY_STORAGE);
  notesStreamEl.innerHTML = "";
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
  await tryAutoLogin();
}

async function tryAutoLogin() {
  const savedKey = localStorage.getItem(ACCESS_KEY_STORAGE);
  if (!savedKey) {
    return;
  }
  try {
    const me = await deriveKeys(savedKey);
    currentUser = me.user;
    currentUserEl.textContent = currentUser.username;
    unlocked = true;
    unlockCard.classList.add("hidden");
    noteCard.classList.remove("hidden");
    accessKeyInput.value = "";
    setStatus(unlockStatus, `已自动登录 ${currentUser.username}。`, false, true);
    await loadNotes();
  } catch {
    localStorage.removeItem(ACCESS_KEY_STORAGE);
    authCryptoKey = null;
    encCryptoKey = null;
    setStatus(unlockStatus, "自动登录已失效，请重新输入访问密钥。");
  }
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

async function loadNotes(preferredEditId = null) {
  try {
    setStatus(noteStatus, "拉取便签列表...");
    const payload = await authedPost("/api/notes/list", {});
    const metas = Array.isArray(payload.notes) ? payload.notes : [];

    const detailResponses = await Promise.all(
      metas.map((meta) => authedPost("/api/notes/get", { noteId: meta.id }))
    );

    const loaded = [];
    for (let i = 0; i < detailResponses.length; i += 1) {
      const note = detailResponses[i].note;
      const plaintext = note.ciphertext
        ? await decryptText({ ciphertext: note.ciphertext, iv: note.iv })
        : "";
      loaded.push({ ...note, plaintext });
    }

    notes = loaded.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    if (notes.length === 0) {
      activeEditNoteId = null;
      notesStreamEl.innerHTML = "";
      setStatus(noteStatus, "当前没有便签，请先点击“新增”。");
      return;
    }

    const canUsePreferred = notes.some((n) => n.id === preferredEditId);
    if (canUsePreferred) {
      activeEditNoteId = preferredEditId;
    } else if (!activeEditNoteId || !notes.some((n) => n.id === activeEditNoteId)) {
      activeEditNoteId = notes[0].id;
    }

    renderNotes();
    setStatus(noteStatus, `已同步 ${notes.length} 条便签。`, false, true);
  } catch (error) {
    setStatus(noteStatus, `同步失败: ${error.message}`, true);
  }
}

function renderNotes() {
  notesStreamEl.innerHTML = "";

  for (let i = 0; i < notes.length; i += 1) {
    const note = notes[i];
    const isEditing = note.id === activeEditNoteId;

    const card = document.createElement("article");
    card.className = `note-card ${isEditing ? "editing" : ""}`;

    const footer = document.createElement("div");
    footer.className = "note-card-footer";
    footer.innerHTML = `<div>
      <p class="note-meta">创建: ${formatTs(note.createdAt)} | 修改: ${formatTs(note.updatedAt)}</p>
    </div>`;

    const actions = document.createElement("div");
    actions.className = "note-actions";

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.textContent = isEditing ? "编辑中" : "编辑";
    editBtn.disabled = isEditing;
    editBtn.addEventListener("click", () => {
      activeEditNoteId = note.id;
      renderNotes();
      setStatus(noteStatus, `已切换到便签 ${i + 1} 的编辑模式。`, false, true);
    });

    const saveBtn = document.createElement("button");
    saveBtn.type = "button";
    saveBtn.textContent = "保存";
    saveBtn.disabled = !isEditing;

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.textContent = "删除";
    deleteBtn.className = "danger";

    actions.appendChild(editBtn);
    actions.appendChild(saveBtn);
    actions.appendChild(deleteBtn);
    const textarea = document.createElement("textarea");
    textarea.className = "note-editor";
    textarea.value = note.plaintext;
    textarea.disabled = !isEditing;
    textarea.addEventListener("input", () => {
      note.plaintext = textarea.value;
      autoResize(textarea);
    });

    saveBtn.addEventListener("click", async () => {
      await saveNote(note.id, textarea.value);
    });

    deleteBtn.addEventListener("click", async () => {
      const confirmed = window.confirm("确认删除此便签？此操作不可恢复。");
      if (!confirmed) return;
      try {
        await authedPost("/api/notes/delete", { noteId: note.id });
        await loadNotes();
        setStatus(noteStatus, "便签已删除。", false, true);
      } catch (error) {
        setStatus(noteStatus, `删除失败: ${error.message}`, true);
      }
    });

    footer.appendChild(actions);
    card.appendChild(textarea);
    card.appendChild(footer);
    notesStreamEl.appendChild(card);

    autoResize(textarea);
  }
}

async function saveNote(noteId, plaintext) {
  try {
    setStatus(noteStatus, "保存中...");
    const encrypted = await encryptText(plaintext);
    const payload = await authedPost("/api/notes/put", {
      noteId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      updatedAt: Date.now()
    });

    const idx = notes.findIndex((x) => x.id === noteId);
    if (idx >= 0) {
      notes[idx] = { ...payload.note, plaintext };
    }
    await loadNotes(noteId);
    setStatus(noteStatus, "保存成功。", false, true);
  } catch (error) {
    setStatus(noteStatus, `保存失败: ${error.message}`, true);
  }
}

function autoResize(textarea) {
  textarea.style.height = "auto";
  const next = Math.max(120, textarea.scrollHeight);
  textarea.style.height = `${next}px`;
}

async function authedPost(path, body, options = {}) {
  const bodyStr = JSON.stringify(body ?? {});
  const headers = {
    "Content-Type": "application/json"
  };
  const useSignature = options.useSignature ?? Boolean(authCryptoKey);
  if (useSignature) {
    const bodyHash = await sha256Hex(bodyStr);
    const timestamp = String(Date.now());
    const nonce = crypto.randomUUID();
    const canonical = `${timestamp}\n${nonce}\nPOST\n${path}\n${bodyHash}`;
    const signature = await hmacHex(canonical);
    headers["X-Timestamp"] = timestamp;
    headers["X-Nonce"] = nonce;
    headers["X-Signature"] = signature;
  }

  const resp = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers,
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

function formatTs(ts) {
  if (!ts) return "-";
  return new Date(ts).toLocaleString();
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
