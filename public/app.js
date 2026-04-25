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
const createNoteBtn = document.getElementById("create-note-btn");
const deleteNoteBtn = document.getElementById("delete-note-btn");
const noteListEl = document.getElementById("note-list");
const noteTitleEl = document.getElementById("note-title");
const noteMetaEl = document.getElementById("note-meta");

const enc = new TextEncoder();
const dec = new TextDecoder();

let config = null;
let authCryptoKey = null;
let encCryptoKey = null;
let unlocked = false;
let currentUser = null;
let notesMeta = [];
let activeNote = null;
let activeNoteId = null;

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
    await loadNotesAndSelect();
  } catch (error) {
    setStatus(unlockStatus, `解锁失败: ${error.message}`, true);
  }
});

createNoteBtn.addEventListener("click", async () => {
  if (!unlocked) return;
  try {
    setStatus(noteStatus, "正在创建便签...");
    const payload = await authedPost("/api/notes/create", {});
    await loadNotesAndSelect(payload.note.id);
    setStatus(noteStatus, "已创建新便签。", false, true);
  } catch (error) {
    setStatus(noteStatus, `创建失败: ${error.message}`, true);
  }
});

saveBtn.addEventListener("click", async () => {
  if (!unlocked || !activeNoteId) return;
  try {
    setStatus(noteStatus, "保存中...");
    const encrypted = await encryptText(noteText.value);
    const payload = await authedPost("/api/notes/put", {
      noteId: activeNoteId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      updatedAt: Date.now()
    });
    activeNote = payload.note;
    updateMetaFromActiveNote();
    await loadNotesAndSelect(activeNoteId);
    setStatus(noteStatus, "保存成功。", false, true);
  } catch (error) {
    setStatus(noteStatus, `保存失败: ${error.message}`, true);
  }
});

deleteNoteBtn.addEventListener("click", async () => {
  if (!unlocked || !activeNoteId) return;
  const confirmed = window.confirm("确认删除当前便签？此操作不可恢复。");
  if (!confirmed) {
    return;
  }

  try {
    await authedPost("/api/notes/delete", { noteId: activeNoteId });
    const removedId = activeNoteId;
    activeNote = null;
    activeNoteId = null;
    await loadNotesAndSelect();
    setStatus(noteStatus, `便签已删除 (${removedId.slice(0, 8)})`, false, true);
  } catch (error) {
    setStatus(noteStatus, `删除失败: ${error.message}`, true);
  }
});

refreshBtn.addEventListener("click", async () => {
  if (!unlocked) return;
  await loadNotesAndSelect(activeNoteId);
});

lockBtn.addEventListener("click", () => {
  unlocked = false;
  authCryptoKey = null;
  encCryptoKey = null;
  currentUser = null;
  notesMeta = [];
  activeNote = null;
  activeNoteId = null;
  currentUserEl.textContent = "-";
  noteText.value = "";
  accessKeyInput.value = "";
  noteListEl.innerHTML = "";
  noteTitleEl.textContent = "未选择便签";
  noteMetaEl.textContent = "创建时间：- | 最近修改：-";
  setEditorEnabled(false);
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
  setStatus(unlockStatus, "输入访问密钥后可读取便签。", false, false);
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

async function loadNotesAndSelect(preferredNoteId = null) {
  try {
    setStatus(noteStatus, "拉取便签列表...");
    const payload = await authedPost("/api/notes/list", {});
    notesMeta = Array.isArray(payload.notes) ? payload.notes : [];
    renderNoteList();

    if (notesMeta.length === 0) {
      activeNote = null;
      activeNoteId = null;
      noteText.value = "";
      noteTitleEl.textContent = "未选择便签";
      noteMetaEl.textContent = "创建时间：- | 最近修改：-";
      setEditorEnabled(false);
      setStatus(noteStatus, "当前没有便签，请先点击“新增”。", false, false);
      return;
    }

    const target = notesMeta.some((x) => x.id === preferredNoteId)
      ? preferredNoteId
      : notesMeta[0].id;
    await openNote(target);
  } catch (error) {
    setStatus(noteStatus, `同步失败: ${error.message}`, true);
  }
}

function renderNoteList() {
  noteListEl.innerHTML = "";

  for (let i = 0; i < notesMeta.length; i += 1) {
    const note = notesMeta[i];
    const item = document.createElement("li");
    item.className = `note-item ${note.id === activeNoteId ? "active" : ""}`;

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "note-select";
    btn.dataset.noteId = note.id;
    btn.innerHTML = `<span class="note-name">便签 ${i + 1}</span>
      <span class="note-time">创建: ${formatTs(note.createdAt)}</span>
      <span class="note-time">修改: ${formatTs(note.updatedAt)}</span>`;
    btn.addEventListener("click", () => {
      openNote(note.id);
    });

    item.appendChild(btn);
    noteListEl.appendChild(item);
  }
}

async function openNote(noteId) {
  if (!noteId) {
    return;
  }
  try {
    const payload = await authedPost("/api/notes/get", { noteId });
    const note = payload.note;
    const plaintext = note.ciphertext
      ? await decryptText({ ciphertext: note.ciphertext, iv: note.iv })
      : "";

    activeNote = note;
    activeNoteId = note.id;
    noteText.value = plaintext;
    setEditorEnabled(true);
    updateMetaFromActiveNote();
    renderNoteList();
    setStatus(noteStatus, `已打开便签，最近修改: ${formatTs(note.updatedAt)}`, false, true);
  } catch (error) {
    setStatus(noteStatus, `读取便签失败: ${error.message}`, true);
  }
}

function updateMetaFromActiveNote() {
  if (!activeNote) {
    noteTitleEl.textContent = "未选择便签";
    noteMetaEl.textContent = "创建时间：- | 最近修改：-";
    return;
  }
  const idx = notesMeta.findIndex((x) => x.id === activeNote.id);
  noteTitleEl.textContent = idx >= 0 ? `便签 ${idx + 1}` : "便签";
  noteMetaEl.textContent = `创建时间：${formatTs(activeNote.createdAt)} | 最近修改：${formatTs(activeNote.updatedAt)}`;
}

function setEditorEnabled(enabled) {
  noteText.disabled = !enabled;
  saveBtn.disabled = !enabled;
  deleteNoteBtn.disabled = !enabled;
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
