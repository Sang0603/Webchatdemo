const encoder = new TextEncoder();
const decoder = new TextDecoder();

// DOM
const chatTemplate = document.getElementById("chat-item");
const wireTemplate = document.getElementById("wire-item");
const chatLog = document.getElementById("chat-log");
const wireLog = document.getElementById("wire-log");
const userListEl = document.getElementById("user-list");
const activePeerNameEl = document.getElementById("active-peer-name");
const connectionStatusEl = document.getElementById("connection-status");
const loginForm = document.getElementById("login-form");
const usernameInput = document.getElementById("username-input");
const messageForm = document.getElementById("message-form");
const messageInput = document.getElementById("message-input");
const sendButton = messageForm.querySelector(".send-btn");

// Trạng thái client
let ws = null;
let me = null; // { id, name, keys, publicKeyBase64 }
/** @type {Map<string, {id:string,name:string,publicKeyBase64:string}>} */
const peers = new Map();
let activePeerId = null;
/** @type {Map<string, Array<{id:string, fromName:string, toName:string, text:string, timestamp:number, isSelf:boolean}>>} */
const conversations = new Map();

async function createIdentity(name) {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );
  const rawPublic = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  return {
    id: crypto.randomUUID(),
    name,
    keys: keyPair,
    publicKeyBase64: arrayBufferToBase64(rawPublic),
  };
}

function connectWebSocket(identity) {
  ws = new WebSocket("ws://localhost:3000");

  ws.addEventListener("open", () => {
    connectionStatusEl.textContent = "Đã kết nối server";
    ws.send(
      JSON.stringify({
        type: "login",
        id: identity.id,
        name: identity.name,
        publicKeyBase64: identity.publicKeyBase64,
      })
    );
  });

  ws.addEventListener("message", async (event) => {
    const msg = JSON.parse(event.data);

    if (msg.type === "users") {
      updateUsers(msg.users);
      return;
    }

    if (msg.type === "ciphertext") {
      handleIncomingCiphertext(msg);
    }
  });

  ws.addEventListener("close", () => {
    connectionStatusEl.textContent = "Mất kết nối server";
  });
}

function updateUsers(users) {
  userListEl.innerHTML = "";
  peers.clear();

  const availableIds = [];
  users.forEach((u) => {
    if (!me || u.id === me.id) return; // không hiển thị chính mình
    peers.set(u.id, u);
    availableIds.push(u.id);

    const li = document.createElement("li");
    li.className = "user-item";
    li.dataset.id = u.id;
    li.innerHTML = `<span>${u.name}</span><span class="dot"></span>`;
    li.addEventListener("click", () => {
      setActivePeer(u.id);
    });
    userListEl.appendChild(li);
  });

  // nếu peer hiện tại không còn thì reset
  if (activePeerId && !peers.has(activePeerId)) {
    activePeerId = null;
    activePeerNameEl.textContent = "Chưa chọn người nhận";
    sendButton.disabled = true;
  }

  // tự động chọn người đầu tiên để người dùng không quên click
  if (!activePeerId && availableIds.length > 0) {
    setActivePeer(availableIds[0]);
  }
}

function setActivePeer(id) {
  activePeerId = id;
  const peer = peers.get(id);
  if (!peer) return;

  activePeerNameEl.textContent = peer.name;
  activePeerNameEl.title = `Bạn đang chat với ${peer.name}`;
  sendButton.disabled = false;

  document
    .querySelectorAll(".user-item")
    .forEach((el) => el.classList.remove("active"));
  const current = userListEl.querySelector(`[data-id="${id}"]`);
  if (current) current.classList.add("active");

  renderConversation(id);
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = usernameInput.value.trim();
  if (!name) return;

  loginForm.querySelector("button").disabled = true;
  usernameInput.disabled = true;

  me = await createIdentity(name);
  connectWebSocket(me);
});

messageForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = messageInput.value.trim();
  if (!text || !ws || ws.readyState !== WebSocket.OPEN || !activePeerId) return;

  messageInput.value = "";
  const peer = peers.get(activePeerId);
  if (!peer) return;

  const { ivBase64, ciphertextBase64 } = await encryptForPeer(peer, text);

  const payload = {
    type: "ciphertext",
    fromId: me.id,
    toId: peer.id,
    fromName: me.name,
    ivBase64,
    ciphertextBase64,
  };

  addMessageToConversation(peer.id, {
    id: crypto.randomUUID(),
    fromName: me.name,
    toName: peer.name,
    text,
    timestamp: Date.now(),
    isSelf: true,
  });
  appendWireLog(payload);

  ws.send(JSON.stringify(payload));
});

async function encryptForPeer(peer, plaintext) {
  const foreignPublicKey = await importRemotePublicKey(peer.publicKeyBase64);
  const shared = await deriveSharedKey(me.keys.privateKey, foreignPublicKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    shared,
    encoder.encode(plaintext)
  );
  return {
    ivBase64: arrayBufferToBase64(iv),
    ciphertextBase64: arrayBufferToBase64(ciphertext),
  };
}

async function handleIncomingCiphertext(msg) {
  // Nếu mình không phải người gửi cũng không phải người nhận thì bỏ qua
  if (!me || (msg.fromId !== me.id && msg.toId !== me.id)) return;

  const isMine = msg.fromId === me.id;
  const otherName = isMine ? peers.get(msg.toId)?.name : msg.fromName;

  appendWireLog(msg);

  // Giải mã nếu mình là người nhận
  if (msg.toId === me.id) {
    const foreignPublicKey = await importRemotePublicKey(
      msg.fromPublicKeyBase64
    );
    const shared = await deriveSharedKey(me.keys.privateKey, foreignPublicKey);
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToArrayBuffer(msg.ivBase64),
      },
      shared,
      base64ToArrayBuffer(msg.ciphertextBase64)
    );

    addMessageToConversation(msg.fromId, {
      id: msg.id || crypto.randomUUID(),
      fromName: msg.fromName,
      toName: me.name,
      text: decoder.decode(decrypted),
      timestamp: msg.createdAt || Date.now(),
      isSelf: false,
    });
  } else if (isMine) {
    // server echo lại tin của mình: chỉ log thêm một lần phía mình (đã log trước đó) nên có thể bỏ qua
    return;
  }
}

function addMessageToConversation(peerId, message) {
  if (!conversations.has(peerId)) {
    conversations.set(peerId, []);
  }
  conversations.get(peerId).push(message);

  if (peerId === activePeerId) {
    renderMessage(message);
    chatLog.scrollTop = chatLog.scrollHeight;
  }
}

function renderConversation(peerId) {
  chatLog.innerHTML = "";
  const history = conversations.get(peerId) || [];
  history.forEach((message) => {
    renderMessage(message);
  });
  chatLog.scrollTop = chatLog.scrollHeight;
}

function renderMessage(message) {
  const item = chatTemplate.content.firstElementChild.cloneNode(true);
  const meta = item.querySelector(".meta");
  meta.textContent = new Date(message.timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });

  item.querySelector(".plaintext").textContent = message.text;

  item.classList.add(message.isSelf ? "self" : "other");
  item.title = message.isSelf
    ? `Bạn (${me?.name || "Bạn"})`
    : message.fromName || "Người dùng";

  chatLog.appendChild(item);
}

function appendWireLog(payload) {
  const item = wireTemplate.content.firstElementChild.cloneNode(true);
  item.classList.add("wire");
  item.querySelector(".tag--from").textContent =
    payload.fromName || payload.fromId;
  item.querySelector(".tag--to").textContent = payload.toId;
  item.querySelector(".plaintext").textContent = `IV: ${payload.ivBase64}`;
  item.querySelector(
    ".ciphertext"
  ).textContent = `Ciphertext: ${payload.ciphertextBase64}`;
  wireLog.prepend(item);
}

async function deriveSharedKey(privateKey, foreignPublicKey) {
  return crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: foreignPublicKey,
    },
    privateKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function importRemotePublicKey(base64) {
  const raw = base64ToArrayBuffer(base64);
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

function arrayBufferToBase64(buffer) {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

