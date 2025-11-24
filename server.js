// Server WebSocket rất đơn giản: chỉ chuyển tiếp ciphertext giữa các client
// và broadcast danh sách user + public key. Không bao giờ thấy plaintext.

const WebSocket = require("ws");

const wss = new WebSocket.Server({ port: 3000 });

/** @type {Map<WebSocket, {id:string, name:string, publicKeyBase64:string}>} */
const clients = new Map();

function broadcastUserList() {
  const users = Array.from(clients.values()).map((u) => ({
    id: u.id,
    name: u.name,
    publicKeyBase64: u.publicKeyBase64,
  }));

  const payload = JSON.stringify({ type: "users", users });
  for (const ws of clients.keys()) {
    ws.send(payload);
  }
}

function sendTo(targetId, data) {
  for (const [ws, meta] of clients.entries()) {
    if (meta.id === targetId) {
      ws.send(data);
    }
  }
}

wss.on("connection", (ws) => {
  ws.on("message", (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString("utf8"));
    } catch {
      return;
    }

    if (msg.type === "login") {
      const { id, name, publicKeyBase64 } = msg;
      clients.set(ws, { id, name, publicKeyBase64 });
      broadcastUserList();
      return;
    }

    if (msg.type === "ciphertext") {
      // Chỉ forward, không đọc nội dung
      const data = JSON.stringify({
        type: "ciphertext",
        fromId: msg.fromId,
        toId: msg.toId,
        fromName: msg.fromName,
        ivBase64: msg.ivBase64,
        ciphertextBase64: msg.ciphertextBase64,
        // gửi kèm public key bên gửi để bên nhận derive shared key
        fromPublicKeyBase64: clients.get(ws)?.publicKeyBase64,
        createdAt: Date.now(),
      });

      // gửi cho người nhận
      sendTo(msg.toId, data);
      // echo lại cho người gửi để hiển thị ngay trên UI
      sendTo(msg.fromId, data);
      return;
    }
  });

  ws.on("close", () => {
    clients.delete(ws);
    broadcastUserList();
  });
});

console.log("WebSocket server listening on ws://localhost:3000");


