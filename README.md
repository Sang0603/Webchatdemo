# Web Crypto E2E Chat Demo

Demo chat nhiều người dùng, mã hóa end-to-end bằng Web Crypto API. Mỗi trình duyệt tự sinh cặp khóa ECDH, chỉ chia sẻ public key qua WebSocket server. Payload gửi đi luôn được mã hóa bằng AES-GCM, server không bao giờ nhìn thấy plaintext.

## Kiến trúc

1. `server.js`: WebSocket server đơn giản (cổng `3000`) giữ danh sách người dùng online và forward lại ciphertext/IV đến người nhận.
2. `index.html` + `styles.css` + `app.js`: frontend giống Messenger mini, có login, danh sách người online, khung chat với bong bóng trái/phải, panel hiển thị payload trên "wire".
3. Mỗi tin nhắn:
   - Client derive shared secret qua `ECDH (P-256)` giữa private key của mình và public key phía đối tác.
   - Mã hóa bằng `AES-GCM 256-bit`, sinh IV ngẫu nhiên 12 byte.
   - Gửi `{ciphertextBase64, ivBase64, fromId, toId}` qua server.
   - Bên nhận dùng private key của mình và public key đi kèm để giải mã.

## Cách chạy

```bash
# 1. Cài dependencies (chỉ cần 1 lần)
npm install

# 2. Chạy WebSocket server
npm run server
# server lắng nghe ws://localhost:3000

# 3. Phục vụ frontend (chọn 1 trong các cách)
npx serve .
# hoặc dùng Live Server/any static server, miễn là truy cập qua http://
```

Sau đó mở `index.html` bằng trình duyệt (qua server ở bước 3). Để thử multi-user, mở 2–3 tab hoặc trình duyệt khác nhau, mỗi tab đăng nhập với tên khác, rồi chọn user ở cột trái để chat. Panel bên phải hiển thị IV và ciphertext để minh họa rằng dữ liệu trên đường truyền đã được mã hóa.# Webchatdemo
