const net = require('net');
const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const https = require('https');
const auth = require("basic-auth");
const { exec } = require('child_process');
const { URL } = require('url'); // Diperlukan untuk parsing URL

const username = process.env.WEB_USERNAME || "admin";
const password = process.env.WEB_PASSWORD || "password";

// Pastikan UUID diambil dari environment atau default, dan tanpa tanda hubung
const uuid = (process.env.UUID || '37a0bd7c-8b9f-4693-8916-bd1e2da0a817').replace(/-/g, '');
const expectedPath = `/${uuid}`; // Path yang diharapkan untuk koneksi WebSocket

const port = process.env.PORT || 7860;
const DOH_SERVER = process.env.DOH_SERVER || 'https://dns.nextdns.io/7df33f';

// Jalankan agent.sh di background
(async () => {
  exec('./agent.sh &', (error, stdout, stderr) => {
    if (error) {
      console.error(`Exec error: ${error.message}`);
      return;
    }
    if (stderr) {
      // Mungkin ada output normal di stderr, jadi tidak selalu error
      // console.error(`Exec stderr: ${stderr}`);
    }
    // console.log(`Exec stdout: ${stdout}`); // Hapus log stdout normal
  });
})();

const app = express();
const server = http.createServer(app);

// Inisialisasi WebSocket Server tanpa server HTTP (noServer: true)
// Kita akan menangani upgrade secara manual
const wss = new WebSocket.Server({ noServer: true });

async function resolveHostViaDoH(domain) {
  return new Promise((resolve, reject) => {
    const url = `${DOH_SERVER}?name=${encodeURIComponent(domain)}&type=A`;
    https.get(url, {
      headers: { 'Accept': 'application/dns-json' }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          if (response.Answer && response.Answer.length > 0) {
            const answer = response.Answer.find(a => a.type === 1); // Type 1 for A record
            if (answer) return resolve(answer.data);
          }
          reject(new Error('No valid A record found in DoH response'));
        } catch (e) {
          reject(new Error(`Failed to parse DoH response: ${e.message}`));
        }
      });
    }).on('error', (err) => reject(new Error(`DoH request failed: ${err.message}`)));
  });
}

function parseHost(msg, offset) {
  const ATYP = msg.readUInt8(offset++);
  let host;
  let hostLen = 0;
  if (ATYP === 1) { // IPv4
    hostLen = 4;
    host = msg.slice(offset, offset + hostLen).join('.');
  } else if (ATYP === 3) { // Domain Name
    hostLen = msg.readUInt8(offset++);
    host = msg.slice(offset, offset + hostLen).toString('utf8');
  } else if (ATYP === 4) { // IPv6
    hostLen = 16;
    const ipBytes = msg.slice(offset, offset + hostLen);
    const segments = [];
    for (let j = 0; j < 16; j += 2) {
      segments.push(ipBytes.readUInt16BE(j).toString(16));
    }
    host = segments.join(':').replace(/:(0:)+/, '::').replace(/:{3,}/, '::'); // Basic IPv6 compression
  } else {
    // Dalam protokol |/VMESS, ATYP=2 adalah IPv6, ATYP=3 adalah Domain
    // Jika ATYP=2 adalah Domain di implementasi asli Anda, sesuaikan kembali:
    // } else if (ATYP === 2) { // Domain Name (jika implementasi Anda begini)
    //     hostLen = msg.readUInt8(offset++);
    //     host = msg.slice(offset, offset + hostLen).toString('utf8');
    // } else if (ATYP === 3) { // IPv6 (jika implementasi Anda begini)
    //     hostLen = 16; ... (kode IPv6 di atas) ...
    throw new Error("Unsupported address type: " + ATYP);
  }
  offset += hostLen;
  return { ATYP, host, offset };
}

// Tangani koneksi WebSocket SETELAH validasi UUID berhasil
wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  const interval = setInterval(() => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  }, 30000);

  ws.on('close', () => {
    clearInterval(interval);
  });

  ws.once('message', async (msg) => {
    try {
       // | Header structure (simplified assumption):
       // 1 byte version, 16 bytes UUID, 1 byte addon length, ...
       // Need to find the start of the address correctly.
       // The original code's offset logic might be specific to a protocol.
       // Let's assume the target address info starts after the UUID and any addons.
       // This part HIGHLY depends on the exact protocol format the client sends.
       // The original offset calculation: `msg.readUInt8(17) + 19` seems arbitrary without context.
       // Let's try a common | approach: Addr starts after Version (1) + UUID (16) + AddonLen (1) + Addons (?)
       // Assuming addon length is 0 for simplicity here. Adjust if needed.
       let offset = 1 + 16 + 1; // Start after version, UUID, addon length byte
       // If addon length byte (at index 17) is non-zero, adjust offset:
       const addonLen = msg.readUInt8(17);
       offset += addonLen; // Add actual addon length

       // Now read the target port (2 bytes)
       const targetPort = msg.readUInt16BE(offset);
       offset += 2;

       // Parse the host address (ATYP + Address)
       let parsedHost;
       try {
           parsedHost = parseHost(msg, offset);
       } catch (parseError) {
           console.error('Failed to parse target address:', parseError.message);
           ws.close();
           return;
       }
       let { ATYP, host } = parsedHost;
       offset = parsedHost.offset; // Update offset based on parsed host length

       let targetIP = host;
       // Resolve domain using DoH if ATYP indicates domain name (ATYP=3)
       if (ATYP === 3) { // ATYP 3 is typically Domain Name
         try {
           targetIP = await resolveHostViaDoH(host);
         } catch (err) {
           console.error(`DoH resolution failed for ${host}:`, err.message);
           ws.close();
           return;
         }
       }

       // | response: Version (1 byte), Addon Length (1 byte, usually 0)
       ws.send(Buffer.from([msg[0], 0])); // Assuming request version msg[0], response addon length 0

       const duplex = WebSocket.createWebSocketStream(ws);
       const socket = net.connect({ host: targetIP, port: targetPort }, () => {
         // Write the rest of the initial packet (payload)
         socket.write(msg.slice(offset));
         // Start piping data
         duplex.pipe(socket).pipe(duplex);
       });

       socket.on('error', (err) => {
         // console.error(`Target socket error for ${host}:${targetPort}:`, err.message); // Kurangi log
         socket.destroy();
         ws.close();
       });
       duplex.on('error', (err) => {
         // console.error('WebSocket stream duplex error:', err.message); // Kurangi log
         socket.destroy(); // ws already closed/closing if duplex errors
       });
       socket.on('end', () => {
           ws.close(); // Close WebSocket if target closes connection
       });
       ws.on('close', () => {
           socket.destroy(); // Ensure target socket is destroyed when WebSocket closes
       });

    } catch (err) {
      console.error('Error processing first message:', err);
      ws.close();
    }
  });

  ws.on('error', (err) => {
    // console.error('WebSocket error:', err.message); // Kurangi log
  });
});

// Middleware Basic Auth untuk endpoint HTTP GET
app.use((req, res, next) => {
    // Auth tidak berlaku untuk upgrade WebSocket, hanya untuk GET biasa
    if (req.headers.upgrade && req.headers.upgrade.toLowerCase() === 'websocket') {
        return next(); // Lewati auth untuk permintaan upgrade
    }
    const user = auth(req);
    if (user && user.name === username && user.pass === password) {
        return next();
    }
    res.set("WWW-Authenticate", 'Basic realm="Node Access"');
    return res.status(401).send("Authentication required.");
});

// Handler untuk HTTP GET (misalnya untuk menampilkan link konfigurasi)
app.get('*', (req, res) => {
  const protocol = req.headers['x-forwarded-proto'] || req.protocol; // Handle proxy proto header
  let host = req.headers['x-forwarded-host'] || req.get('host'); // Handle proxy host header
  let portNum = host.includes(':') ? host.split(':')[1] : (protocol === 'https' ? 443 : 80);
  if (host.includes(':')) {
      [host] = host.split(':');
  }

  // Gunakan path yang divalidasi di server.on('upgrade')
  const wsPath = expectedPath; // Path = /<uuid>

  // Sesuaikan template link dengan protokol yang Anda gunakan (|/VMESS/Trojan/Pler?)
  // Contoh ini menggunakan |, ganti '|' jika perlu
  const link = protocol === 'https'
    ? `|://${uuid}@${host}:${portNum}?path=${encodeURIComponent(wsPath)}&security=tls&encryption=none&host=${host}&type=ws&sni=${host}#Node-${port}`
    : `|://${uuid}@${host}:${portNum}?path=${encodeURIComponent(wsPath)}&type=ws&encryption=none&host=${host}#Node-${port}`;

  res.type('text/html');
  res.send(`<!DOCTYPE html>
<html>
<head><title>Config</title></head>
<body>
  <p>Use this link in your client:</p>
  <pre>${link}</pre>
  <p>Make sure the 'path' in your client configuration is exactly: <code>${wsPath}</code></p>
</body>
</html>`);
});

// Tangani permintaan Upgrade WebSocket
server.on('upgrade', (request, socket, head) => {
  let requestUrl;
  try {
      // Coba parse URL lengkap untuk mendapatkan pathname dengan aman
      requestUrl = new URL(request.url, `ws://${request.headers.host}`);
  } catch (e) {
      console.error("Invalid request URL during upgrade:", request.url);
      socket.destroy();
      return;
  }
  const pathname = requestUrl.pathname;

  // Validasi Path berdasarkan UUID
  if (pathname !== expectedPath) {
    // console.log(`UUID validation failed. Path mismatch. Expected: ${expectedPath}, Received: ${pathname}`); // Kurangi log
    socket.destroy(); // Tolak koneksi jika path tidak cocok
    return;
  }

  // Jika path cocok, lanjutkan dengan upgrade WebSocket
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request); // Emit event 'connection' untuk ditangani oleh listener di atas
  });
});

server.listen(port, () => {
  // console.log(`Server running on port ${port}`); // Kurangi log
  // console.log(`WebSocket connections expected on path: ${expectedPath}`); // Kurangi log
});

process.on('SIGTERM', () => {
    server.close(() => { process.exit(0); });
});
process.on('SIGINT', () => {
    server.close(() => { process.exit(0); });
});
