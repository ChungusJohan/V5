const net = require('net');
const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const https = require('https');
const auth = require("basic-auth");
const { URL } = require('url'); // Diperlukan untuk parsing URL upgrade
const { exec } = require('child_process');

// --- Konfigurasi ---
const ENV_USERNAME = process.env.WEB_USERNAME || "admin";
const ENV_PASSWORD = process.env.WEB_PASSWORD || "password";
const ENV_UUID = (process.env.UUID || '37a0bd7c-8b9f-4693-8916-bd1e2da0a817').replace(/-/g, '');
const ENV_PORT = process.env.PORT || 7860;
const ENV_DOH_SERVER = process.env.DOH_SERVER || 'https://dns.nextdns.io/7df33f';
// Tentukan path yang diharapkan untuk koneksi WebSocket (biasanya '/uuid')
const EXPECTED_WS_PATH = '/' + ENV_UUID;
// --- Akhir Konfigurasi ---


// Jalankan agent.sh di background (jika diperlukan)
(async () => {
  exec('./agent.sh &', (error, stdout, stderr) => {
    if (error) {
      // Catat error penting ini, tapi jangan pakai console.error jika tidak diinginkan
      // console.error(`Error starting agent: ${error.message}`);
      return;
    }
    if (stderr) {
      // console.error(`Agent stderr: ${stderr}`);
      return;
    }
    // console.log(`Agent stdout: ${stdout}`);
  });
})();

const app = express();
const server = http.createServer(app);

// Inisialisasi WebSocket Server tanpa otomatis menangani upgrade
const wss = new WebSocket.Server({ noServer: true });

// Fungsi resolver DNS-over-HTTPS (tidak diubah)
async function resolveHostViaDoH(domain) {
  return new Promise((resolve, reject) => {
    const url = `${ENV_DOH_SERVER}?name=${encodeURIComponent(domain)}&type=A`;
    https.get(url, {
      headers: { 'Accept': 'application/dns-json' }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          if (response.Answer && response.Answer.length > 0) {
            const answer = response.Answer.find(a => a.type === 1); // TYPE A record
            if (answer) return resolve(answer.data);
          }
          reject(new Error('No valid A record found in DoH response'));
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', (err) => reject(err));
  });
}

// Fungsi parsing host (tidak diubah)
function parseHost(msg, offset) {
  const ATYP = msg.readUInt8(offset++);
  let host;
  if (ATYP === 1) { // IPv4
    host = msg.slice(offset, offset + 4).join('.');
    offset += 4;
  } else if (ATYP === 3) { // Domain
    const len = msg.readUInt8(offset++);
    host = msg.slice(offset, offset + len).toString('utf8');
    offset += len;
  } else if (ATYP === 4) { // IPv6
    const ipBytes = msg.slice(offset, offset + 16);
    offset += 16;
    const segments = [];
    for (let j = 0; j < 16; j += 2) {
      segments.push(ipBytes.readUInt16BE(j).toString(16));
    }
    host = segments.join(':').replace(/:(0:)+/, '::').replace(/^(0:)+/, '::');
  } else {
    throw new Error("Unsupported address type: " + ATYP);
  }
  return { ATYP, host, offset };
}

// Logika penanganan koneksi WebSocket yang berhasil divalidasi
wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  const interval = setInterval(() => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  }, 30000); // 30 detik keepalive ping

  ws.on('close', () => {
    clearInterval(interval);
  });

  ws.once('message', async (msg) => {
    try {
       // Asumsi VSS header structure
      if (msg.length < 24) { // Basic VSS header check
        throw new Error('Invalid VSS header length');
      }
      // Version (1 byte) + UUID (16 bytes) + Addons Length (1 byte) = 18
      const addonsLength = msg.readUInt8(17);
      let offset = 18 + addonsLength; // Command (always 1 for TCP) + Port (2 bytes) + Addr Type (1 byte)
      
      if (msg.readUInt8(offset++) !== 1) { // Ensure command is 0x01 (TCP)
         throw new Error('Unsupported command');
      }

      const targetPort = msg.readUInt16BE(offset);
      offset += 2;

      let hostInfo = parseHost(msg, offset);
      let targetHost = hostInfo.host;
      offset = hostInfo.offset; // Update offset based on parsed host

      if (hostInfo.ATYP === 3) { // If it's a domain name
        try {
          targetHost = await resolveHostViaDoH(targetHost);
        } catch (dohError) {
          // console.error(`DoH resolution failed for ${targetHost}:`, dohError);
          ws.close(1011, 'DNS resolution failed'); // 1011: Internal Error
          return;
        }
      }
      
      // Send response to client (VSS version 0, no addons)
      ws.send(Buffer.from([0x00, 0x00])); 

      const duplex = WebSocket.createWebSocketStream(ws, { decodeStrings: false });
      const socket = net.connect({ host: targetHost, port: targetPort }, () => {
         // Write remaining data (actual payload) after VSS header
        if (msg.length > offset) { 
            socket.write(msg.slice(offset));
        }
        duplex.pipe(socket).pipe(duplex);
      });

      socket.on('error', (err) => {
        // console.error('Remote socket error:', err);
        socket.destroy();
        if (!duplex.destroyed) duplex.destroy();
      });
      socket.on('end', () => {
         if (!duplex.destroyed) duplex.end();
      });

      duplex.on('error', (err) => {
        // console.error('WebSocket stream error:', err);
        if (!socket.destroyed) socket.destroy();
        if (!duplex.destroyed) duplex.destroy();
      });
       duplex.on('close', () => {
         if (!socket.destroyed) socket.destroy();
      });
      ws.on('close', () => {
         if (!socket.destroyed) socket.destroy();
      });

    } catch (err) {
      // console.error('Error processing first message:', err);
      ws.close(1002, 'Protocol Error'); // 1002: Protocol Error
    }
  });

  ws.on('error', (err) => {
    // console.error('WebSocket error:', err);
     ws.close();
  });
});

// Tangani permintaan upgrade WebSocket secara manual
server.on('upgrade', (request, socket, head) => {
  try {
    // 1. Cek Path URL
    const pathname = new URL(request.url, `ws://${request.headers.host}`).pathname;
    if (pathname !== EXPECTED_WS_PATH) {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n'); // Atau 400 Bad Request
      socket.destroy();
      return;
    }

    // 2. Cek Basic Authentication (opsional, tapi seringkali path sudah cukup)
    // Jika Anda *juga* ingin memerlukan Basic Auth untuk upgrade WS:
    /*
    const user = auth(request);
    if (!user || user.name !== ENV_USERNAME || user.pass !== ENV_PASSWORD) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="Node"\r\n\r\n');
      socket.destroy();
      return;
    }
    */

    // Jika path (dan auth jika diaktifkan) valid, serahkan ke 'ws'
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } catch (err) {
     // console.error('Upgrade error:', err);
     socket.destroy();
  }
});

// Middleware Basic Authentication untuk endpoint HTTP GET (jika diperlukan)
// app.use((req, res, next) => {
//   const user = auth(req);
//   if (user && user.name === ENV_USERNAME && user.pass === ENV_PASSWORD) {
//     return next();
//   }
//   res.set("WWW-Authenticate", 'Basic realm="Node"');
//   res.status(401).send('Authentication required.');
// });

// Endpoint HTTP GET untuk menampilkan link konfigurasi
// Menggunakan '/' untuk menghindari potensi masalah dengan '*'
app.get('/', (req, res) => {
  const protocol = req.protocol; // http atau https (tergantung proxy di depannya)
  const hostHeader = req.get('host'); // Misal: example.com atau example.com:8080
  
  // Ekstrak host dan port dari header Host
  let host = hostHeader;
  let portNum = protocol === 'https' ? 443 : 80; // Default port
  if (hostHeader.includes(':')) {
     const parts = hostHeader.split(':');
     host = parts[0];
     portNum = parseInt(parts[1], 10);
  }
  
  // Gunakan EXPECTED_WS_PATH untuk konsistensi
  const wsPathQueryParam = encodeURIComponent(EXPECTED_WS_PATH);

  const link = protocol === 'https'
    ? `vls://${ENV_UUID}@${host}:${portNum}?path=${wsPathQueryParam}&security=tls&encryption=none&host=${host}&type=ws&sni=${host}#node-vless-ws-tls`
    : `vls://${ENV_UUID}@${host}:${portNum}?path=${wsPathQueryParam}&type=ws&encryption=none&host=${host}#node-vless-ws`;

  res.type('text/html');
  res.send(`<!DOCTYPE html>
<html>
<head><title>Config</title></head>
<body>
  <p>Copy the link below:</p>
  <pre>${link}</pre>
</body>
</html>`);
});

// Fallback untuk path lain jika diperlukan
app.use((req, res) => {
   res.status(404).send('Not Found');
});


server.listen(ENV_PORT, () => {
  console.log(`Server running on port ${ENV_PORT}, expecting WebSocket connections on path ${EXPECTED_WS_PATH}`);
});
