const http = require('http');
const https = require('https');
const auth = require("basic-auth");
const { exec } = require('child_process');
const express = require('express'); // <- Tambahkan import express
const WebSocket = require('ws');   // <- Tambahkan import ws
const net = require('net');         // <- Tambahkan import net
const url = require('url');         // <- Tambahkan import url

const username = process.env.WEB_USERNAME || "admin";
const password = process.env.WEB_PASSWORD || "password";

// Pastikan UUID tanpa tanda hubung (-) untuk perbandingan path
const uuid = (process.env.UUID || '37a0bd7c-8b9f-4693-8916-bd1e2da0a817').replace(/-/g, '');
const expectedPath = `/${uuid}`; // Path yang diharapkan untuk koneksi WebSocket

const port = process.env.PORT || 7860;
const DOH_SERVER = process.env.DOH_SERVER || 'https://dns.nextdns.io/7df33f';

// KHUSUS UNTUK NODE.JS
(async () => {
  exec('./agent.sh &', (error, stdout, stderr) => {
    // Penanganan error dan output bisa ditambahkan jika perlu, tapi sesuai permintaan, log dihilangkan
    if (error) {
      // console.error(`Error starting agent: ${error.message}`);
      return;
    }
    if (stderr) {
      // console.error(`stderr from agent: ${stderr}`);
      return;
    }
    // console.log(`stdout from agent: ${stdout}`);
  });
})();

const app = express();
const server = http.createServer(app);

// Fungsi verifikasi client WebSocket
function verifyClient(info, cb) {
  const reqUrl = info.req.url;
  const pathname = url.parse(reqUrl).pathname;

  if (pathname === expectedPath) {
    cb(true); // Izinkan koneksi jika path cocok
  } else {
    // console.warn(`Connection denied: Invalid path ${pathname}. Expected ${expectedPath}`); // Log penolakan (opsional, dihapus sesuai permintaan)
    cb(false, 401, 'Unauthorized'); // Tolak koneksi dengan status 401
  }
}

// Buat WebSocket server dengan opsi verifyClient
const wss = new WebSocket.Server({ server, verifyClient });

async function resolveHostViaDoH(domain) {
  return new Promise((resolve, reject) => {
    const dohUrl = `${DOH_SERVER}?name=${encodeURIComponent(domain)}&type=A`;
    https.get(dohUrl, {
      headers: { 'Accept': 'application/dns-json' }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          if (response.Answer && response.Answer.length > 0) {
            const answer = response.Answer.find(a => a.type === 1); // Type 1 is A record
            if (answer) return resolve(answer.data);
          }
          reject(new Error('No A record found or DNS query failed'));
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', (err) => reject(err));
  });
}

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
         host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s, [])
            .map(b => b.readUInt16BE(0).toString(16)).join(':');
         offset += 16;
    } else {
        throw new Error(`Unsupported address type: ${ATYP} in message ${msg.toString('hex')}`);
    }
    return { ATYP, host, offset };
}


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
        const V = msg.readUInt8(0); // | version
        if (V !== 0) {
            throw new Error(`Unsupported | version: ${V}`);
        }

        const receivedUUID = msg.slice(1, 17).toString('hex'); // UUID
        // Tidak perlu cek UUID di sini karena sudah divalidasi di verifyClient/upgrade handler

        let offset = 17; // Start after UUID
        const addonLen = msg.readUInt8(offset++); // Addon length
        offset += addonLen; // Skip addons for now

        const command = msg.readUInt8(offset++); // Command (1=TCP, 2=UDP, 3=MUX)
         if (command !== 1) { // Hanya support TCP
              throw new Error(`Unsupported command: ${command}`);
         }


      const targetPort = msg.readUInt16BE(offset);
      offset += 2;

      let host, ATYP;
      ({ ATYP, host, offset } = parseHost(msg, offset));

      if (ATYP === 3) { // Jika domain (ATYP 3 dalam |, bukan 2 seperti di SOCKS)
        try {
          host = await resolveHostViaDoH(host);
          // Jika resolve berhasil, host sekarang adalah IP (string)
        } catch (err) {
          // console.error(`DNS resolution failed for ${host}:`, err.message);
          ws.close();
          return;
        }
      }
      // Jika ATYP 1 (IPv4) atau 4 (IPv6), host sudah berupa IP

      ws.send(Buffer.from([V, 0])); // Send | response version 0, addon length 0

      const duplex = WebSocket.createWebSocketStream(ws);
      const socket = net.connect({ host, port: targetPort }, () => {
        // Kirim sisa data (payload |) jika ada
         if (msg.length > offset) {
             socket.write(msg.slice(offset));
         }
        duplex.pipe(socket).pipe(duplex);
      });

      socket.on('error', (err) => {
        // console.error('Remote socket error:', err.message);
        socket.destroy();
        if (!duplex.destroyed) duplex.destroy(err);
      });
      socket.on('end', () => {
        socket.destroy();
         if (!duplex.destroyed) duplex.destroy();
      });


      duplex.on('error', (err) => {
        // console.error('WebSocket stream duplex error:', err.message);
         if (!socket.destroyed) socket.destroy(err);
         if (!duplex.destroyed) duplex.destroy(err);
      });
       duplex.on('close', () => {
           if (!socket.destroyed) socket.destroy();
       });
       ws.on('close', () => {
          if (!socket.destroyed) socket.destroy();
           if (!duplex.destroyed) duplex.destroy();
           clearInterval(interval);
       });


    } catch (err) {
      // console.error('Error processing message:', err.message);
      ws.close();
    }
  });

  ws.on('error', (err) => {
    // console.error('WebSocket error:', err.message);
    ws.close();
  });
});

// Middleware otentikasi Basic Auth untuk endpoint HTTP
app.use((req, res, next) => {
  // Kecualikan path WebSocket dari otentikasi Basic Auth
  if (req.headers.upgrade && req.headers.upgrade.toLowerCase() === 'websocket') {
    return next(); // Lewati middleware ini untuk upgrade request
  }

  const user = auth(req);
  if (user && user.name === username && user.pass === password) {
    return next();
  }
  res.set("WWW-Authenticate", 'Basic realm="Node"');
  return res.status(401).send("Authentication required."); // Kirim respons jika otentikasi gagal
});


// Endpoint untuk menampilkan link konfigurasi (sudah diautentikasi)
app.get('*', (req, res) => {
  // Periksa jika request adalah untuk upgrade ke WebSocket, jangan kirim link
  if (req.headers.upgrade && req.headers.upgrade.toLowerCase() === 'websocket') {
    res.status(404).send('Not Found'); // Atau respons lain yang sesuai
    return;
  }

  const protocol = req.protocol; // http atau https (tergantung proxy di depannya)
  const detectedHost = req.get('host'); // host:port dari header Host
  const path = req.path === '/' ? `/${uuid}` : req.path; // Gunakan path UUID jika root

  // Asumsi path untuk websocket selalu /uuid
  const wsPath = `/${uuid}`;


  // Gunakan UUID asli dengan tanda hubung untuk link
  const originalUuid = process.env.UUID || '37a0bd7c-8b9f-4693-8916-bd1e2da0a817';

  // Buat link |
   const link = `|://${originalUuid}@${detectedHost}?path=${encodeURIComponent(wsPath)}&security=none&encryption=none&type=ws#node-ws-${detectedHost}`;


  res.type('text/html');
  res.send(`<!DOCTYPE html>
<html>
<head><title>Config</title></head>
<body>
  <p>Click to copy:</p>
  <pre id="configLink" style="background-color:#f0f0f0; padding:10px; cursor:pointer;">${link}</pre>
  <p id="copyStatus"></p>
  <script>
    document.getElementById('configLink').addEventListener('click', function() {
      navigator.clipboard.writeText(this.textContent).then(() => {
        document.getElementById('copyStatus').textContent = 'Copied!';
        setTimeout(() => { document.getElementById('copyStatus').textContent = ''; }, 2000);
      }).catch(err => {
        document.getElementById('copyStatus').textContent = 'Failed to copy!';
      });
    });
  </script>
</body>
</html>`);
});


server.listen(port, () => {
  // console.log(`Server running on port ${port} with UUID path ${expectedPath}`); // Log startup (dihapus sesuai permintaan)
});
