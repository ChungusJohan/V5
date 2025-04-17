const net = require('net');
const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const https = require('https');
const auth = require("basic-auth");
const { URL } = require('url');
const { exec } = require('child_process');

// --- Konfigurasi ---
const username = process.env.WEB_USERNAME || "admin";
const password = process.env.WEB_PASSWORD || "password";
// Pastikan UUID environment variable ada dan valid, atau gunakan default
const V_UUID = (process.env.UUID || '37a0bd7c-8b9f-4693-8916-bd1e2da0a817').replace(/-/g, '');
const port = process.env.PORT || 7860;
const DOH_SERVER = process.env.DOH_SERVER || 'https://dns.nextdns.io/7df33f';
// Tentukan path WebSocket yang diharapkan. Klien HARUS terhubung ke path ini.
const WS_PATH = process.env.WS_PATH || '/';
// --- Akhir Konfigurasi ---


// Jalankan proses agent.sh di background
(async () => {
  exec('./agent.sh &', (error, stdout, stderr) => {
    if (error) {
      process.stderr.write(`Error starting agent.sh: ${error.message}\n`);
      return;
    }
    if (stderr) {
      process.stderr.write(`agent.sh stderr: ${stderr}\n`);
      // Mungkin tidak perlu return di sini, tergantung apakah stderr adalah error fatal
    }
    // Tidak menampilkan stdout normalnya
  });
})();

const app = express();
const server = http.createServer(app);

// Pisahkan WebSocket Server dari HTTP Server untuk penanganan upgrade eksplisit
const wss = new WebSocket.Server({ noServer: true });

// Fungsi resolver DNS-over-HTTPS
async function resolveHostViaDoH(domain) {
  return new Promise((resolve, reject) => {
    // Validasi domain sederhana
    if (!domain || typeof domain !== 'string' || domain.length === 0) {
       return reject(new Error('Invalid domain for DoH resolution'));
    }
    const url = `${DOH_SERVER}?name=${encodeURIComponent(domain)}&type=A`;
    https.get(url, {
      headers: { 'Accept': 'application/dns-json' },
      rejectUnauthorized: false // Tambahkan jika DOH server menggunakan cert self-signed
    }, (res) => {
      let data = '';
      if (res.statusCode !== 200) {
        res.resume(); // Konsumsi data untuk membebaskan memori
        return reject(new Error(`DoH query failed with status code: ${res.statusCode}`));
      }
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          // Periksa Status dan Answer (format standar DoH JSON)
          if (response.Status === 0 && response.Answer && response.Answer.length > 0) {
            // Cari record A (type 1)
            const answer = response.Answer.find(a => a.type === 1);
            if (answer && answer.data) {
              return resolve(answer.data); // Kembalikan IP address
            }
          }
          // Jika tidak ada jawaban atau status error
          reject(new Error('No valid A record found in DoH response'));
        } catch (e) {
          reject(new Error(`Failed to parse DoH response: ${e.message}`));
        }
      });
    }).on('error', (err) => reject(new Error(`DoH request error: ${err.message}`)));
  });
}

// Fungsi parsing host (asumsi format protokol |/|)
function parseHostInfo(msg, offset) {
  const ATYP = msg.readUInt8(offset++);
  let host;
  let hostLength = 0; // Untuk menghitung panjang total bagian host

  if (ATYP === 1) { // IPv4
    hostLength = 4;
    host = msg.slice(offset, offset + hostLength).join('.');
  } else if (ATYP === 3) { // Domain Name
    hostLength = msg.readUInt8(offset++); // Panjang domain
    host = msg.slice(offset, offset + hostLength).toString('utf8');
  } else if (ATYP === 2) { // IPv6 (Revisi: Biasanya ATYP=3 untuk Domain, ATYP=2 untuk IPv6 di |. Sesuaikan jika protokol Anda berbeda)
    hostLength = 16;
    const ipBytes = msg.slice(offset, offset + hostLength);
    const segments = [];
    for (let j = 0; j < 16; j += 2) {
      segments.push(ipBytes.readUInt16BE(j).toString(16));
    }
    host = segments.join(':').replace(/:(0:)+/, '::').replace(/::+/, '::'); // Format IPv6
  } else {
    throw new Error("Unsupported address type: " + ATYP);
  }
  offset += hostLength; // Maju setelah membaca host
  const port = msg.readUInt16BE(offset);
  offset += 2; // Maju setelah membaca port

  return { ATYP, host, port, offset };
}


wss.on('connection', (ws, req) => {
  ws.isAlive = true;
  let initialClientDataProcessed = false;
  let remoteSocket = null;
  let streamDuplex = null;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  const heartbeatInterval = setInterval(() => {
    if (!ws.isAlive) {
      // process.stderr.write('WebSocket client timeout, terminating connection.\n');
      ws.terminate();
      return;
    }
    ws.isAlive = false;
    ws.ping();
  }, 30000); // 30 detik ping interval

  ws.on('message', async (message) => {
    try {
      // Proses pesan pertama untuk setup koneksi backend
      if (!initialClientDataProcessed) {
        initialClientDataProcessed = true;

        // --- Validasi UUID ---
        // Asumsi UUID ada di 16 byte pertama (sesuai |/|)
        if (message.length < 18) { // Minimal UUID(16) + Versi(1) + AddonsLen(1)
            throw new Error("Received message too short for initial handshake.");
        }
        const clientUUID = message.slice(0, 16).toString('hex');
        if (clientUUID !== V_UUID) {
          // process.stderr.write(`UUID mismatch. Expected: ${V_UUID}, Received: ${clientUUID}. Closing connection.\n`);
          ws.close(1008, "Invalid UUID"); // Kirim kode close policy violation
          return;
        }
        // --- Akhir Validasi UUID ---


        // Lanjutkan parsing sisa header |/| (contoh sederhana)
        // Struktur |: Version(1) + UUID(16) + AddonsLen(1) + [Addons] + Command(1) + Port(2) + ATYP(1) + Address(...)
        // Offset awal setelah UUID
        let offset = 16;
        const version = message.readUInt8(offset++); // Baca versi (biasanya 0 untuk |)
        const addonsLen = message.readUInt8(offset++); // Panjang addons (biasanya 0)
        offset += addonsLen; // Lewati addons jika ada

        const command = message.readUInt8(offset++); // Command (biasanya 1 untuk TCP)
        if (command !== 1) {
             throw new Error(`Unsupported command: ${command}`);
        }

        // Dapatkan Host dan Port tujuan
        const { ATYP, host: rawHost, port: targetPort, offset: newOffset } = parseHostInfo(message, offset);
        let targetHost = rawHost;
        offset = newOffset; // Update offset setelah parseHostInfo

        // Resolve domain via DoH jika ATYP adalah Domain (ATYP=3)
        if (ATYP === 3) { // Domain Name
          try {
            targetHost = await resolveHostViaDoH(rawHost);
            // process.stdout.write(`DoH resolved ${rawHost} to ${targetHost}\n`);
          } catch (err) {
            process.stderr.write(`DoH resolution failed for ${rawHost}: ${err.message}. Closing connection.\n`);
            ws.close(1011, "DNS resolution failed");
            return;
          }
        }

        // Kirim response ke client (misalnya | response: Version(1) + AddonsLen(1))
        // Untuk |, respons biasanya [0x00, 0x00] jika tidak ada Addons
        ws.send(Buffer.from([version, 0x00]));

        // Buat koneksi TCP ke tujuan
        remoteSocket = net.connect({
          host: targetHost, // Gunakan IP hasil resolve jika domain
          port: targetPort
        }, () => {
          // Koneksi TCP berhasil, siapkan piping
          streamDuplex = WebSocket.createWebSocketStream(ws);
          // Tulis sisa data dari paket pertama client (jika ada) ke remote socket
          const remainingData = message.slice(offset);
          if (remainingData.length > 0) {
            remoteSocket.write(remainingData);
          }
          // Pipe data dua arah
          streamDuplex.pipe(remoteSocket).pipe(streamDuplex);
        });

        // Error handling untuk koneksi TCP
        remoteSocket.on('error', (err) => {
          // process.stderr.write(`Remote socket error: ${err.message}. Closing WebSocket.\n`);
          ws.close(1011, "Upstream connection error"); // Internal server error
          remoteSocket.destroy();
          if (streamDuplex) streamDuplex.destroy(err);
        });

        remoteSocket.on('end', () => {
          // process.stdout.write('Remote socket ended connection.\n');
          if (streamDuplex) streamDuplex.end(); // Tutup sisi tulis WebSocket stream
        });

        remoteSocket.on('close', (hadError) => {
            // process.stdout.write(`Remote socket closed. Had error: ${hadError}\n`);
            if (streamDuplex) streamDuplex.destroy();
            ws.close(); // Pastikan WebSocket juga ditutup
        });

        // Error handling untuk stream WebSocket
        streamDuplex.on('error', (err) => {
        //   process.stderr.write(`WebSocket stream error: ${err.message}. Closing connections.\n`);
          ws.close(1011, "WebSocket stream error");
          if (remoteSocket) remoteSocket.destroy();
          streamDuplex.destroy(err);
        });


      } else {
        // Jika bukan pesan pertama dan koneksi remote sudah siap, teruskan data
        if (remoteSocket && remoteSocket.writable && streamDuplex) {
          // Data ini sudah otomatis di-pipe oleh streamDuplex.pipe(remoteSocket)
          // Tidak perlu ws.send() atau remoteSocket.write() manual di sini lagi
          // Cukup pastikan streamDuplex aktif
        } else {
            // Jika pesan datang sebelum remote siap atau setelah error
            // process.stderr.write('Received WebSocket message, but upstream not ready or closed.\n');
            // Pertimbangkan untuk menutup ws jika ini terjadi setelah setup gagal
            // ws.close(1011, "Upstream not available");
        }
      }
    } catch (err) {
      process.stderr.write(`Error processing WebSocket message: ${err.message}\n`);
      ws.close(1011, "Internal processing error"); // Internal server error
      if (remoteSocket) remoteSocket.destroy();
      if (streamDuplex) streamDuplex.destroy(err);
    }
  });

  ws.on('close', (code, reason) => {
    // process.stdout.write(`WebSocket connection closed. Code: ${code}, Reason: ${reason || 'No reason given'}\n`);
    clearInterval(heartbeatInterval);
    ws.isAlive = false;
    if (remoteSocket) remoteSocket.destroy();
    if (streamDuplex) streamDuplex.destroy();
  });

  ws.on('error', (err) => {
    // process.stderr.write(`WebSocket error: ${err.message}\n`);
    clearInterval(heartbeatInterval);
    ws.isAlive = false;
    if (remoteSocket) remoteSocket.destroy();
    if (streamDuplex) streamDuplex.destroy(err);
    ws.close(1011, "WebSocket error occurred"); // Tutup jika belum tertutup
  });
});

// Tangani permintaan upgrade WebSocket secara eksplisit
server.on('upgrade', (request, socket, head) => {
  // 1. Cek Basic Authentication
  const user = auth(request);
  if (!user || user.name !== username || user.pass !== password) {
    // process.stderr.write('WebSocket upgrade failed: Basic Authentication failed.\n');
    socket.write('HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="Node"\r\n\r\n');
    socket.destroy();
    return;
  }

  // 2. Cek Path URL
  const pathname = new URL(request.url, `http://${request.headers.host}`).pathname;
  if (pathname !== WS_PATH) {
    // process.stderr.write(`WebSocket upgrade failed: Path mismatch. Expected: ${WS_PATH}, Received: ${pathname}.\n`);
    socket.write(`HTTP/1.1 400 Bad Request\r\n\r\n`);
    socket.destroy();
    return;
  }

  // 3. Jika Auth dan Path OK, serahkan ke WSS untuk menyelesaikan handshake
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

// Middleware Basic Auth untuk rute HTTP biasa (jika diperlukan)
// app.use((req, res, next) => {
//   // Lewati jika permintaan upgrade WebSocket (sudah ditangani di server.on('upgrade'))
//   if (req.headers.upgrade && req.headers.upgrade.toLowerCase() === 'websocket') {
//       return next();
//   }
//   const user = auth(req);
//   if (user && user.name === username && user.pass === password) {
//     return next();
//   }
//   res.set("WWW-Authenticate", 'Basic realm="Node"');
//   res.status(401).send("Authentication Required");
// });

// Rute HTTP untuk menampilkan link koneksi (tidak diautentikasi di sini)
// Biasanya halaman ini tidak perlu auth, hanya koneksi WS yang perlu
app.get('*', (req, res) => {
    // Dapatkan host dan port dari header Host, tangani IPv6
    const hostHeader = req.get('host') || '';
    let detectedHost = hostHeader;
    let detectedPort = server.address().port; // Ambil port aktual server berjalan

    const ipv6Match = hostHeader.match(/\[(.*)\](?::(\d+))?$/); // Cocokkan [ipv6]:port
    const ipv4Match = hostHeader.match(/([^:]+)(?::(\d+))?$/);  // Cocokkan ipv4:port atau domain:port

    if (ipv6Match) {
        detectedHost = ipv6Match[1]; // Alamat IPv6 tanpa kurung
        if (ipv6Match[2]) {
            detectedPort = parseInt(ipv6Match[2], 10); // Port jika ada
        }
    } else if (ipv4Match) {
        detectedHost = ipv4Match[1]; // Alamat IPv4 atau domain
        if (ipv4Match[2]) {
            detectedPort = parseInt(ipv4Match[2], 10); // Port jika ada
        }
    }

    // Tentukan protokol berdasarkan request (meskipun server ini hanya HTTP)
    // Jika di belakang reverse proxy TLS, 'x-forwarded-proto' bisa digunakan
    const protocol = req.get('x-forwarded-proto') === 'https' ? 'https' : req.protocol;
    const isTls = protocol === 'https';

    // Format link pler://
    // Sesuaikan parameter query sesuai kebutuhan protokol pler Anda
    let link = `pler://${V_UUID}@${detectedHost}:${detectedPort}?`;
    link += `type=ws&path=${encodeURIComponent(WS_PATH)}&host=${encodeURIComponent(detectedHost)}`;
    if (isTls) {
        link += `&security=tls&sni=${encodeURIComponent(detectedHost)}`; // Tambahkan security=tls dan sni jika HTTPS
    } else {
        link += `&security=none`; // Atau sesuaikan jika ada parameter lain untuk non-TLS
    }
    link += `#node-pler`; // Fragment identifier

    res.setHeader('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html><html><head><title>Connection Info</title></head><body><p>Scan or copy the link:</p><pre style="word-wrap: break-word; white-space: pre-wrap;">${link}</pre></body></html>`);
});


server.listen(port, '0.0.0.0', () => { // Dengarkan di semua interface
  process.stdout.write(`Server running on port ${port}, WebSocket Path: ${WS_PATH}\n`);
  process.stdout.write(`Expected UUID: ${V_UUID}\n`);
});

// Tangani sinyal shutdown
process.on('SIGINT', () => {
    process.stdout.write("\nGracefully shutting down...\n");
    wss.close(() => {
        server.close(() => {
            process.stdout.write("Server closed.\n");
            process.exit(0);
        });
    });
    // Beri waktu sedikit untuk koneksi aktif selesai
    setTimeout(() => {
        process.stderr.write("Shutdown timeout, forcing exit.\n");
        process.exit(1);
    }, 5000); // 5 detik timeout
});
