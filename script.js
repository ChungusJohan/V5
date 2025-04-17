const net = require('net');
const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const https = require('https');
const auth = require("basic-auth");
const { exec } = require('child_process');
const url = require('url');

const username = process.env.WEB_USERNAME || "admin";
const password = process.env.WEB_PASSWORD || "password";
const env_uuid = process.env.UUID || '37a0bd7c-8b9f-4693-8916-bd1e2da0a817';
const expected_uuid = env_uuid.replace(/-/g, '');
const port = process.env.PORT || 7860;
const DOH_SERVER = process.env.DOH_SERVER || 'https://dns.nextdns.io/7df33f';
const ws_path = `/${expected_uuid}`;


(async () => {
  exec('./agent.sh &', (error, stdout, stderr) => {
    if (error || stderr) {
      process.exit(1); // Keluar jika ada error saat menjalankan agent
    }
  });
})();

const app = express();
const server = http.createServer(app);

const wss = new WebSocket.Server({ noServer: true });

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
            const answer = response.Answer.find(a => a.type === 1); // Type 1 for A record
            if (answer) return resolve(answer.data);
          }
          reject(new Error('No valid A record found or DNS query failed'));
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
    const ipBytes = msg.slice(offset, offset + 16);
    offset += 16;
    const segments = [];
    for (let j = 0; j < 16; j += 2) {
      segments.push(ipBytes.readUInt16BE(j).toString(16));
    }
    host = segments.join(':').replace(/:(0:)+/, '::').replace(/:{3,}/, '::');
     if (host.startsWith('::') && host.endsWith('::')) {
         host = host.slice(0, -1);
     } else if (host.endsWith('::')) {
         host = host.slice(0, -1);
     }
  } else {
    throw new Error("Unsupported address type: " + ATYP);
  }
  return { ATYP, host, offset };
}


server.on('upgrade', (request, socket, head) => {
  const pathname = url.parse(request.url).pathname;

  if (pathname === ws_path) {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});

wss.on('connection', (ws) => {
  ws.isAlive = true;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  const interval = setInterval(() => {
    if (!ws.isAlive) {
      ws.terminate();
      return;
    }
    ws.isAlive = false;
    ws.ping();
  }, 30000);

  ws.on('close', () => {
    clearInterval(interval);
  });

  ws.once('message', async (msg) => {
    try {
        if (msg.length < 20) { // Basic | header check
             ws.close(1008, 'Invalid | header');
             return;
        }

      const version = msg[0]; // Should be 0 for | v0
      const receivedUuid = msg.slice(1, 17).toString('hex');

      // Double check UUID, although primary check is on upgrade path
      if (receivedUuid !== expected_uuid) {
          ws.close(1008, 'UUID mismatch');
          return;
      }

      // | v0 structure: Version (1) | UUID (16) | Addons Length (1) | Command (1) | Port (2) | Addr Type (1) | Addr (...) | Req Data (...)
      // offset starts after Addons Length field
      let offset = 18;
      const cmd = msg.readUInt8(offset++); // 1 = TCP, 2 = UDP, 3 = MUX
      const targetPort = msg.readUInt16BE(offset);
      offset += 2;

      let host, ATYP;
      ({ ATYP, host, offset } = parseHost(msg, offset));

      if (ATYP === 3) { // Domain name
        try {
          host = await resolveHostViaDoH(host);
           if (!net.isIP(host)) { // Check if resolution result is a valid IP
               throw new Error('DoH resolution did not return a valid IP');
           }
        } catch (err) {
          ws.close(1011, 'DNS resolution failed');
          return;
        }
      }

      if (!host) {
           ws.close(1008, 'Invalid target host');
           return;
      }

      // Send back connection confirmation (| v0: Version (1) | Addons Length (1) = 0)
      ws.send(Buffer.from([version, 0]));

      const duplex = WebSocket.createWebSocketStream(ws, { decodeStrings: false });
      
      const options = { host: host, port: targetPort };
      if (net.isIPv6(host)) options.family = 6;

      const socket = net.connect(options, () => {
         if (msg.length > offset) {
            socket.write(msg.slice(offset));
         }
         duplex.pipe(socket).pipe(duplex);
      });

      socket.on('error', (err) => {
        socket.destroy();
        if (!duplex.destroyed) duplex.destroy(err);
      });

      socket.on('end', () => {
        socket.destroy();
        if (!duplex.destroyed) duplex.destroy();
      });

      duplex.on('error', (err) => {
        socket.destroy();
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
       ws.on('error', (err) => {
          if (!socket.destroyed) socket.destroy();
          if (!duplex.destroyed) duplex.destroy(err);
           clearInterval(interval);
       });


    } catch (err) {
      ws.close(1011, 'Processing error');
    }
  });

   ws.on('error', (err) => {
       ws.close(1011, 'WebSocket error');
   });
});


app.use((req, res, next) => {
  if (req.url === ws_path) { // Jangan terapkan auth ke path websocket
      return next();
  }
  const user = auth(req);
  if (user && user.name === username && user.pass === password) {
    return next();
  }
  res.set("WWW-Authenticate", 'Basic realm="Node |"');
  res.status(401).send();
});


app.get('/', (req, res) => {
   res.send('OK'); // Hanya endpoint dasar untuk cek kesehatan
});

app.get('/link', (req, res) => { // Ganti '*' menjadi path spesifik
  const protocol = req.protocol;
  let host = req.get('host');
  let portNum = server.address().port; // Dapatkan port aktual server

  if (host.includes(':')) {
    [host] = host.split(':'); // Hanya ambil host, port didapat dari server.address()
  }

   // Gunakan ws_path yang sudah didefinisikan
  const link = protocol === 'https'
    ? `|://${expected_uuid}@${host}:${portNum}?path=${encodeURIComponent(ws_path)}&security=tls&encryption=none&host=${host}&type=ws&sni=${host}#node-|-ws-tls`
    : `|://${expected_uuid}@${host}:${portNum}?path=${encodeURIComponent(ws_path)}&type=ws&encryption=none&host=${host}#node-|-ws`;

  res.type('text/plain').send(link); // Kirim sebagai plain text
});

server.listen(port, '0.0.0.0', () => {
   // Tidak ada log di sini
});

server.on('error', (err) => {
  process.exit(1); // Keluar jika server gagal start
});
