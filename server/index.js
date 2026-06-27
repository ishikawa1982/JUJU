import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import { WebSocketServer } from 'ws';

import { config } from './config.js';
import { router } from './routes.js';
import * as sessions from './sessions.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, '..', 'public');

const app = express();
app.set('trust proxy', true);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'", 'ws:', 'wss:'],
        mediaSrc: ["'self'", 'blob:'],
        workerSrc: ["'self'", 'blob:'],
        objectSrc: ["'none'"],
      },
    },
    // QRスキャンのカメラ利用のため、クロスオリジン分離系は緩める
    crossOriginEmbedderPolicy: false,
  }),
);

app.use('/api', router);
app.use(express.static(publicDir, { extensions: ['html'] }));

// 受信リンク /r/:id は受信画面へ(SPA的にindexを返す)
app.get('/r/:id', (req, res) => res.sendFile(path.join(publicDir, 'index.html')));

const server = http.createServer(app);

// --- WebSocket: 進捗/状態をリアルタイム通知 ---
const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const sessionId = url.searchParams.get('sessionId') || '';
  const role = url.searchParams.get('role') || '';
  const tok = url.searchParams.get('token') || '';
  const s = sessions.get(sessionId);
  if (!s) return ws.close();
  // 役割ごとにトークン照合(送信者は常に、受信者はclaim後)
  const ok =
    (role === 'sender' && tok === s.senderToken) ||
    (role === 'receiver' && tok && tok === s.receiverToken);
  if (!ok) return ws.close();

  s.sockets.add(ws);
  ws.on('close', () => s.sockets.delete(ws));
  ws.on('error', () => s.sockets.delete(ws));
  ws.send(JSON.stringify({ type: 'hello', state: s.state }));
});

sessions.startSweeper();

server.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`授受 (JUJU) listening on http://localhost:${config.port}  (TTL ${config.ttlSec}s)`);
});
