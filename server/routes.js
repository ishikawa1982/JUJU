import express from 'express';
import { config } from './config.js';
import * as sessions from './sessions.js';
import * as storage from './storage.js';

export const router = express.Router();

const tokenOf = (req) => req.get('x-juju-token') || '';

function requireSender(req, res) {
  const s = sessions.get(req.params.id);
  if (!s) { res.status(404).json({ error: 'not found' }); return null; }
  if (tokenOf(req) !== s.senderToken) { res.status(403).json({ error: 'forbidden' }); return null; }
  return s;
}

// --- PIN解決のレート制限(IP単位の単純なスライディングカウンタ) ---
const attempts = new Map(); // ip -> { count, start }
function rateLimited(ip) {
  const now = Date.now();
  const e = attempts.get(ip);
  if (!e || now - e.start > config.resolveWindowMs) {
    attempts.set(ip, { count: 1, start: now });
    return false;
  }
  e.count += 1;
  return e.count > config.resolveMaxAttempts;
}

// 送信者: セッション作成
router.post('/sessions', (req, res) => {
  const s = sessions.create();
  res.json({
    sessionId: s.id,
    pin: s.pin,
    senderToken: s.senderToken,
    ttlSec: config.ttlSec,
    maxBytes: config.maxBytes,
    expiresAt: s.expiresAt,
  });
});

// 送信者: アップロード前にメタ情報(包んだ鍵・暗号化ファイル名)を登録
router.post('/sessions/:id/prepare', express.json({ limit: '64kb' }), (req, res) => {
  const s = requireSender(req, res);
  if (!s) return;
  const { wrappedKey, encMeta } = req.body || {};
  if (typeof wrappedKey !== 'string' || typeof encMeta !== 'string') {
    return res.status(400).json({ error: 'wrappedKey and encMeta required' });
  }
  sessions.prepare(s, { wrappedKey, encMeta });
  res.json({ ok: true });
});

// 送信者: 暗号文を生ストリームでアップロード
router.put('/sessions/:id/blob', async (req, res) => {
  const s = requireSender(req, res);
  if (!s) return;
  if (s.state !== 'ready') return res.status(409).json({ error: 'not ready' });
  try {
    const { size } = await storage.writeStream(s.id, req, {
      maxBytes: config.maxBytes,
      onProgress: (n) => sessions.notify(s, { type: 'upload_progress', bytes: n }),
    });
    s.size = size;
    s.state = 'uploaded';
    sessions.notify(s, { type: 'uploaded', size });
    res.json({ ok: true, size });
  } catch (err) {
    res.status(413).json({ error: String(err.message || err) });
  }
});

// 受信者: PIN → sessionId 解決(レート制限あり)
router.post('/resolve', express.json({ limit: '4kb' }), (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  if (rateLimited(ip)) return res.status(429).json({ error: 'too many attempts' });
  const pin = String((req.body && req.body.pin) || '').trim();
  if (!/^\d{6}$/.test(pin)) return res.status(400).json({ error: 'invalid pin' });
  const s = sessions.resolvePin(pin);
  if (!s) return res.status(404).json({ error: 'not found' });
  res.json({ sessionId: s.id });
});

// 受信者: セッションをロックして受け取りに必要な情報を取得
router.post('/sessions/:id/claim', (req, res) => {
  const s = sessions.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'not found' });
  if (s.state !== 'uploaded') return res.status(409).json({ error: 'not ready' });
  const receiverToken = sessions.claim(s);
  if (!receiverToken) return res.status(409).json({ error: 'already claimed' });
  res.json({
    receiverToken,
    encMeta: s.encMeta,
    wrappedKey: s.wrappedKey,
    size: s.size,
  });
});

// 送信者/受信者共通: 軽い状態確認(ポーリング用)
router.get('/sessions/:id', (req, res) => {
  const s = sessions.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'not found' });
  res.json({
    state: s.state,
    size: s.size,
    claimed: Boolean(s.receiverToken),
    expiresAt: s.expiresAt,
  });
});

// 受信者: 暗号文を受け取り、完了後にサーバーから即削除
router.get('/sessions/:id/blob', async (req, res) => {
  const s = sessions.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'not found' });
  if (tokenOf(req) !== s.receiverToken) return res.status(403).json({ error: 'forbidden' });
  if (s.state !== 'uploaded' || !(await storage.exists(s.id))) {
    return res.status(409).json({ error: 'no file' });
  }
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', String(s.size));
  sessions.notify(s, { type: 'download_started' });
  try {
    await storage.readStream(s.id, res);
    // 受信完了 → セッションごと破棄(暗号文も削除)
    sessions.notify(s, { type: 'completed' });
    await sessions.destroy(s.id, 'completed');
  } catch {
    // 切断などはスイーパー/TTLに任せる
  }
});

// 送信者: 明示的なキャンセル/削除
router.delete('/sessions/:id', async (req, res) => {
  const s = requireSender(req, res);
  if (!s) return;
  await sessions.destroy(s.id, 'cancelled');
  res.json({ ok: true });
});
