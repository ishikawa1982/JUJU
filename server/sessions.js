// メモリ上のセッション管理。
// 1セッション = 1回の授受。送信者がファイル(暗号文)を用意し、受信者が1人だけ受け取る。
// サーバーは暗号化メタ情報(opaque)とルーティング情報のみ保持。平文・鍵は持たない。
import crypto from 'node:crypto';
import { config } from './config.js';
import * as storage from './storage.js';

/**
 * session = {
 *   id, pin,
 *   senderToken, receiverToken,
 *   state: 'created' | 'ready' | 'uploaded' | 'done',
 *   wrappedKey,  // PIN由来鍵で包んだcontentKey(PIN手入力経路用。base64)
 *   encMeta,     // contentKeyで暗号化したファイル名/種別(base64)
 *   size,        // 暗号文サイズ
 *   createdAt, expiresAt,
 *   sockets: Set<ws>,
 * }
 */
const byId = new Map();
const byPin = new Map();

const token = (n = 24) => crypto.randomBytes(n).toString('base64url');
const id6 = () => crypto.randomBytes(12).toString('base64url');

function freshPin() {
  // 6桁。衝突する間引き直す(同時利用が極端でなければ即決まる)。
  for (let i = 0; i < 50; i++) {
    const pin = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
    if (!byPin.has(pin)) return pin;
  }
  throw new Error('no free pin available');
}

export function create() {
  const id = id6();
  const pin = freshPin();
  const now = Date.now();
  const s = {
    id,
    pin,
    senderToken: token(),
    receiverToken: null,
    state: 'created',
    wrappedKey: null,
    encMeta: null,
    size: 0,
    createdAt: now,
    expiresAt: now + config.ttlSec * 1000,
    sockets: new Set(),
  };
  byId.set(id, s);
  byPin.set(pin, id);
  return s;
}

export function get(id) {
  return byId.get(id);
}

export function resolvePin(pin) {
  const id = byPin.get(pin);
  return id ? byId.get(id) : undefined;
}

// 送信者がアップロード前にメタ情報を登録。
export function prepare(s, { wrappedKey, encMeta }) {
  s.wrappedKey = wrappedKey;
  s.encMeta = encMeta;
  s.state = 'ready';
}

// 受信者を1人にロック。既にロック済みなら null。
export function claim(s) {
  if (s.receiverToken) return null;
  s.receiverToken = token();
  notify(s, { type: 'receiver_joined' });
  return s.receiverToken;
}

export function notify(s, msg) {
  const data = JSON.stringify(msg);
  for (const ws of s.sockets) {
    if (ws.readyState === ws.OPEN) ws.send(data);
  }
}

export async function destroy(id, reason = 'done') {
  const s = byId.get(id);
  if (!s) return;
  notify(s, { type: 'closed', reason });
  for (const ws of s.sockets) {
    try { ws.close(); } catch { /* noop */ }
  }
  byId.delete(id);
  byPin.delete(s.pin);
  await storage.remove(id);
}

// 期限切れセッション/一時ファイルを定期的に掃除。
export function startSweeper() {
  const timer = setInterval(async () => {
    const now = Date.now();
    for (const [id, s] of byId) {
      if (s.expiresAt <= now) await destroy(id, 'expired');
    }
  }, 5_000);
  timer.unref?.();
  return timer;
}
