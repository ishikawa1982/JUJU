// ブラウザ側 E2E 暗号化ヘルパ (Web Crypto / AES-GCM 256bit)。
// ファイルはここで暗号化してからアップロードし、受信側でここで復号する。
// サーバーは暗号文しか扱わない。
//
// ファイル暗号文のレイアウト(チャンク方式・大容量でもメモリを抑える):
//   [8 byte fileNonce][ 4 byte BE ctLen | ctLen byte ciphertext ] * N
//   各チャンクのIV(12byte) = fileNonce(8) || counter(4 BE)
const CHUNK = 1024 * 1024; // 平文1MiBごとに暗号化

export const b64u = {
  enc(bytes) {
    let s = '';
    const a = new Uint8Array(bytes);
    for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  dec(str) {
    const s = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
    const a = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
    return a;
  },
};

const te = new TextEncoder();
const td = new TextDecoder();

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// contentKey: ファイル本体とメタ情報を暗号化する高エントロピー鍵。
export async function generateContentKey() {
  const raw = randomBytes(32);
  const key = await importContentKey(raw);
  return { raw, key };
}

export function importContentKey(raw) {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

// PIN(+sessionId)から鍵を派生。手入力PIN経路で contentKey を包む/解く用。
export async function derivePinKey(pin, sessionId) {
  const base = await crypto.subtle.importKey('raw', te.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: te.encode(`juju:${sessionId}`), iterations: 200_000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function sealBytes(key, plain) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return b64u.enc(out);
}

async function openBytes(key, b64) {
  const raw = b64u.dec(b64);
  const iv = raw.slice(0, 12);
  const ct = raw.slice(12);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
}

// PIN由来鍵で contentKey(raw 32byte)を包む / 解く
export const wrapContentKey = (rawContentKey, pinKey) => sealBytes(pinKey, rawContentKey);
export const unwrapContentKey = (b64, pinKey) => openBytes(pinKey, b64);

// ファイル名/種別などのメタ情報を contentKey で暗号化 / 復号
export const encryptMeta = (contentKey, obj) => sealBytes(contentKey, te.encode(JSON.stringify(obj)));
export async function decryptMeta(contentKey, b64) {
  return JSON.parse(td.decode(await openBytes(contentKey, b64)));
}

function chunkIv(nonce, counter) {
  const iv = new Uint8Array(12);
  iv.set(nonce, 0);
  new DataView(iv.buffer).setUint32(8, counter, false);
  return iv;
}

// File を暗号化して Blob を返す(チャンクごと)。onProgress(bytesRead).
export async function encryptFile(contentKey, file, onProgress) {
  const nonce = randomBytes(8);
  const parts = [nonce];
  let offset = 0;
  let counter = 0;
  while (offset < file.size) {
    const slice = file.slice(offset, Math.min(offset + CHUNK, file.size));
    const plain = new Uint8Array(await slice.arrayBuffer());
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv: chunkIv(nonce, counter) }, contentKey, plain),
    );
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, ct.length, false);
    parts.push(len, ct);
    offset += plain.length;
    counter += 1;
    onProgress?.(offset);
    // 空ファイル対策: 1回はループを抜けるためのガード
    if (plain.length === 0) break;
  }
  return new Blob(parts, { type: 'application/octet-stream' });
}

// fetch の Response(暗号文ストリーム)を復号して Blob を返す。onProgress(bytesDecrypted).
export async function decryptResponse(contentKey, response, mimeType, onProgress) {
  const reader = response.body.getReader();
  let buf = new Uint8Array(0);
  let nonce = null;
  let counter = 0;
  let done = false;
  const out = [];
  let produced = 0;

  const append = (chunk) => {
    const merged = new Uint8Array(buf.length + chunk.length);
    merged.set(buf, 0);
    merged.set(chunk, buf.length);
    buf = merged;
  };
  const take = (n) => {
    const head = buf.slice(0, n);
    buf = buf.slice(n);
    return head;
  };

  while (!done) {
    const r = await reader.read();
    if (r.value) append(r.value);
    done = r.done;

    if (!nonce) {
      if (buf.length < 8) { if (done) break; continue; }
      nonce = take(8);
    }
    // 取り出せるチャンクをすべて処理
    for (;;) {
      if (buf.length < 4) break;
      const ctLen = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, false);
      if (buf.length < 4 + ctLen) break;
      take(4);
      const ct = take(ctLen);
      const plain = new Uint8Array(
        await crypto.subtle.decrypt({ name: 'AES-GCM', iv: chunkIv(nonce, counter) }, contentKey, ct),
      );
      out.push(plain);
      produced += plain.length;
      counter += 1;
      onProgress?.(produced);
    }
  }
  return new Blob(out, { type: mimeType || 'application/octet-stream' });
}
