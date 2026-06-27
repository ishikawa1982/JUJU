// 暗号文(opaqueなバイト列)の一時保存。
// - ストリームで書き込み/読み出しし、メモリ膨張を避ける。
// - ダウンロード完了で即削除、TTL経過でスイーパーが削除。
// サーバーは平文も鍵も扱わない。ここで触れるのは常に暗号文のみ。
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { config } from './config.js';

const dir = path.resolve(config.storageDir);
let totalBytes = 0; // 現在保持している暗号文の合計サイズ

await fsp.mkdir(dir, { recursive: true });
// 起動時に前回の残骸を掃除(再起動でファイルが残らないように)。
for (const f of await fsp.readdir(dir).catch(() => [])) {
  await fsp.rm(path.join(dir, f), { force: true }).catch(() => {});
}

const filePath = (id) => path.join(dir, `${id}.bin`);

// req(Readable)を一時ファイルへ書き込む。maxBytes / maxTotalBytes 超過時は中断して破棄。
export function writeStream(id, readable, { maxBytes, onProgress } = {}) {
  return new Promise((resolve, reject) => {
    const dest = filePath(id);
    const out = fs.createWriteStream(dest);
    let written = 0;
    let aborted = false;

    const fail = (err) => {
      if (aborted) return;
      aborted = true;
      out.destroy();
      fs.rm(dest, { force: true }, () => {});
      readable.destroy?.();
      reject(err);
    };

    readable.on('data', (chunk) => {
      written += chunk.length;
      if (maxBytes && written > maxBytes) {
        return fail(new Error('file too large'));
      }
      if (totalBytes + written > config.maxTotalBytes) {
        return fail(new Error('server storage full'));
      }
      onProgress?.(written);
    });
    readable.on('error', fail);
    out.on('error', fail);
    out.on('finish', () => {
      if (aborted) return;
      totalBytes += written;
      resolve({ size: written });
    });
    readable.pipe(out);
  });
}

// 暗号文を res へストリーム配信。
export function readStream(id, res) {
  return new Promise((resolve, reject) => {
    const src = fs.createReadStream(filePath(id));
    src.on('error', reject);
    res.on('error', reject);
    res.on('finish', resolve);
    src.pipe(res);
  });
}

export async function exists(id) {
  return fsp.access(filePath(id)).then(() => true).catch(() => false);
}

export async function size(id) {
  return fsp.stat(filePath(id)).then((s) => s.size).catch(() => 0);
}

// 一時ファイルを削除し、合計サイズを補正。
export async function remove(id) {
  const s = await size(id);
  await fsp.rm(filePath(id), { force: true }).catch(() => {});
  if (s) totalBytes = Math.max(0, totalBytes - s);
}

export function totalUsed() {
  return totalBytes;
}
