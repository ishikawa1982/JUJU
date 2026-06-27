// 授受 (JUJU) フロント制御: 画面遷移 + E2E暗号化 + アップロード/ダウンロード + QR。
import {
  b64u, randomBytes, generateContentKey, importContentKey,
  derivePinKey, wrapContentKey, unwrapContentKey,
  encryptMeta, decryptMeta, encryptFile, decryptResponse,
} from './crypto.js';

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fmtSize = (n) => {
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
};

// ---- 画面遷移 ----
function show(view) {
  for (const el of document.querySelectorAll('.view')) el.classList.remove('active');
  $(view).classList.add('active');
}
$('homeBtn').addEventListener('click', () => { resetAll(); show('home'); });
for (const btn of document.querySelectorAll('[data-go]')) {
  btn.addEventListener('click', () => show(btn.dataset.go));
}

let activeWs = null;
function resetAll() {
  try { activeWs?.close(); } catch { /* noop */ }
  activeWs = null;
  $('sendPick').classList.remove('hidden');
  $('sendShare').classList.add('hidden');
  $('recvEntry').classList.remove('hidden');
  $('recvProgress').classList.add('hidden');
  $('fileInput').value = '';
  $('fileInfo').textContent = '';
  $('pinInput').value = '';
  stopScanner();
}

function openWs(sessionId, role, token, onMsg) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws?sessionId=${sessionId}&role=${role}&token=${encodeURIComponent(token)}`);
  ws.onmessage = (e) => { try { onMsg(JSON.parse(e.data)); } catch { /* noop */ } };
  return ws;
}

// =====================================================================
//  授(送る)
// =====================================================================
$('fileInput').addEventListener('change', () => {
  const f = $('fileInput').files[0];
  if (f) { $('fileInfo').textContent = `${f.name} — ${fmtSize(f.size)}`; startSend(f); }
});
$('sendCancel').addEventListener('click', async () => {
  if (currentSend) {
    await fetch(`/api/sessions/${currentSend.id}`, {
      method: 'DELETE', headers: { 'x-juju-token': currentSend.senderToken },
    }).catch(() => {});
  }
  resetAll(); show('home');
});

let currentSend = null;

async function startSend(file) {
  try {
    // 1. セッション作成
    const sRes = await fetch('/api/sessions', { method: 'POST' });
    const s = await sRes.json();
    currentSend = s;
    if (file.size > s.maxBytes) {
      alert(`ファイルが大きすぎます(上限 ${fmtSize(s.maxBytes)})`);
      resetAll(); show('home'); return;
    }

    // 2. 鍵を生成し、PIN由来鍵で包む(PIN手入力経路のため)
    const { raw, key } = await generateContentKey();
    const pinKey = await derivePinKey(s.pin, s.sessionId);
    const wrappedKey = await wrapContentKey(raw, pinKey);
    const encMeta = await encryptMeta(key, { name: file.name, type: file.type || 'application/octet-stream' });
    await fetch(`/api/sessions/${s.sessionId}/prepare`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-juju-token': s.senderToken },
      body: JSON.stringify({ wrappedKey, encMeta }),
    });

    // 3. 画面に PIN と QR を表示(鍵は URL フラグメントに載せ、サーバーには送らない)
    $('sendPick').classList.add('hidden');
    $('sendShare').classList.remove('hidden');
    $('pinShow').textContent = s.pin.split('').join(' ');
    const link = `${location.origin}/r/${s.sessionId}#k=${b64u.enc(raw)}`;
    if (window.QRCode) {
      QRCode.toCanvas($('qrCanvas'), link, { width: 220, margin: 1 }, () => {});
    }

    // 4. WS で受信者の参加・完了を監視
    activeWs = openWs(s.sessionId, 'sender', s.senderToken, (m) => {
      if (m.type === 'receiver_joined') $('sendStatus').textContent = '受信者が参加。授受中…';
      if (m.type === 'completed') {
        $('sendStatus').textContent = '✓ 授受完了';
        $('sendProgress').classList.add('hidden');
      }
      if (m.type === 'closed' && m.reason === 'expired') $('sendStatus').textContent = '期限切れで削除されました';
    });

    // 5. 暗号化してアップロード
    const bar = $('sendProgress');
    bar.classList.remove('hidden');
    $('sendStatus').textContent = '暗号化中…';
    const blob = await encryptFile(key, file, (read) => {
      bar.value = Math.round((read / file.size) * 50); // 前半50%=暗号化
    });
    $('sendStatus').textContent = 'アップロード中…';
    await uploadBlob(`/api/sessions/${s.sessionId}/blob`, blob, s.senderToken, (loaded, total) => {
      bar.value = 50 + Math.round((loaded / total) * 50); // 後半50%=送信
    });
    $('sendStatus').textContent = '準備完了。受信を待っています…';
  } catch (err) {
    console.error(err);
    $('sendStatus').textContent = `エラー: ${err.message || err}`;
  }
}

function uploadBlob(url, blob, token, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', url);
    xhr.setRequestHeader('x-juju-token', token);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded, e.total); };
    xhr.onload = () => (xhr.status < 300
      ? resolve(JSON.parse(xhr.responseText || '{}'))
      : reject(new Error(xhr.responseText || `HTTP ${xhr.status}`)));
    xhr.onerror = () => reject(new Error('ネットワークエラー'));
    xhr.send(blob);
  });
}

// =====================================================================
//  受(受け取る)
// =====================================================================
$('recvByPin').addEventListener('click', async () => {
  const pin = $('pinInput').value.trim();
  if (!/^\d{6}$/.test(pin)) { alert('6桁の数字を入力してください'); return; }
  try {
    const r = await fetch('/api/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin }),
    });
    if (!r.ok) throw new Error(r.status === 429 ? '試行回数が多すぎます' : 'PINが見つかりません');
    const { sessionId } = await r.json();
    // PIN経路: 鍵はPINから派生して取り出す
    await receive(sessionId, { pin });
  } catch (err) { alert(err.message || err); }
});

// URL が /r/:id#k=... のときは受信フローへ直行
async function maybeAutoReceive() {
  const m = location.pathname.match(/^\/r\/([^/]+)$/);
  if (!m) return;
  const sessionId = m[1];
  const key = new URLSearchParams(location.hash.slice(1)).get('k');
  show('receive');
  if (key) await receive(sessionId, { rawKeyB64: key });
}

// QRスキャン(html5-qrcode)
let scanner = null;
$('scanBtn').addEventListener('click', async () => {
  if (!window.Html5Qrcode) { alert('QRライブラリの読み込みに失敗しました'); return; }
  const box = $('qrReader');
  box.classList.remove('hidden');
  scanner = new Html5Qrcode('qrReader');
  try {
    await scanner.start({ facingMode: 'environment' }, { fps: 10, qrbox: 220 }, async (text) => {
      await stopScanner();
      handleScanned(text);
    });
  } catch (err) {
    alert(`カメラを起動できません: ${err}`);
    box.classList.add('hidden');
  }
});

async function stopScanner() {
  if (scanner) {
    try { await scanner.stop(); } catch { /* noop */ }
    scanner = null;
  }
  $('qrReader')?.classList.add('hidden');
}

async function handleScanned(text) {
  try {
    const u = new URL(text, location.origin);
    const m = u.pathname.match(/^\/r\/([^/]+)$/);
    const key = new URLSearchParams(u.hash.slice(1)).get('k');
    if (m && key) return receive(m[1], { rawKeyB64: key });
  } catch { /* not a url */ }
  // URLでなければ数字PINとして扱う
  if (/^\d{6}$/.test(text.trim())) {
    $('pinInput').value = text.trim();
    $('recvByPin').click();
  } else {
    alert('対応していないQRコードです');
  }
}

async function receive(sessionId, { rawKeyB64, pin }) {
  $('recvEntry').classList.add('hidden');
  $('recvProgress').classList.remove('hidden');
  const status = $('recvStatus');
  const bar = $('recvBar');
  try {
    // 1. 送信側のアップロード完了を待つ
    status.textContent = '送信者を待っています…';
    await waitUploaded(sessionId);

    // 2. セッションをロックして受信情報を取得
    const cRes = await fetch(`/api/sessions/${sessionId}/claim`, { method: 'POST' });
    if (!cRes.ok) {
      const e = await cRes.json().catch(() => ({}));
      throw new Error(e.error === 'already claimed' ? '別のデバイスが既に受け取り中です' : '受け取りを開始できません');
    }
    const { receiverToken, encMeta, wrappedKey, size } = await cRes.json();

    // 3. 鍵を用意(QR/リンク経路=フラグメント鍵 / PIN経路=PIN派生で展開)
    let contentKey;
    if (rawKeyB64) {
      contentKey = await importContentKey(b64u.dec(rawKeyB64));
    } else {
      const pinKey = await derivePinKey(pin, sessionId);
      const raw = await unwrapContentKey(wrappedKey, pinKey).catch(() => null);
      if (!raw) throw new Error('PINが一致しません');
      contentKey = await importContentKey(raw);
    }

    // 4. メタ情報を復号
    const meta = await decryptMeta(contentKey, encMeta);
    $('recvFile').textContent = `${meta.name} — ${fmtSize(size)}`;

    // 5. 進捗WS
    activeWs = openWs(sessionId, 'receiver', receiverToken, () => {});

    // 6. 暗号文を取得して復号
    status.textContent = '授受中…';
    const res = await fetch(`/api/sessions/${sessionId}/blob`, { headers: { 'x-juju-token': receiverToken } });
    if (!res.ok) throw new Error('ファイルの取得に失敗しました');
    const blob = await decryptResponse(contentKey, res, meta.type, (done) => {
      bar.value = Math.round((done / Math.max(1, size)) * 100);
    });

    // 7. 保存
    downloadBlob(blob, meta.name);
    bar.value = 100;
    status.textContent = '✓ 授受完了(保存しました)';
  } catch (err) {
    console.error(err);
    status.textContent = `エラー: ${err.message || err}`;
  }
}

async function waitUploaded(id, timeoutMs = 180_000) {
  const start = Date.now();
  for (;;) {
    const r = await fetch(`/api/sessions/${id}`);
    if (!r.ok) throw new Error('セッションが見つからない/期限切れです');
    const s = await r.json();
    if (s.state === 'uploaded') return s;
    if (s.claimed) throw new Error('別のデバイスが既に受け取り中です');
    if (Date.now() - start > timeoutMs) throw new Error('タイムアウトしました');
    await sleep(1000);
  }
}

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name || 'download';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

// 起動
maybeAutoReceive();
