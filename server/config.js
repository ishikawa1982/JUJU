// 環境変数による設定。すべて任意で、安全なデフォルトを持つ。
const num = (v, d) => (v === undefined || v === '' ? d : Number(v));

export const config = {
  port: num(process.env.PORT, 3000),
  // セッション/一時ファイルの寿命(秒)。既定3分。
  ttlSec: num(process.env.JUJU_TTL_SEC, 180),
  // 1ファイルの最大サイズ(バイト)。既定 200MB。
  maxBytes: num(process.env.JUJU_MAX_MB, 200) * 1024 * 1024,
  // サーバー全体で同時に保持できる一時ファイル合計の上限(バイト)。既定 2GB。
  maxTotalBytes: num(process.env.JUJU_MAX_TOTAL_MB, 2048) * 1024 * 1024,
  // PIN解決(総当たり)に対するレート制限。
  resolveWindowMs: num(process.env.JUJU_RESOLVE_WINDOW_MS, 60_000),
  resolveMaxAttempts: num(process.env.JUJU_RESOLVE_MAX, 20),
  // 一時保存ディレクトリ。
  storageDir: process.env.JUJU_STORAGE_DIR || '.tmp-storage',
};
