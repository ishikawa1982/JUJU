# 授受 (JUJU) — HTTPSリレーをどこでも動かせるポータブルなコンテナ。
# RenderなどのPaaSはこのイメージを検出し、TLS(443)をホスト側で終端する。
FROM node:20-alpine

ENV NODE_ENV=production
WORKDIR /app

# 依存だけ先に入れてレイヤキャッシュを効かせる
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# アプリ本体
COPY server ./server
COPY public ./public

# PaaSは$PORTを注入する。既定は3000。
ENV PORT=3000
EXPOSE 3000

# 死活監視用
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:${PORT}/healthz || exit 1

CMD ["npm", "start"]
