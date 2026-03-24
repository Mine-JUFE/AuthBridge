# ------------------------------
# 第一阶段：构建 CSS
# ------------------------------
FROM node:22-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build:css

# ------------------------------
# 第二阶段：生产最小镜像
# ------------------------------
FROM node:22-alpine

WORKDIR /app

# 安装生产依赖
COPY package*.json ./
RUN npm ci --only=production


COPY --from=builder /app/public     ./public
COPY --from=builder /app/views      ./views
COPY --from=builder /app/routes     ./routes
COPY --from=builder /app/middleware ./middleware
COPY --from=builder /app/services   ./services
COPY --from=builder /app/utils      ./utils
COPY --from=builder /app/scripts    ./scripts
COPY --from=builder /app/config     ./config

COPY --from=builder /app/server.js  ./
COPY --from=builder /app/app.js     ./

# 非 root 运行
USER node

EXPOSE 3000
CMD ["node", "server.js"]