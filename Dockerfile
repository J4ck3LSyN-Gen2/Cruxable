FROM node:22-alpine
WORKDIR /app
# Install build essentials for native modules + wget for healthcheck
RUN apk add --no-cache python3 make g++ wget
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
# Ensure the runs directory exists for the delta engine
RUN mkdir -p /app/runs && chmod 755 /app/runs
EXPOSE 3117
HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
  CMD wget -qO- http://localhost:3117/ || exit 1
CMD ["node", "server.mjs"]