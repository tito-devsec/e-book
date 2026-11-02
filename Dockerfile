FROM node:22-bookworm-slim

# fonts-dejavu-core: font for the per-buyer watermark stamped on PDF pages.
RUN apt-get update \
 && apt-get install -y --no-install-recommends fonts-dejavu-core ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src ./src
COPY public ./public
COPY migrations ./migrations
COPY scripts ./scripts

ENV NODE_ENV=production PORT=3000
RUN mkdir -p /var/lib/bookapp/storage && chown -R node:node /var/lib/bookapp
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD node -e "fetch('http://127.0.0.1:3000/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "src/server.js"]
