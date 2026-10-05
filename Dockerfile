FROM node:22-bookworm-slim

WORKDIR /app
COPY package.json ./
COPY server.js ./
COPY public ./public

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "server.js"]
