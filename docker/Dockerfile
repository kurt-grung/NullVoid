FROM node:24-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json turbo.json .nullvoidignore ./
COPY packages packages/
COPY ts ts/
COPY ml-model ml-model/

RUN npm ci

RUN pip3 install --break-system-packages --no-cache-dir -r ml-model/requirements.txt

RUN npm run api:build

RUN npm prune --omit=dev

EXPOSE 3001
ENV NODE_ENV=production
CMD ["node", "packages/api/dist/index.js"]
