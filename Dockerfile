# NullVoid API - Node + Python for ML commands (ml:train, ml:export, etc.)
FROM node:20-bookworm-slim

# Install Python and pip for ml-model (train.py, export-features.js, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files and workspace structure for npm ci
COPY package.json package-lock.json turbo.json ./
COPY packages packages/
COPY ts ts/
COPY js js/
COPY ml-model ml-model/

# Install Node deps
RUN npm ci --omit=dev

# Install Python deps for ml-model (joblib, xgboost, scikit-learn, etc.)
RUN pip3 install --no-cache-dir -r ml-model/requirements.txt

# Build API (produces packages/api/dist, ts/dist)
RUN npm run api:build

EXPOSE 3001
ENV NODE_ENV=production
CMD ["node", "packages/api/dist/index.js"]
