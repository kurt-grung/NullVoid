.PHONY: all help build build-api api dashboard dev test lint install serve train ml-serve ml-train kill

all: dashboard

help:
	@echo "NullVoid - Makefile targets"
	@echo ""
	@echo "  make            - Start dashboard (default)"
	@echo "  make dashboard  - Start dashboard dev server (proxies to API)"
	@echo "  make build      - Build TypeScript scanner"
	@echo "  make build-api  - Build API package"
	@echo "  make api        - Start API (builds first, port 3001)"
	@echo "  make dev        - Start scanner in dev mode"
	@echo "  make test       - Run tests"
	@echo "  make lint       - Run linter"
	@echo "  make install    - Install dependencies"
	@echo "  make serve      - Start ML model server via nullvoid serve (port 8000)"
	@echo "  make train      - Train ML model via nullvoid train"
	@echo "  make kill       - Kill API (3001), dashboard (5174), ML server (8000)"
	@echo ""

build:
	npm run build

build-api:
	npm run api:build

api:
	npm run api:start

dashboard:
	API_PROXY_TARGET=http://localhost:3001 npm run dashboard:dev

dev:
	npm run dev

test:
	npm run test

lint:
	npm run lint

install:
	npm install

serve:
	node ts/dist/bin/nullvoid.js serve --port 8000

train:
	node ts/dist/bin/nullvoid.js train --input train.jsonl --output model.pkl

# Backward-compatible aliases
ml-serve: serve

ml-train: train

kill:
	@-lsof -ti :3001 | xargs kill -9 2>/dev/null; true
	@-lsof -ti :5174 | xargs kill -9 2>/dev/null; true
	@-lsof -ti :8000 | xargs kill -9 2>/dev/null; true
	@echo "Killed processes on ports 3001, 5174, 8000"
