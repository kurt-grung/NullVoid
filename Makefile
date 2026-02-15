.PHONY: help build build-api api dashboard dev test lint install ml-serve ml-train

help:
	@echo "NullVoid - Makefile targets"
	@echo ""
	@echo "  make build      - Build TypeScript scanner"
	@echo "  make build-api  - Build API package"
	@echo "  make api        - Start API (builds first, port 3001)"
	@echo "  make dashboard  - Start dashboard dev server (proxies to API)"
	@echo "  make dev        - Start scanner in dev mode"
	@echo "  make test       - Run tests"
	@echo "  make lint       - Run linter"
	@echo "  make install    - Install dependencies"
	@echo "  make ml-serve   - Start ML model server (port 8000)"
	@echo "  make ml-train   - Train ML model"
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

ml-serve:
	npm run ml:serve

ml-train:
	npm run ml:train
