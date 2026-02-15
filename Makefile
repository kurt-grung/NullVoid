.PHONY: all help build build-api api dashboard dev test lint install ml-serve ml-train kill

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
	@echo "  make ml-serve   - Start ML model server (port 8000)"
	@echo "  make ml-train   - Train ML model"
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

ml-serve:
	npm run ml:serve

ml-train:
	npm run ml:train

kill:
	@-lsof -ti :3001 | xargs kill -9 2>/dev/null; true
	@-lsof -ti :5174 | xargs kill -9 2>/dev/null; true
	@-lsof -ti :8000 | xargs kill -9 2>/dev/null; true
	@echo "Killed processes on ports 3001, 5174, 8000"
