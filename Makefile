PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
UVICORN := $(VENV)/bin/uvicorn
NPM := npm --cache $(CURDIR)/.npm-cache

.PHONY: backend-install frontend-install install test-openclaw-plugin dev run-backend run-frontend test-backend build-frontend check docker-up docker-down

$(UVICORN): backend/requirements.txt
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -r backend/requirements.txt

frontend/node_modules/.bin/vite: frontend/package-lock.json frontend/package.json
	cd frontend && $(NPM) ci

backend-install: $(UVICORN)

frontend-install: frontend/node_modules/.bin/vite

install: backend-install frontend-install

test-openclaw-plugin:
	node --test openclaw-plugin/test/*.test.js

dev: $(UVICORN) frontend/node_modules/.bin/vite
	@trap 'kill $$backend_pid' EXIT INT TERM; \
	(cd backend && ../$(UVICORN) app.main:app --reload --host 0.0.0.0 --port 8000) & \
	backend_pid=$$!; \
	cd frontend && $(NPM) run dev -- --host 0.0.0.0 --port 5173

run-backend: $(UVICORN)
	cd backend && ../$(UVICORN) app.main:app --reload --host 0.0.0.0 --port 8000

run-frontend: frontend/node_modules/.bin/vite
	cd frontend && $(NPM) run dev -- --host 0.0.0.0 --port 5173

test-backend: $(UVICORN)
	cd backend && ../$(PYTEST)

build-frontend: frontend/node_modules/.bin/vite
	cd frontend && $(NPM) run build

check: test-backend test-openclaw-plugin build-frontend

docker-up:
	docker compose up --build

docker-down:
	docker compose down
