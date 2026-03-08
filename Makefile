PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
UVICORN := $(VENV)/bin/uvicorn

.PHONY: backend-install frontend-install install run-backend run-frontend test-backend build-frontend check docker-up docker-down

backend-install:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -r backend/requirements.txt

frontend-install:
	cd frontend && npm ci

install: backend-install frontend-install

run-backend:
	cd backend && ../$(UVICORN) app.main:app --reload --host 0.0.0.0 --port 8000

run-frontend:
	cd frontend && npm run dev -- --host 0.0.0.0 --port 5173

test-backend:
	cd backend && ../$(PYTEST)

build-frontend:
	cd frontend && npm run build

check: test-backend build-frontend

docker-up:
	docker compose up --build

docker-down:
	docker compose down
