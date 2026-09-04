# Convenience targets for running the stack without Docker.
# The Docker Compose path is `make up` / `docker compose up`.

PY := .venv/bin/python
PIP := .venv/bin/pip
ALEMBIC := cd backend && ../.venv/bin/alembic

.PHONY: help venv install migrate seed api web dev up down logs reset test verify-chain

help:
	@echo "Local (no Docker):"
	@echo "  make install      Create .venv (Python 3.11) and install backend deps"
	@echo "  make migrate      Apply Alembic migrations"
	@echo "  make seed         Seed 90 days of data (destructive: --reset)"
	@echo "  make api          Run the FastAPI server on :8000"
	@echo "  make web          Run the Vite dev server on :5173"
	@echo "  make verify-chain Walk the audit hash chain and report integrity"
	@echo ""
	@echo "Docker:"
	@echo "  make up           docker compose up --build"
	@echo "  make down         docker compose down"
	@echo "  make logs         docker compose logs -f api worker"

venv:
	@test -d .venv || python3.11 -m venv .venv

install: venv
	$(PIP) install --upgrade pip
	$(PIP) install -r backend/requirements.txt
	cd frontend && npm install

migrate:
	$(ALEMBIC) upgrade head

seed:
	$(PY) scripts/seed.py --reset

api:
	cd backend && ../.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

web:
	cd frontend && npm run dev

verify-chain:
	$(PY) scripts/verify_chain.py

up:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs -f api worker

test:
	cd backend && ../.venv/bin/pytest -q
