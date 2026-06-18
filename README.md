# net-scan-backend

A network scanner backend. An HTTP API accepts a list of IPs/CIDRs, fans the
work out over a RabbitMQ queue to worker processes, each worker fingerprints
every IP with a suite of network probes, and results stream back to clients over
Server-Sent Events.

## Architecture

Three decoupled processes communicate through Postgres and RabbitMQ:

- **API** (`src/main.py`, `src/api/`) — `POST /ping` validates/expands targets,
  creates a job, splits the IPs into batches, and publishes one message per
  batch. `POST /ping/{job_id}` is a paginated snapshot; `GET /ping/{job_id}/stream`
  is a resumable SSE tail.
- **Worker** (`python -m src.queue`) — consumes batches and fingerprints each IP
  via `scan_ip` (`src/core/scan/runner.py`), persisting results.
- **Postgres** is the result store and the streaming bus (`LISTEN`/`NOTIFY`).

Fingerprinting runs probes in three phases — reachability, primary services,
supplementary signals — re-scoring after each so a confident host short-circuits
before the slower phases run. See `src/core/scan/` and `CLAUDE.md`.

## Setup

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows; or: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                # then edit credentials
```

A reachable Postgres and RabbitMQ are required for an end-to-end run.

## Running

```bash
python -m scripts.init_db           # create/upgrade the schema (idempotent)
uvicorn src.main:app --reload       # API
python -m src.queue                 # worker (run at least one)
python -m scripts.reap              # delete jobs past the retention window
```

Run `scripts.reap` periodically (cron / k8s CronJob) to enforce
`SCANNER_DATABASE__RESULT_RETENTION_TIME_DAY` (default 30); deleting a job
cascades to its results.

### ICMP privileges (worker)

The worker pings hosts over a real ICMP socket instead of spawning `ping` per
host. On Linux this needs either the `CAP_NET_RAW` capability (raw socket) or a
permissive `net.ipv4.ping_group_range` (unprivileged datagram socket, e.g.
`sysctl -w net.ipv4.ping_group_range="0 2147483647"`). In Docker/Kubernetes,
grant `NET_RAW`. Without either — or on Windows — it transparently falls back to
the `ping` binary, so it still works, just slower.

## Tests

```bash
pytest
```

### End-to-end smoke test

Against a live Postgres + RabbitMQ, drives the whole flow (publish → worker →
persist → stream) and asserts results land and the stream emits `done`:

```bash
python -m scripts.init_db                 # once, if the schema isn't applied
python -m scripts.smoke 127.0.0.1 8.8.8.8 # defaults to these targets if omitted
```

## Lint

```bash
ruff check .          # lint
ruff check . --fix    # autofix
```

## API protection

- **Auth**: set `SCANNER_SECURITY__API_KEY` to require an `X-API-Key` header
  (empty = open, for development).
- **Rate limit**: `SCANNER_SECURITY__RATE_LIMIT_PER_MINUTE` (default 120, 0 to
  disable) throttles per client (API key, else client IP) and returns 429 when
  exceeded. It is **in-process** — behind N API replicas the effective limit is
  N×; put a shared limiter (gateway/Redis) in front if you need a global cap.
  Behind a proxy, the client IP is the proxy's unless you terminate/trust
  `X-Forwarded-For` upstream.

Configuration is environment-driven; see `.env.example` for all `SCANNER_*`
variables.
