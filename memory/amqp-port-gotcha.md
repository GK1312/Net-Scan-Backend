---
name: amqp-port-gotcha
description: SCANNER_QUEUE__URL must use AMQP port 5672, not management port 15672
metadata:
  type: feedback
---

`SCANNER_QUEUE__URL` (RabbitMQ) must point at the AMQP protocol port **5672**, not the management web UI port **15672**. The local `.env` had it set to `amqp://...@localhost:15672/`, which silently broke publishing — jobs got a `job_id` but batches never landed on `scan_queue`, so `processed` stuck at `0/N` forever in the SSE stream.

**Why:** RabbitMQ listens on both ports (5672 = AMQP, 15672 = HTTP management). Speaking AMQP to 15672 fails/hangs but the symptom is silent: the API still creates the job row and returns a `job_id`.

**How to apply:** When a scan job shows `processed: 0` and never advances, check (1) the AMQP URL port is 5672, and (2) a worker process (`python -m src.queue`) is actually running and consuming — the API (`uvicorn`) alone is not enough. Verify with `rabbitmqctl list_queues name messages consumers`.
