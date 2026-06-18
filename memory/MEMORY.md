# Memory Index

- [AMQP port gotcha](amqp-port-gotcha.md) — RabbitMQ URL must use 5672 (AMQP), not 15672 (mgmt UI); a stuck `processed:0` job means wrong port or no worker running.
- [Classifier identity rules](classifier-identity-rules.md) — the scoring.py rewrite dropped old per-device heuristics; where brand/identity rules now live when a device misclassifies as generic linux.
