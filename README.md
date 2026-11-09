# Prompt Guard

A Python project for detecting secrets and personally identifiable
information (PII) in text, with block, redact, and warn policies.

## Planned Structure

- app/detector.py: secret and PII detection
- app/policy.py: block, redact, and warn policies
- app/main.py: FastAPI service
- tests/test_detector.py: detector tests

## Status

Initial project structure created. Implementation is in progress.

## Known Limitations

### Hexadecimal secrets may be missed

The generic entropy detector uses a threshold greater than 4.0 bits
per character to avoid flagging hexadecimal hashes and public IDs.

As a trade-off, purely hexadecimal secrets, such as a random
32-character hex API key, will not be detected by the entropy rule.
Another applicable detection rule may still catch them.

Entropy is a heuristic: some harmless strings may be flagged,
and some secrets may be missed.