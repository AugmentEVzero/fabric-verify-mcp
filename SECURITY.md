# Security

Please report security issues privately to **support@augmentev.com**. Don't open a public issue.

## What this connector does with your data

- It signs each record on your computer with your agent's own Ed25519 key. That key never leaves your machine.
- It sends Fabric Verify only a salted SHA-256 fingerprint of the action summary, never the summary itself.
- The public log permanently shows the agent name, key name, kind of action, time and public key. Keep personal data out of names.

## What a proof shows

A proof shows that an exact record existed, unchanged, by a certain time, and which key signed it. It does not show that what the record describes is true.
