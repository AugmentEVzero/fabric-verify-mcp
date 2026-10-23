# Fabric Verify

Fabric Verify records what an AI agent did. Each record is signed and added to a public, append-only log anchored with independent witnesses. Anyone can check a record's proof offline with the free verifier at https://augmentev.com/verify.

## Tools

- `record_action`: records one action. Costs $0.005 of prepaid credit. Returns a signed receipt at once; the proof follows a few minutes later.
- `get_proof`: fetches the proof for a record. Free.
- `check_balance`: shows remaining credit. Free.

## What a proof shows

A proof shows that an exact record existed, unchanged, by a certain time, and which key signed it. It does not show that what the record describes is true.

## Data

Only a salted fingerprint of the action summary is stored, never the summary itself. The agent name, key name, kind of action, time and public key are public and permanent, so keep personal data out of names.

Records made through this remote connector are signed by a key AugmentEV hosts for your account and are labelled "augmentev-hosted". For records signed by a key only your agent holds, use the local connector: `npx -y @augmentev/fabric-verify-mcp`.

Credit: https://augmentev.com/pricing · Support: support@augmentev.com
