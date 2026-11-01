# Fabric Verify

Fabric Verify records what an AI agent did. Each record is signed and added to a public, append-only log anchored with independent witnesses. Anyone can check a record's proof offline with the free verifier at https://augmentev.com/verify.

## Tools

- `record_action`: records one action. Costs $0.005 of prepaid credit. Returns a signed receipt at once; the proof follows a few minutes later.
- `record_event`: records one structured agent event (a tool call, its result, an approval, a delegation, a halt and so on). Costs $0.005 of prepaid credit. Returns the event with its salt for you to keep; with each record's proof it forms a bundle anyone can check offline with `augmentev-verify agent-events`.
- `get_proof`: fetches the proof for a record. Free.
- `check_balance`: shows remaining credit. Free.

## What a proof shows

A proof shows that an exact record existed, unchanged, by a certain time, and which key signed it. It does not show that what the record describes is true.

## Data

Only a salted fingerprint of the action summary is stored, never the summary itself. Action details stay private: the public log holds only a salted fingerprint, the action kind and time, and coded identifiers that only you, or an auditor you give an audit pack to, can link to your assistant. Records are permanent. Keep personal data out of agent names.

Records made through this remote connector are signed by a key AugmentEV hosts for your account and are labelled "augmentev-hosted". For records signed by a key only your agent holds, use the local connector: `npx -y @augmentev/fabric-verify-mcp`.

Credit: https://augmentev.com/pricing · Support: support@augmentev.com
