# Fabric Verify MCP server

Give your AI agent a tamper-evident record of what it did.

Each time the agent records an action, this server signs a short record **on your machine, with the agent's own key**, and adds it to the Fabric Verify public log. Later you get a **proof** that anyone can check offline, without trusting you or us.

A proof shows that **this exact record existed, unchanged, by a certain time.** It does not show that what the record describes is true.

Your text stays with you. Each record sends a salted fingerprint of it, plus the signature. The public log permanently shows the **agent name, key name, action kind, time and public key** with every record, so never put personal data in `FABRIC_AGENT` or `FABRIC_KID`.

## Price

| Tool | Cost |
|---|---|
| `record_action` | $0.005 per record, from prepaid credit |
| `get_proof`, `check_balance`, `buy_credit_link` | free |

Buy credit by card at <https://augmentev.com/pricing#buy>. Your credit key (`fvk_…`) is shown once after payment, so save it in a password manager.

## Install

You need Node.js 20 or later. Add this to your MCP client's configuration:

```json
{
  "mcpServers": {
    "fabric-verify": {
      "command": "npx",
      "args": ["-y", "@augmentev/fabric-verify-mcp"],
      "env": {
        "FABRIC_CREDIT_KEY": "fvk_...",
        "FABRIC_AGENT": "my-agent"
      }
    }
  }
}
```

In Claude Code:

```bash
claude mcp add fabric-verify --env FABRIC_CREDIT_KEY=fvk_... --env FABRIC_AGENT=my-agent -- npx -y @augmentev/fabric-verify-mcp
```

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `FABRIC_CREDIT_KEY` | (required) | Your credit key. Keep it secret. |
| `FABRIC_AGENT` | `mcp-agent` | A stable name for this agent (printable ASCII, no spaces). |
| `FABRIC_KID` | `<agent>-key-1` | A name for the agent's signing key. Change it when you rotate the key. |
| `FABRIC_HOME` | `~/.fabric-verify` | Where the agent key and your records are kept (private to your user). |
| `FABRIC_MAX_SPEND_USD` | `1` | The most this server may spend in one session. |

## Tools

- **`record_action`** (`kind`, `summary`, optional `idempotency_key`): signs and logs one record, then returns its log index. The summary and its salt are saved under `FABRIC_HOME/records/<api host>/<index>/`, so you can later show what the record was about. If a call fails, call again with the same `idempotency_key`, `kind` and `summary`: the exact same signed record is resent and charged at most once.
- **`get_proof`** (`index`, optional `wait_seconds` up to 45): fetches the proof and saves it next to the record. Proofs are usually ready a few minutes after recording.
- **`check_balance`**: shows your remaining credit and this session's spend.
- **`buy_credit_link`** (`amount_usd`: 25, 50, 100 or 500): returns a card checkout link for a person to open. This tool charges nothing.

## Check a proof

Download the verifier and the published log keys from <https://augmentev.com/verify>, then run this in the record's folder:

```bash
augmentev-verify log-proof proof.json --pins fabric-log-v1.json --audit agent-record.json
```

## Pin the version

For production agents, pin an exact version, such as `npx -y @augmentev/fabric-verify-mcp@0.1.1`, and update deliberately. The package ships a lockfile (`npm-shrinkwrap.json`) so its dependencies are fixed too.

## Keep your agent key

The agent key is `FABRIC_HOME/agent-ed25519.pem`. Back it up. Each key name (`FABRIC_KID`) belongs to one key for good. If you lose the key, set a new `FABRIC_KID`.

## Support

support@augmentev.com

## Licence

Apache-2.0. "Fabric Verify" and "AugmentEV" are trademarks of AugmentEV Inc.; the licence grants no rights to them.
