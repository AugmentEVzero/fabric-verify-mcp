// MCP wiring for Fabric Verify. Transport: stdio (runs on the user's machine).
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { FabricClient, FabricError, KINDS, TOPUP_AMOUNTS, VERIFY_URL, VERSION, loadConfig } from "./fabric.js";

export { VERSION };

const PROOF_MEANING =
  "A proof shows that this exact record existed, unchanged, by a certain time. It does not show that what the record describes is true.";

const INSTRUCTIONS = `Fabric Verify keeps a tamper-evident public log of what this agent did.
Each record is signed on this machine with the agent's own key. The summary text never leaves this machine; the public log permanently shows the agent name, key name, action kind, time, public key and a salted fingerprint of the summary. Never put personal data in the agent or key name.
${PROOF_MEANING}
record_action costs $0.005 of prepaid credit per call. Fetching proofs and checking the balance are free.
Record actions that matter (decisions, payments, approvals, deployments, data writes); don't record trivia.
Proofs usually become ready a few minutes after recording; check them with get_proof.`;

function ok(data) {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }], structuredContent: data };
}

function fail(e) {
  const msg = e instanceof FabricError ? e.message : "Unexpected error in the Fabric Verify tool.";
  if (!(e instanceof FabricError)) process.stderr.write(`fabric-verify-mcp: ${e?.name ?? "Error"}\n`);
  return { content: [{ type: "text", text: msg }], isError: true };
}

const guard = (fn) => async (args) => {
  try { return ok(await fn(args)); } catch (e) { return fail(e); }
};

export function createServer({ env = process.env, fetchImpl, sleep } = {}) {
  const cfg = loadConfig(env);
  const client = new FabricClient(cfg, { fetchImpl, sleep });
  const server = new McpServer({ name: "fabric-verify", title: "Fabric Verify", version: VERSION }, { instructions: INSTRUCTIONS });

  server.registerTool("record_action", {
    title: "Record an agent action (costs $0.005)",
    description:
      "Sign a record of an action this agent took and add it to the Fabric Verify public log. " +
      "Spends $0.005 of prepaid credit. The summary stays on this machine. The public log permanently shows the agent name, key name, kind, time, public key and a salted SHA-256 fingerprint of the summary. " +
      "Returns the record's log index; fetch its proof later with get_proof. " + PROOF_MEANING,
    inputSchema: {
      kind: z.enum(KINDS).describe("Type of action"),
      summary: z.string().min(1).max(16_000).describe("What the agent did, in plain words. Kept locally with the salt so the user can later show what the record was about. Not sent."),
      idempotency_key: z.string().regex(/^[\x21-\x7e]{8,128}$/).optional().describe("Optional. If a call fails, retry with the same value (and the same kind and summary): the exact same signed record is resent and charged at most once."),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, guard(({ kind, summary, idempotency_key }) => client.recordAction({ kind, summary, idempotencyKey: idempotency_key })));

  server.registerTool("get_proof", {
    title: "Get the proof for a record",
    description:
      "Fetch the public proof for a recorded action and save it next to the record, with the agent record needed to check it. Free. " +
      `Returns "pending" if the record is not in a public checkpoint yet (usually a few minutes). Anyone can check a saved proof offline with the verifier at ${VERIFY_URL}. ` +
      PROOF_MEANING,
    inputSchema: {
      index: z.number().int().min(0).describe("The log index returned by record_action"),
      wait_seconds: z.number().int().min(0).max(45).optional().describe("How long to wait for the proof if it is not ready yet (default 0, max 45). If still pending, call again later."),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, guard(async ({ index, wait_seconds }) => {
    const res = await client.getProof({ index, waitSeconds: wait_seconds ?? 0 });
    if (res.status === "ready") {
      res.check_offline = `augmentev-verify log-proof proof.json --pins fabric-log-v1.json --audit agent-record.json  (run in ${res.saved_to}; verifier and pins: ${VERIFY_URL})`;
    }
    return res;
  }));

  server.registerTool("check_balance", {
    title: "Check Fabric Verify credit",
    description: "Show the remaining prepaid credit, about how many records it covers, and this session's spend against its limit. Free.",
    inputSchema: {},
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, guard(() => client.checkBalance()));

  server.registerTool("buy_credit_link", {
    title: "Get a link to buy credit",
    description:
      "Create a card checkout link for adding Fabric Verify credit ($25, $50, $100 or $500; balance capped at $1,000; credit is non-refundable). " +
      "Nothing is charged by this tool: a person must open the link and pay. Give the link to the user; never try to pay it yourself.",
    inputSchema: { amount_usd: z.union(TOPUP_AMOUNTS.map((n) => z.literal(n))).describe("Top-up amount in US dollars") },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, guard(({ amount_usd }) => client.buyCreditLink({ amountUsd: amount_usd })));

  return { server, client, cfg };
}
