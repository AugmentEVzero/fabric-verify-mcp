// MCP wiring for Fabric Verify. Transport: stdio (runs on the user's machine).
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { FabricClient, FabricError, KINDS, LOG_KINDS, TOPUP_AMOUNTS, VERIFY_URL, VERSION, loadConfig } from "./fabric.js";
import { EVENTS } from "./agent-event.js";

export { VERSION };

const PROOF_MEANING =
  "A proof shows that this exact record existed, unchanged, by a certain time. It does not show that what the record describes is true.";

// The founder-approved privacy line (2026-10-26), in model-facing form.
const PRIVACY =
  "Action details stay private: the public log holds only a salted fingerprint of the payload, the action kind and time, and coded identifiers that only the user, or an auditor they give an audit pack to, can link to this agent.";
const HEX64 = /^[0-9a-f]{64}$/;
const ID = /^[\x21-\x7e]{1,256}$/;

const INSTRUCTIONS = `Fabric Verify keeps a tamper-evident public log of what this agent did.
Each record is signed on this machine with the agent's own key. The summary text never leaves this machine. Action details stay private: the public log holds only a salted fingerprint of the summary, the action kind and time, and coded identifiers that only the user, or an auditor they give an audit pack to, can link to this agent. Records are permanent. The agent and key names are kept by AugmentEV for audit packs, so never put personal data in them.
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
      "Spends $0.005 of prepaid credit. The summary stays on this machine. The public log permanently holds only a salted SHA-256 fingerprint of the summary, the action kind and time, and coded identifiers that only the user, or an auditor they give an audit pack to, can link to this agent. " +
      "Returns the record's log index; fetch its proof later with get_proof. " + PROOF_MEANING,
    inputSchema: {
      kind: z.enum(KINDS).describe("Type of action"),
      summary: z.string().min(1).max(16_000).describe("What the agent did, in plain words. Kept locally with the salt so the user can later show what the record was about. Not sent."),
      idempotency_key: z.string().regex(/^[\x21-\x7e]{8,128}$/).optional().describe("Optional. If a call fails, retry with the same value (and the same kind and summary): the exact same signed record is resent and charged at most once."),
      approval_record: z.string().regex(HEX64).optional().describe("Optional. The record (payload_sha256) of an approval, when the account's governance policy requires one for this kind."),
    },
    annotations: { title: "Record an agent action (costs $0.005)",  readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, guard(({ kind, summary, idempotency_key, approval_record }) => client.recordAction({ kind, summary, idempotencyKey: idempotency_key, approvalRecord: approval_record })));

  server.registerTool("record_event", {
    title: "Record an agent event (costs $0.005)",
    description:
      "Sign a structured record of one governed step and add it to the Fabric Verify log: a tool call, its result, an approval, a delegation, a policy decision, a halt, and so on (format augmentev/fabric-agent-event/v1). " +
      `Spends $0.005 of prepaid credit. The event stays on this machine with its salt. ${PRIVACY} ` +
      "Returns `record`: later events link to it (a tool call's approval_record, a tool result's request_record, parent_record). " +
      "For a tool call, give `body.tool` and `body.arguments` (hashed for you), or `action`; an approval of that call gives the same `action`, so both name the same action. " +
      "When the account's policy requires approval for tool calls, set body.approval_record and it is presented to the log. Bundle a run with export_events for an offline check. " +
      "The check shows each event was logged unchanged and every link points to an earlier event of the right type. It does not show that a described tool result is true.",
    inputSchema: {
      event: z.enum(EVENTS).describe("Event type"),
      body: z.record(z.string(), z.unknown()).describe("The event's fields. tool_call: tool, arguments (or arguments_sha256), optional server, call_id, approval_record. tool_result: request_record, is_error, result (or result_sha256), optional call_id. approval: approver_id, decision (approve/deny), action_sha256 or `action`. delegation: to_agent_id, task_sha256. Others: see the format."),
      kind: z.enum(LOG_KINDS).optional().describe("Only when the event allows several kinds (delegation: message_sent or decision; third_party_access: data_read, data_write or credential_use)."),
      action: z.object({ tool: z.string().min(1).max(1024), server: z.string().min(1).max(1024).optional(), arguments: z.unknown().optional() }).optional()
        .describe("For tool_call, approval and policy_decision: the tool, server and arguments the action is about. Fills action_sha256 by the published recipe, so a call and its approval match."),
      run_id: z.string().regex(ID).optional().describe("Your run identifier; export_events bundles a run by it."),
      step_id: z.string().regex(ID).optional(),
      parent_record: z.string().regex(HEX64).optional().describe("An earlier record this one follows from."),
      delegation_record: z.string().regex(HEX64).optional().describe("The delegation record that handed this agent its task."),
      idempotency_key: z.string().regex(/^[\x21-\x7e]{8,128}$/).optional().describe("Optional. Retry with the same value and the same event to resend the same signed record; charged at most once."),
    },
    annotations: { title: "Record an agent event (costs $0.005)", readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, guard((a) => client.recordEvent({
    event: a.event, kind: a.kind, body: a.body, action: a.action, runId: a.run_id, stepId: a.step_id,
    parentRecord: a.parent_record, delegationRecord: a.delegation_record, idempotencyKey: a.idempotency_key,
  })));

  server.registerTool("export_events", {
    title: "Bundle agent events for an offline check",
    description:
      "Gather agent events recorded from this machine, with their proofs and salts, into one file (augmentev/fabric-agent-events/v1) that anyone can check offline with `augmentev-verify agent-events`. Free. " +
      "Fetch each event's proof with get_proof first. The file discloses the events' contents to whoever receives it. " +
      "It shows the bundled events, not that the bundle holds every event: completeness comes from the account's governance export.",
    inputSchema: {
      run_id: z.string().regex(ID).optional().describe("Bundle every saved event of this run."),
      indices: z.array(z.number().int().min(0)).min(1).max(1000).optional().describe("Or bundle these log indices."),
    },
    annotations: { title: "Bundle agent events for an offline check", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, guard(async ({ run_id, indices }) => {
    const res = client.exportEvents({ runId: run_id, indices });
    res.check_offline = `augmentev-verify agent-events ${res.saved_to} --pins fabric-log-v1.json  (verifier and pins: ${VERIFY_URL})`;
    return res;
  }));

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
    annotations: { title: "Get the proof for a record",  readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
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
    annotations: { title: "Check Fabric Verify credit",  readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, guard(() => client.checkBalance()));

  server.registerTool("buy_credit_link", {
    title: "Get a link to buy credit",
    description:
      "Create a card checkout link for adding Fabric Verify credit ($25, $50, $100 or $500; balance capped at $1,000; credit is non-refundable). " +
      "Nothing is charged by this tool: a person must open the link and pay. Give the link to the user; never try to pay it yourself.",
    inputSchema: { amount_usd: z.union(TOPUP_AMOUNTS.map((n) => z.literal(n))).describe("Top-up amount in US dollars") },
    annotations: { title: "Get a link to buy credit",  readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, guard(({ amount_usd }) => client.buyCreditLink({ amountUsd: amount_usd })));

  return { server, client, cfg };
}
