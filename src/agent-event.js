// Agent events (augmentev/fabric-agent-event/v1): a record's payload that
// describes a tool call, approval, delegation, policy decision or other
// governed step, so a reviewer can check it offline with
// `augmentev-verify agent-events`. Spec: docs/fabric-verify/governance/FORMATS.md §1.
//
// The log's leaf is unchanged: an event is an ordinary record whose salted
// payload hash commits to these bytes. checkEvent mirrors the verifier's
// schema check (verifier/crates/fabric/src/agent_event.rs) so a client never
// signs an event the verifier would call INVALID; links are checked there.
//
// This file is shared word for word by ops/fabric/mcp and ops/fabric/mcp-remote
// (a test keeps the copies equal). WebCrypto only: Node 20+ and Workers.

export const EVENT_FORMAT = "augmentev/fabric-agent-event/v1";
export const BUNDLE_FORMAT = "augmentev/fabric-agent-events/v1";
/** Recommended recipe for action_sha256 (§1.3); the verifier only compares digests. */
export const ACTION_FORMAT = "augmentev/fabric-action/v1";
/** The verifier refuses larger payloads. */
export const MAX_EVENT_BYTES = 65_536;

/** Every v1 event type and the signed action kinds it may be recorded under (first = default). */
export const EVENT_KINDS = {
  model_call: ["model_output"],
  tool_call: ["tool_call"],
  tool_result: ["other", "tool_call"], // `other` first: a policy gating tool_call does not gate results
  delegation: ["message_sent", "decision"],
  approval: ["approval"],
  authorization: ["approval"],
  policy_set: ["proxy_policy"],
  policy_decision: ["decision"],
  halt: ["decision"],
  resume: ["decision"],
  third_party_access: ["data_read", "data_write", "credential_use"],
  model_change: ["deployment"],
  engine_change: ["deployment"],
};
export const EVENTS = Object.keys(EVENT_KINDS);

export class EventError extends Error {}

const enc = new TextEncoder();
const MAX_SAFE = Number.MAX_SAFE_INTEGER; // 2^53 - 1, the verifier's limit
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/; // Rust char::is_control (Cc)
const HEX64 = /^[0-9a-f]{64}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

/**
 * RFC 8785 canonical JSON for objects, arrays, strings, integers, booleans and
 * null. Like the verifier, it refuses floats and integers beyond ±(2^53 − 1).
 */
export function canonicalJson(v) {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean": return v ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(v)) throw new EventError("only integers up to 2^53 - 1 can be hashed (no floats)");
      return String(v);
    case "string":
      if (LONE_SURROGATE.test(v)) throw new EventError("a string holds an unpaired surrogate");
      return JSON.stringify(v);
    case "object":
      if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
      // Default sort compares UTF-16 code units, as RFC 8785 requires.
      return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort()
        .map((k) => `${canonicalJson(k)}:${canonicalJson(v[k])}`).join(",")}}`;
    default:
      throw new EventError(`a ${typeof v} cannot be hashed`);
  }
}

export async function sha256Hex(bytes) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** SHA-256 of a value's canonical JSON: what `arguments_sha256` and `result_sha256` hold. */
export const jsonSha256 = (v) => sha256Hex(enc.encode(canonicalJson(v)));

/**
 * The recommended action digest: SHA-256 of the canonical JSON of
 * {format, tool, server?, arguments_sha256}. The approver and the agent compute
 * it from the same tool, server and arguments, so a tool call and its approval
 * name the same action without disclosing the arguments.
 */
export async function actionSha256({ tool, server, arguments: args, arguments_sha256 }) {
  const a = arguments_sha256 ?? (await jsonSha256(args === undefined ? null : args));
  return jsonSha256({ format: ACTION_FORMAT, tool, ...(server == null ? {} : { server }), arguments_sha256: a });
}

/** The signed kind for an event: the given one if the event allows it, else the default. */
export function eventKind(event, kind) {
  const kinds = EVENT_KINDS[event];
  if (!kinds) throw new EventError(`event must be one of: ${EVENTS.join(", ")}`);
  if (kind == null) return kinds[0];
  if (!kinds.includes(kind)) throw new EventError(`a ${event} event is recorded as ${kinds.join(" or ")}, not ${kind}`);
  return kind;
}

// ---------------------------------------------------------------- schema

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const idOk = (s) => s.length >= 1 && s.length <= 256 && /^[\x21-\x7e]+$/.test(s);
const textOk = (s) => s.length > 0 && enc.encode(s).length <= 1024 && !CONTROL.test(s);

/** Field rules: [type, required]. A type is a checker name or a list of allowed values. */
const BODIES = {
  model_call: { model: ["text", 1], input_sha256: ["hex", 1], output_sha256: ["hex"], model_manifest_sha256: ["hex"], engine: ["text"], attested_run_id: ["id"] },
  tool_call: { tool: ["text", 1], arguments_sha256: ["hex", 1], action_sha256: ["hex", 1], server: ["text"], call_id: ["id"], arguments: ["json"], approval_record: ["hex"], policy_sha256: ["hex"] },
  tool_result: { request_record: ["hex", 1], result_sha256: ["hex", 1], is_error: ["bool", 1], call_id: ["id"], result: ["json"] },
  delegation: { to_agent_id: ["id", 1], task_sha256: ["hex", 1], scope: ["text"] },
  approval: { approver_id: ["id", 1], decision: [["approve", "deny"], 1], action_sha256: ["hex", 1], reason: ["text"], sensitive_category: ["id"] },
  authorization: { subject_id: ["id", 1], grant: ["text", 1], scope: ["text"], expires_at: ["time"] },
  policy_set: { policy_sha256: ["hex", 1], policy_version: ["version", 1] },
  policy_decision: { policy_sha256: ["hex", 1], decision: [["allow", "deny"], 1], rule_id: ["id", 1], reason_code: ["id", 1], policy_record: ["hex"], action_sha256: ["hex"] },
  halt: { scope: [["tenant", "agent"], 1], reason_code: ["id", 1], by: [["customer", "operator"], 1], target_agent_id: ["id"] },
  third_party_access: { counterparty: ["text", 1], endpoint: ["text", 1], direction: [["inbound", "outbound"], 1], session_id: ["id"], auth_time: ["time"], resources: ["texts"], origin_ip_sha256: ["hex"], outcome: [["allowed", "denied"]] },
  model_change: { new: ["identity", 1], prior: ["identity"], reason_code: ["id"] },
};
BODIES.resume = BODIES.halt;
BODIES.engine_change = BODIES.model_change;
const TOP = { format: 1, event: 1, actor: 1, body: 1, run_id: 0, step_id: 0, parent_record: 0, origin: 0, ext: 0 };
const ACTOR = { agent_id: ["id", 1], key_id: ["id"], delegation_record: ["hex"] };
const ORIGIN = { deployment: ["text"], app_id: ["id"], compose_sha256: ["hex"], image_digest: ["digest"], environment: ["id"], region: ["id"] };
const IDENTITY = { model_manifest_sha256: ["hex"], compose_sha256: ["hex"], image_digest: ["digest"], engine: ["text"] };

function fields(errs, path, obj, rules) {
  if (!isObj(obj)) return void errs.push(`${path} must be an object`);
  for (const k of Object.keys(obj)) if (!(k in rules)) errs.push(`${path}.${k} is not a v1 field`);
  for (const [k, [type, required]] of Object.entries(rules)) {
    const v = obj[k];
    const f = `${path}.${k}`;
    if (v == null) { // the verifier reads null as absent
      if (required) errs.push(`${f} is required`);
      continue;
    }
    const str = typeof v === "string";
    if (Array.isArray(type)) { if (!(str && type.includes(v))) errs.push(`${f} must be one of ${type.join(", ")}`); continue; }
    switch (type) {
      case "id": if (!(str && idOk(v))) errs.push(`${f} must be 1 to 256 printable ASCII characters without spaces`); break;
      case "text": if (!(str && textOk(v))) errs.push(`${f} must be 1 to 1024 characters without control characters`); break;
      case "hex": if (!(str && HEX64.test(v))) errs.push(`${f} must be 64 lowercase hex characters`); break;
      case "digest": if (!(str && v.startsWith("sha256:") && HEX64.test(v.slice(7)))) errs.push(`${f} must be sha256: followed by 64 lowercase hex characters`); break;
      case "time": if (!(str && v.length <= 30 && TIME.test(v))) errs.push(`${f} must be RFC 3339 UTC ending in Z`); break;
      case "bool": if (typeof v !== "boolean") errs.push(`${f} must be true or false`); break;
      case "version": if (!(Number.isSafeInteger(v) && v >= 1 && v <= MAX_SAFE)) errs.push(`${f} must be from 1 to 2^53 - 1`); break;
      case "json": try { canonicalJson(v); } catch { errs.push(`${f} is not canonicalisable (floats or integers beyond 2^53)`); } break;
      case "texts":
        if (!Array.isArray(v)) { errs.push(`${f} must be a list`); break; }
        if (v.length > 256) errs.push(`${f} holds at most 256 entries`);
        for (const x of v) if (!(typeof x === "string" && textOk(x))) errs.push(`${f}[] must be 1 to 1024 characters without control characters`);
        break;
      case "identity":
        fields(errs, f, v, IDENTITY);
        if (isObj(v) && Object.keys(IDENTITY).every((x) => v[x] == null)) errs.push(`${f} names nothing`);
        break;
    }
  }
}

/** Schema errors for an event document (empty when the verifier would accept its shape). */
export function checkEvent(doc) {
  const errs = [];
  if (!isObj(doc)) return ["the event must be a JSON object"];
  if (doc.format !== EVENT_FORMAT) return [`format must be ${EVENT_FORMAT}`];
  if (!BODIES[doc.event]) return [`event must be one of: ${EVENTS.join(", ")}`];
  for (const k of Object.keys(doc)) if (!(k in TOP)) errs.push(`${k} is not a v1 field (put later fields in ext)`);
  fields(errs, "actor", doc.actor, ACTOR);
  for (const k of ["run_id", "step_id"]) if (doc[k] != null && !(typeof doc[k] === "string" && idOk(doc[k]))) errs.push(`${k} must be 1 to 256 printable ASCII characters without spaces`);
  if (doc.parent_record != null && !(typeof doc.parent_record === "string" && HEX64.test(doc.parent_record))) errs.push("parent_record must be 64 lowercase hex characters");
  if (doc.origin != null) fields(errs, "origin", doc.origin, ORIGIN);
  if (doc.ext != null && !isObj(doc.ext)) errs.push("ext must be an object");
  fields(errs, "body", doc.body, BODIES[doc.event]);
  const b = isObj(doc.body) ? doc.body : {};
  if ((doc.event === "halt" || doc.event === "resume") && (b.scope === "agent") !== (b.target_agent_id != null)) {
    errs.push("body.target_agent_id is required for scope agent, and only then");
  }
  return errs;
}

/** Disclosed arguments/result that do not hash to their digests (the verifier's check). */
export async function checkDisclosed(doc) {
  const b = doc.body;
  const pairs = doc.event === "tool_call" ? [["arguments", "arguments_sha256"]] : doc.event === "tool_result" ? [["result", "result_sha256"]] : [];
  const errs = [];
  for (const [v, d] of pairs) {
    if (b[v] != null && (await jsonSha256(b[v])) !== b[d]) errs.push(`body.${v} is disclosed but does not hash to body.${d}`);
  }
  return errs;
}

const drop = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v != null));

/**
 * Build an event's payload. Fills `arguments_sha256` / `result_sha256` from
 * disclosed values, and `action_sha256` from `action` ({tool, server?,
 * arguments}) by the recommended recipe when it is not given. Throws
 * EventError with every problem when the verifier would refuse the shape.
 * Returns { doc, payload } where payload is the canonical JSON text.
 */
export async function buildEvent({ event, agentId, keyId, body = {}, runId, stepId, parentRecord, delegationRecord, origin, ext, action }) {
  if (!EVENT_KINDS[event]) throw new EventError(`event must be one of: ${EVENTS.join(", ")}`);
  if (!isObj(body)) throw new EventError("body must be an object");
  const b = drop(body);
  try {
    if (event === "tool_call") {
      if (action) { b.tool ??= action.tool; if (action.server != null) b.server ??= action.server; if (action.arguments !== undefined) b.arguments ??= action.arguments; }
      if (b.arguments !== undefined && b.arguments_sha256 == null) b.arguments_sha256 = await jsonSha256(b.arguments);
      if (b.action_sha256 == null && typeof b.tool === "string" && b.arguments_sha256 != null) {
        b.action_sha256 = await actionSha256({ tool: b.tool, server: b.server, arguments_sha256: b.arguments_sha256 });
      }
    } else if (action && b.action_sha256 == null && (event === "approval" || event === "policy_decision")) {
      b.action_sha256 = await actionSha256(action);
    }
    if (event === "tool_result" && b.result !== undefined && b.result_sha256 == null) b.result_sha256 = await jsonSha256(b.result);
  } catch (e) {
    throw e instanceof EventError ? new EventError(`body: ${e.message}`) : e;
  }
  const doc = drop({
    format: EVENT_FORMAT, event,
    actor: drop({ agent_id: agentId, key_id: keyId, delegation_record: delegationRecord }),
    run_id: runId, step_id: stepId, parent_record: parentRecord, origin, ext, body: b,
  });
  const errs = checkEvent(doc);
  if (!errs.length) errs.push(...(await checkDisclosed(doc)));
  if (errs.length) throw new EventError(`not a valid ${event} event: ${errs.join("; ")}`);
  const payload = canonicalJson(doc);
  if (enc.encode(payload).length > MAX_EVENT_BYTES) throw new EventError(`the event is larger than ${MAX_EVENT_BYTES} bytes; disclose less (keep only the digests)`);
  return { doc, payload };
}
