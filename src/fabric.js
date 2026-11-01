// Fabric Verify client core: agent key, record signing, REST calls, local evidence store.
// The agent's private key never leaves this machine. The credit key is sent only as a
// bearer header to the configured API and is never logged or returned to the model.
//
// What goes to the public log for each record (and stays there): the agent name, the key
// name (kid), the action kind, the agent's clock time, the public key, the signature and a
// salted SHA-256 fingerprint of the summary. The summary text and salt stay on this machine.
import { generateKeyPairSync, createPrivateKey, createPublicKey, sign, randomBytes, createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, renameSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { BUNDLE_FORMAT, EventError, buildEvent, eventKind } from "./agent-event.js";

export const VERSION = "0.2.0";
export const CONTEXT = "augmentev-fabric-log-statement-v1\n";
export const KINDS = [
  "tool_call", "model_output", "message_sent", "data_read", "data_write", "file_write",
  "payment", "approval", "decision", "credential_use", "deployment", "other",
];
/** Kinds a record may be signed under: KINDS plus proxy_policy, which only policy_set events use. */
export const LOG_KINDS = [...KINDS, "proxy_policy"];
export const PRICE_MICROS = 5_000; // $0.005 per record
export const TOPUP_AMOUNTS = [25, 50, 100, 500];
export const BUY_URL = "https://augmentev.com/pricing#buy";
export const VERIFY_URL = "https://augmentev.com/verify";
const CHECKOUT_HOSTS = new Set(["checkout.stripe.com"]);
const NAME_RE = /^[\x21-\x7e]{1,256}$/; // printable ASCII, no spaces

export class FabricError extends Error {
  constructor(message, { status, code, retryable = false } = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryable = retryable;
  }
}

// C0/C1 controls and the Unicode line/paragraph separators.
const CONTROL_RE = new RegExp("[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]", "g");
/** Server-provided text that reaches the model: printable, short. */
export function clean(text, max = 200) {
  return String(text ?? "").replace(CONTROL_RE, " ").slice(0, max);
}

/** Retry-After in seconds, clamped to 1..60 (default 60 when missing or not a number). */
export function retryAfterSeconds(headers, fallback = 60) {
  const raw = headers.get("retry-after");
  const n = raw == null || raw.trim() === "" ? NaN : Number(raw);
  return Number.isFinite(n) ? Math.min(60, Math.max(1, Math.round(n))) : fallback;
}

export function loadConfig(env = process.env) {
  const agent = env.FABRIC_AGENT || "mcp-agent";
  const cfg = {
    api: (env.FABRIC_API || "https://api.augmentev.ai").replace(/\/+$/, ""),
    creditKey: env.FABRIC_CREDIT_KEY || "",
    agent,
    kid: env.FABRIC_KID || `${agent}-key-1`,
    home: env.FABRIC_HOME || join(homedir(), ".fabric-verify"),
    maxSpendMicros: Math.round(Number(env.FABRIC_MAX_SPEND_USD ?? "1") * 1_000_000),
  };
  if (!NAME_RE.test(cfg.agent)) throw new FabricError("FABRIC_AGENT must be printable ASCII without spaces, up to 256 characters");
  if (!NAME_RE.test(cfg.kid)) throw new FabricError("FABRIC_KID must be printable ASCII without spaces, up to 256 characters");
  if (!Number.isFinite(cfg.maxSpendMicros) || cfg.maxSpendMicros < 0) throw new FabricError("FABRIC_MAX_SPEND_USD must be a number >= 0");
  const u = new URL(cfg.api);
  const local = u.hostname === "127.0.0.1" || u.hostname === "localhost";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) throw new FabricError("FABRIC_API must use https (http only for localhost)");
  cfg.apiHost = u.host.replace(/[^A-Za-z0-9.-]/g, "_");
  return cfg;
}

function ensurePrivateDir(dir) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
}

function writePrivate(path, data) {
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  writeFileSync(tmp, data, { mode: 0o600, flag: "wx" });
  renameSync(tmp, path);
}

/** Load the agent's Ed25519 key from FABRIC_HOME, creating it (0600) on first use. */
export function loadAgentKey(home) {
  ensurePrivateDir(home);
  const path = join(home, "agent-ed25519.pem");
  if (!existsSync(path)) {
    const { privateKey } = generateKeyPairSync("ed25519");
    try {
      writeFileSync(path, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600, flag: "wx" });
      return privateKey;
    } catch (e) {
      if (e.code !== "EEXIST") throw e; // another instance created it first: use theirs
    }
  }
  const mode = statSync(path).mode & 0o777;
  if (mode & 0o077) chmodSync(path, 0o600); // tighten if someone loosened it
  return createPrivateKey(readFileSync(path));
}

export function publicKeyHex(sk) {
  return createPublicKey(sk).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
}

// Canonical JSON for the statement: keys sorted, no spaces (RFC 8785 for these ASCII fields).
export const canonical = (o) => JSON.stringify(Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]])));

export function utcSeconds(d = new Date()) {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Build and sign one record. The payload itself is never part of the request. */
export function makeRecord(sk, { agent, kid, kind, payload, now = new Date(), salt = randomBytes(32) }) {
  if (!LOG_KINDS.includes(kind)) throw new FabricError(`kind must be one of: ${KINDS.join(", ")}`);
  const statement = {
    agent, kid, kind,
    payload_sha256: createHash("sha256").update(salt).update(payload).digest("hex"),
    client_time: utcSeconds(now),
  };
  const msg = Buffer.concat([Buffer.from(CONTEXT), Buffer.from(canonical({ ...statement, v: 1 }))]);
  const sig = sign(null, msg, sk).toString("hex");
  return { body: { statement, sig_alg: "ed25519", sig, public_key: publicKeyHex(sk) }, salt };
}

export class FabricClient {
  constructor(cfg, { fetchImpl = (...a) => globalThis.fetch(...a), sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
    this.cfg = cfg;
    this.fetch = fetchImpl;
    this.sleep = sleep;
    this.spentMicros = 0; // charged
    this.reservedMicros = 0; // in flight (counted against the cap before sending)
    this._sk = null;
  }

  get sk() {
    if (!this._sk) this._sk = loadAgentKey(this.cfg.home);
    return this._sk;
  }

  requireKey() {
    if (!this.cfg.creditKey) {
      throw new FabricError(`No credit key configured. Buy credit at ${BUY_URL} (the key is shown once after payment), then set FABRIC_CREDIT_KEY in this server's environment.`, { code: "no_credit_key" });
    }
  }

  headers(extra = {}) {
    return { authorization: `Bearer ${this.cfg.creditKey}`, accept: "application/json", "user-agent": `fabric-verify-mcp/${VERSION}`, ...extra };
  }

  async request(method, path, { body, headers = {}, retries = 0 } = {}) {
    this.requireKey();
    for (let attempt = 0; ; attempt++) {
      let r;
      try {
        r = await this.fetch(`${this.cfg.api}${path}`, {
          method,
          headers: this.headers(body ? { "content-type": "application/json", ...headers } : headers),
          body: body ? JSON.stringify(body) : undefined,
          redirect: "error", // never follow a redirect with the credit key
          signal: AbortSignal.timeout(30_000),
        });
      } catch (e) {
        if (attempt < retries) { await this.sleep(500 * 2 ** attempt); continue; }
        throw new FabricError(`Network error calling Fabric Verify: ${e.name === "TimeoutError" ? "timed out" : "request failed"}`, { retryable: true });
      }
      if (r.status === 503 && attempt < retries) {
        await this.sleep(Math.min(retryAfterSeconds(r.headers, 1), 10) * 1000 * (attempt + 1));
        continue;
      }
      return r;
    }
  }

  async errorFrom(r) {
    let code, message, j = {};
    try {
      j = await r.json();
      code = clean(j.error ?? j.code, 64);
      message = clean(j.message ?? j.detail);
    } catch { /* non-JSON body */ }
    const map = {
      401: `The credit key was rejected (invalid_key). Check FABRIC_CREDIT_KEY.`,
      402: `Not enough credit (or no key sent). Add credit with the buy_credit_link tool, or at ${BUY_URL}.`,
      403: "This account is frozen. Contact support@augmentev.com.",
      409: `Conflict with an earlier request${message ? `: ${message}` : ""}.`,
      413: "The request is too large.",
      429: "Too many requests. Wait and retry.",
      503: "Fabric Verify is temporarily unavailable.",
    };
    if (r.status === 403 && code === "governance_refused") {
      map[403] = `Refused by this account's governance policy or a halt (rule ${clean(j.rule_id, 32) || "unknown"}, reason ${clean(j.reason_code, 64) || "unknown"}). Nothing was charged or recorded.`;
    }
    if (r.status === 409 && /already registered with a different public key/.test(message ?? "")) {
      map[409] = `The key name "${this.cfg.kid}" is already bound to a different agent key (each key name belongs to one key, forever). ` +
        `Restore the original agent-ed25519.pem in ${this.cfg.home}, or set a new FABRIC_KID such as "${this.cfg.agent}-key-2".`;
    }
    const text = map[r.status] ?? `Fabric Verify returned HTTP ${r.status}${message ? `: ${message}` : ""}`;
    return new FabricError(text, { status: r.status, code, retryable: r.status === 503 || r.status === 429 });
  }

  pendingPath(idem) {
    const dir = join(this.cfg.home, "pending", this.cfg.apiHost);
    ensurePrivateDir(join(this.cfg.home, "pending"));
    ensurePrivateDir(dir);
    return join(dir, `${createHash("sha256").update(idem).digest("hex").slice(0, 32)}.json`);
  }

  /**
   * The `governance` part of an append: the approval is presented only when the
   * account's policy gates this kind (naming one for an ungated kind is refused).
   */
  async governanceFor(kind, approvalRecord) {
    if (!approvalRecord) return undefined;
    const r = await this.request("GET", "/v1/governance/policy", { retries: 2 });
    if (!r.ok) return undefined; // no policy service: the record still links its approval
    const j = await r.json().catch(() => ({}));
    return j?.policy?.approval?.kinds?.includes(kind) ? { approval_record: approvalRecord } : undefined;
  }

  /** Sign and append one record. Spends $0.005 of credit. */
  async recordAction({ kind, summary, idempotencyKey, approvalRecord, event }) {
    this.requireKey();
    // Reserve before sending, so parallel calls cannot overshoot the session cap.
    if (this.spentMicros + this.reservedMicros + PRICE_MICROS > this.cfg.maxSpendMicros) {
      throw new FabricError(`Spend limit reached for this session ($${(this.cfg.maxSpendMicros / 1e6).toFixed(3)}, set by FABRIC_MAX_SPEND_USD). Ask the user before raising it.`, { code: "spend_limit" });
    }
    this.reservedMicros += PRICE_MICROS;
    try {
      // A retry with the same idempotency key resends the exact same signed record (no second charge).
      let pending = null;
      let pPath = null;
      if (idempotencyKey) {
        pPath = this.pendingPath(idempotencyKey);
        if (existsSync(pPath)) {
          pending = JSON.parse(readFileSync(pPath, "utf8"));
          if (pending.summary !== summary || pending.kind !== kind || (pending.approval_record ?? null) !== (approvalRecord ?? null)) {
            throw new FabricError("This idempotency_key was already used for a different action. Use a new key for a new action.", { code: "idempotency_mismatch" });
          }
        }
      }
      let body, salt;
      if (pending) {
        body = pending.request;
        salt = Buffer.from(pending.salt_hex, "hex");
      } else {
        ({ body, salt } = makeRecord(this.sk, { agent: this.cfg.agent, kid: this.cfg.kid, kind, payload: Buffer.from(summary, "utf8") }));
      }
      const idem = idempotencyKey || body.statement.payload_sha256.slice(0, 32);
      pPath ??= this.pendingPath(idem);
      if (!pending) writePrivate(pPath, JSON.stringify({ idempotency_key: idem, kind, summary, approval_record: approvalRecord, salt_hex: salt.toString("hex"), request: body }));

      const governance = await this.governanceFor(kind, approvalRecord);
      const r = await this.request("POST", "/v1/log/append", { body: governance ? { ...body, governance } : body, headers: { "idempotency-key": idem }, retries: 3 });
      if (!r.ok) {
        const err = await this.errorFrom(r);
        if (err.retryable || r.status >= 500) {
          err.message += ` Retry with idempotency_key "${idem}" to resend the same signed record; it is charged at most once.`;
        } else {
          rmSync(pPath, { force: true }); // rejected for good: nothing was recorded
        }
        throw err;
      }
      const reply = await r.json();
      this.spentMicros += PRICE_MICROS;
      const index = reply?.ack?.ack?.leaf_index;
      if (!Number.isSafeInteger(index) || index < 0) throw new FabricError("Unexpected reply from Fabric Verify (no leaf index). Your record and salt are kept in the pending folder.");
      const balance = Number(r.headers.get("x-fabric-credit-balance-micros"));
      const dir = this.newRecordDir(index, body.statement.payload_sha256);
      writePrivate(join(dir, "record.json"), JSON.stringify({
        index, kind, ...(event ? { event: event.event, run_id: event.runId ?? null } : {}), client_time: body.statement.client_time,
        salt_hex: salt.toString("hex"), payload: summary, payload_sha256: body.statement.payload_sha256,
        request: body, receipt: reply, api: this.cfg.api,
      }, null, 2));
      this.writeAgentRecord(dir, body.public_key);
      rmSync(pPath, { force: true });
      return {
        index,
        payload_sha256: body.statement.payload_sha256,
        client_time: body.statement.client_time,
        balance_usd: Number.isFinite(balance) ? balance / 1e6 : null,
        saved_to: dir,
      };
    } finally {
      this.reservedMicros -= PRICE_MICROS;
    }
  }

  /**
   * Sign and append one agent event (augmentev/fabric-agent-event/v1) as the
   * record's payload. Spends $0.005 of credit. The event is kept here with its
   * salt; `record` (its payload_sha256) is what later events link to.
   */
  async recordEvent({ event, kind, body, runId, stepId, parentRecord, delegationRecord, action, idempotencyKey }) {
    let built;
    try {
      kind = eventKind(event, kind);
      built = await buildEvent({ event, agentId: this.cfg.agent, keyId: this.cfg.kid, body, runId, stepId, parentRecord, delegationRecord, action });
    } catch (e) {
      if (e instanceof EventError) throw new FabricError(e.message, { code: "invalid_event" });
      throw e;
    }
    const approvalRecord = event === "tool_call" ? built.doc.body.approval_record : undefined;
    const res = await this.recordAction({ kind, summary: built.payload, idempotencyKey, approvalRecord, event: { event, runId } });
    return { ...res, record: res.payload_sha256, event, kind, ...(event === "tool_call" || event === "approval" ? { action_sha256: built.doc.body.action_sha256 } : {}) };
  }

  /**
   * Gather saved agent events that have proofs into one bundle
   * (augmentev/fabric-agent-events/v1) for `augmentev-verify agent-events`. Free.
   * Selects by run id or by log indices; refuses when a selected event has no
   * proof yet, since a bundle missing a linked record does not verify.
   */
  exportEvents({ runId, indices }) {
    if (!runId && !indices?.length) throw new FabricError("Give a run_id or a list of indices.");
    const root = this.recordsRoot();
    const want = indices ? new Set(indices.map(String)) : null;
    const picked = [];
    for (const name of readdirSync(root)) {
      if (!/^\d+$/.test(name) || (want && !want.has(name))) continue; // conflict folders are never bundled
      let rec;
      try { rec = JSON.parse(readFileSync(join(root, name, "record.json"), "utf8")); } catch { continue; }
      if (!rec.event || (runId && rec.run_id !== runId)) continue;
      picked.push({ index: Number(name), dir: join(root, name), rec });
    }
    if (want) {
      const found = new Set(picked.map((p) => String(p.index)));
      const absent = [...want].filter((i) => !found.has(i));
      if (absent.length) throw new FabricError(`No saved agent event at index ${absent.slice(0, 10).join(", ")} (only events recorded from this machine can be bundled).`);
    }
    if (!picked.length) throw new FabricError(`No saved agent events${runId ? ` for run ${clean(runId, 64)}` : ""}.`);
    if (picked.length > 1000) throw new FabricError("A bundle holds at most 1000 events; select fewer.");
    const unproven = picked.filter((p) => !existsSync(join(p.dir, "proof.json"))).map((p) => p.index);
    if (unproven.length) throw new FabricError(`Fetch the proofs first with get_proof for index ${unproven.slice(0, 20).join(", ")}${unproven.length > 20 ? " and more" : ""}.`, { code: "proof_pending" });
    picked.sort((a, b) => a.index - b.index);
    const records = picked.map(({ dir, rec }) => ({
      proof: JSON.parse(readFileSync(join(dir, "proof.json"), "utf8")),
      salt_hex: rec.salt_hex,
      payload_b64: Buffer.from(rec.payload, "utf8").toString("base64"),
      audit: JSON.parse(readFileSync(join(dir, "agent-record.json"), "utf8")),
    }));
    const outDir = join(this.cfg.home, "bundles");
    ensurePrivateDir(outDir);
    const file = join(outDir, `events-${runId ? runId.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 64) : "selection"}-${Date.now()}.json`);
    writePrivate(file, JSON.stringify({ format: BUNDLE_FORMAT, records }, null, 2));
    return { saved_to: file, events: records.length, first_index: picked[0].index, last_index: picked.at(-1).index };
  }

  /** Fetch the proof for one record; optionally wait for it. Free. */
  async getProof({ index, waitSeconds = 0 }) {
    const deadline = Date.now() + waitSeconds * 1000;
    for (let polls = 0; ; polls++) {
      const r = await this.request("GET", `/v1/log/proof/${index}`, { retries: 2 });
      if (r.status === 200) {
        const proof = await r.json();
        const dir = this.recordDirFor(index);
        const ours = existsSync(join(dir, "record.json"));
        writePrivate(join(dir, "proof.json"), JSON.stringify(proof));
        return {
          status: "ready", index, format: clean(proof?.format, 64) || null, saved_to: dir,
          ...(ours ? {} : { note: "This record was not made from this machine, so there is no local agent record or salt for it." }),
        };
      }
      if (r.status !== 202) throw await this.errorFrom(r);
      const retryAfter = retryAfterSeconds(r.headers);
      // MCP clients usually time a tool call out at ~60 s, so poll briefly inside the
      // caller's (capped) wait instead of honouring a long Retry-After in one sleep.
      const step = Math.min(retryAfter, 5) * 1000;
      // Hard stop as well as the clock: at most one poll per second of the (≤ 45 s) wait.
      if (Date.now() + step > deadline || polls >= Math.ceil(waitSeconds)) return { status: "pending", index, retry_after_seconds: retryAfter };
      await this.sleep(step);
    }
  }

  async checkBalance() {
    const r = await this.request("GET", "/v1/credits", { retries: 2 });
    if (!r.ok) throw await this.errorFrom(r);
    const j = await r.json();
    const bal = Number(j.balance_micros);
    if (!Number.isFinite(bal)) throw new FabricError("Unexpected reply from Fabric Verify.");
    return {
      balance_usd: bal / 1e6,
      cap_usd: Number.isFinite(Number(j.cap_micros)) ? Number(j.cap_micros) / 1e6 : null,
      region: j.region == null ? null : clean(j.region, 8),
      records_left_approx: Math.floor(bal / PRICE_MICROS),
      session_spend_usd: this.spentMicros / 1e6,
      session_limit_usd: this.cfg.maxSpendMicros / 1e6,
    };
  }

  async buyCreditLink({ amountUsd }) {
    if (!TOPUP_AMOUNTS.includes(amountUsd)) throw new FabricError(`amount_usd must be one of ${TOPUP_AMOUNTS.join(", ")}`);
    if (!this.cfg.creditKey) return { checkout_url: BUY_URL, note: "No credit key yet: buy on this page; the key is shown once after payment." };
    const r = await this.request("POST", "/v1/credits/checkout", { body: { amount_usd: amountUsd } });
    if (!r.ok) throw await this.errorFrom(r);
    const j = await r.json();
    let url;
    try { url = new URL(j.checkout_url); } catch { throw new FabricError("Unexpected checkout link."); }
    if (url.protocol !== "https:" || !CHECKOUT_HOSTS.has(url.hostname)) throw new FabricError(`Unexpected checkout link. Buy credit at ${BUY_URL} instead.`);
    return { checkout_url: url.href, amount_usd: amountUsd, note: "A person must open this link and pay. Credit appears about a minute after payment." };
  }

  recordsRoot() {
    ensurePrivateDir(join(this.cfg.home, "records"));
    const root = join(this.cfg.home, "records", this.cfg.apiHost);
    ensurePrivateDir(root);
    return root;
  }

  recordDirFor(index) {
    const dir = join(this.recordsRoot(), String(index));
    ensurePrivateDir(dir);
    return dir;
  }

  /** Folder for a new record; never overwrites evidence of a different record at the same index. */
  newRecordDir(index, payloadSha256) {
    const dir = this.recordDirFor(index);
    const existing = join(dir, "record.json");
    if (!existsSync(existing)) return dir;
    try {
      if (JSON.parse(readFileSync(existing, "utf8")).payload_sha256 === payloadSha256) return dir;
    } catch { /* unreadable: keep it, write elsewhere */ }
    const alt = join(this.recordsRoot(), `${index}.conflict-${payloadSha256.slice(0, 12)}`);
    ensurePrivateDir(alt);
    return alt;
  }

  writeAgentRecord(dir, pubHex) {
    writePrivate(join(dir, "agent-record.json"), JSON.stringify({
      format: "augmentev/fabric-audit-entry/v1", agent: this.cfg.agent, kid: this.cfg.kid, public_key_hex: pubHex,
    }));
  }
}
