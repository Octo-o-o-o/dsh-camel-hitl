// src/core/canonical-digest.ts
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
function stableJsonStringify(value) {
  if (value === null || value === void 0) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") return Number.isFinite(value) ? JSON.stringify(value) : "null";
  if (t === "bigint") return JSON.stringify(value.toString());
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => v === void 0 || typeof v === "function" ? "null" : stableJsonStringify(v)).join(",")}]`;
  }
  if (t === "object") {
    const rec = value;
    const pairs = [];
    for (const k of Object.keys(rec).sort()) {
      const v = rec[k];
      if (v === void 0 || typeof v === "function" || typeof v === "symbol") continue;
      pairs.push(`${JSON.stringify(k)}:${stableJsonStringify(v)}`);
    }
    return `{${pairs.join(",")}}`;
  }
  return "null";
}
function canonicalArgsSha256(toolName, args) {
  const material = stableJsonStringify({ toolName, args: args ?? null });
  return createHash("sha256").update(material, "utf8").digest("hex");
}
var ApprovalReceiptStore = class {
  processKey = randomBytes(32);
  byToken = /* @__PURE__ */ new WeakMap();
  byCallId = /* @__PURE__ */ new Map();
  sign(fields) {
    return createHmac("sha256", this.processKey).update(stableJsonStringify(fields), "utf8").digest("hex");
  }
  mint(input) {
    const receiptId = randomBytes(16).toString("hex");
    const expiresAtMs = Date.now() + Math.max(1e3, input.ttlMs ?? 10 * 6e4);
    const macHex = this.sign({
      receiptId,
      callId: input.callId,
      sessionId: input.sessionId,
      toolName: input.toolName,
      argsDigest: input.argsDigest,
      expiresAtMs
    });
    const record = {
      receiptId,
      callId: input.callId,
      sessionId: input.sessionId,
      toolName: input.toolName,
      argsDigest: input.argsDigest,
      expiresAtMs,
      macHex
    };
    if (input.execToken) {
      this.byToken.set(input.execToken, record);
    }
    this.byCallId.set(input.callId, record);
    return record;
  }
  /**
   * Verify MAC, expiry, and exact (sessionId, toolName, argsDigest) binding,
   * then atomically burn the receipt so it can NEVER be replayed.
   */
  verifyAndConsume(input) {
    const record = (input.execToken ? this.byToken.get(input.execToken) : void 0) ?? this.byCallId.get(input.callId);
    if (!record) {
      return { valid: false, reason: "CAMEL_STRONG_CONFIRM_RECEIPT_MISSING" };
    }
    if (input.execToken) this.byToken.delete(input.execToken);
    this.byCallId.delete(input.callId);
    if (Date.now() > record.expiresAtMs) {
      return { valid: false, reason: "CAMEL_STRONG_CONFIRM_RECEIPT_EXPIRED" };
    }
    if (record.callId !== input.callId || record.sessionId !== input.sessionId || record.toolName !== input.toolName || record.argsDigest !== input.argsDigest) {
      return { valid: false, reason: "CAMEL_STRONG_CONFIRM_DIGEST_MISMATCH" };
    }
    const expectedMac = this.sign({
      receiptId: record.receiptId,
      callId: record.callId,
      sessionId: record.sessionId,
      toolName: record.toolName,
      argsDigest: record.argsDigest,
      expiresAtMs: record.expiresAtMs
    });
    const a = Buffer.from(record.macHex, "hex");
    const b = Buffer.from(expectedMac, "hex");
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return { valid: false, reason: "CAMEL_STRONG_CONFIRM_MAC_INVALID" };
    }
    return { valid: true, receiptId: record.receiptId };
  }
};

// src/core/policy-engine.ts
var READ_ONLY_CLEAN_TOOLS = /* @__PURE__ */ new Set([
  "read_file",
  "fs_read",
  "list_dir",
  "fs_list",
  "find_files",
  "fs_find",
  "fs_search",
  "grep",
  "glob",
  "get_goal",
  "todo_read",
  "todo_list"
]);
var EXTERNAL_UNTRUSTED_READERS = {
  web_fetch: "url_fetch",
  web_search: "url_fetch",
  fetch_url: "url_fetch",
  http_get: "url_fetch",
  email_read: "email_body",
  mail_read: "email_body",
  read_email: "email_body",
  browser_snapshot: "browser_page",
  browser_read: "browser_page",
  browser_screenshot: "browser_screenshot",
  kb_search: "rag",
  kb_read: "rag",
  rag_search: "rag",
  search_files: "rag",
  office_read: "office_document",
  docx_read: "office_document",
  sql_query: "database_result",
  data_query: "database_result",
  subagent: "delegated_agent"
};
var WORKSPACE_MUTATION_TOOLS = /* @__PURE__ */ new Set([
  "write_file",
  "edit_file",
  "str_replace_editor",
  "fs_write",
  "fs_edit",
  "fs_copy",
  "fs_move",
  "fs_mkdir",
  "apply_patch",
  "bash",
  "pwsh",
  "shell",
  "terminal_send"
]);
var EXPORT_CLASS_RE = /(?:^|_|-|:)(?:email_send|send_email|bulk_email|mail_send|pdf_sign|sign_document|vault_export|vault_delete|vault_reset|vault_credential|data_export|publish|deploy|webhook_send|http_post|transfer_funds)(?:$|_|-)/i;
var RED_DESTRUCTIVE_TOOL_RE = /(?:^|_|-|:)(?:delete|remove|rm|drop|truncate|purge|wipe|revoke|force_push)(?:$|_|-)/i;
var DESTRUCTIVE_SHELL_RE = /\b(?:rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r|git\s+push\s+[^\n]*--force|git\s+reset\s+--hard|del\s+\/[sqf]|remove-item\s+[^\n]*-recurse|format-volume|mkfs\.|dd\s+if=|curl\s+[^\n]*(?:-X\s*(?:POST|PUT|DELETE)|-d\s|--data)|invoke-webrequest\s+[^\n]*-method\s+(?:post|put|delete))\b/i;
function extractCommandText(args) {
  if (!args || typeof args !== "object") return "";
  const rec = args;
  for (const key of ["command", "cmd", "script", "text"]) {
    if (typeof rec[key] === "string") return rec[key];
  }
  return "";
}
function classifyTool(toolName, args, config = {}) {
  const normalized = toolName.trim();
  const lower = normalized.toLowerCase();
  const override = config.toolTierOverrides?.[normalized] ?? config.toolTierOverrides?.[lower];
  if (override) {
    return {
      toolName: normalized,
      tier: override,
      untrustedOutput: !READ_ONLY_CLEAN_TOOLS.has(lower),
      outputOrigin: EXTERNAL_UNTRUSTED_READERS[lower] ?? (lower.startsWith("mcp:") ? "mcp_tool_result" : "inferred_from_tool"),
      reason: `Explicitly configured tier override: ${override}`
    };
  }
  if (EXPORT_CLASS_RE.test(lower)) {
    return {
      toolName: normalized,
      tier: "export-class",
      untrustedOutput: false,
      reason: "External send, irreversible export, signing, or vault-admin class operation"
    };
  }
  if (RED_DESTRUCTIVE_TOOL_RE.test(lower)) {
    return {
      toolName: normalized,
      tier: "red",
      untrustedOutput: false,
      reason: "Irreversible destructive operation"
    };
  }
  if (lower in EXTERNAL_UNTRUSTED_READERS) {
    return {
      toolName: normalized,
      tier: "green",
      untrustedOutput: true,
      outputOrigin: EXTERNAL_UNTRUSTED_READERS[lower],
      reason: `External/untrusted data reader (${EXTERNAL_UNTRUSTED_READERS[lower]})`
    };
  }
  if (READ_ONLY_CLEAN_TOOLS.has(lower)) {
    return {
      toolName: normalized,
      tier: "green",
      untrustedOutput: false,
      reason: "Read-only local workspace inspection tool"
    };
  }
  if (WORKSPACE_MUTATION_TOOLS.has(lower)) {
    const cmdText = extractCommandText(args);
    if (cmdText && DESTRUCTIVE_SHELL_RE.test(cmdText)) {
      return {
        toolName: normalized,
        tier: "red",
        untrustedOutput: true,
        outputOrigin: "inferred_from_tool",
        reason: "Shell command matched destructive or outbound mutation pattern"
      };
    }
    return {
      toolName: normalized,
      tier: "yellow",
      untrustedOutput: true,
      outputOrigin: "inferred_from_tool",
      reason: "Workspace mutation or shell execution tool"
    };
  }
  const isMcp = lower.startsWith("mcp:") || lower.includes("__") || lower.startsWith("mcp_");
  return {
    toolName: normalized,
    tier: "yellow",
    untrustedOutput: true,
    outputOrigin: isMcp ? "mcp_tool_result" : "inferred_from_tool",
    reason: isMcp ? "Unknown MCP tool defaults to yellow risk + untrusted output" : "Unknown third-party tool defaults to yellow risk + untrusted output"
  };
}
function evaluateTrifectaDecision(input) {
  const { classification, sessionTaint, config } = input;
  const untrustedOrigins = [...new Set(sessionTaint.map((t) => t.origin))];
  const hasTaint = untrustedOrigins.length > 0;
  if (classification.tier === "export-class") {
    return {
      action: "strong_confirm",
      tier: "export-class",
      untrustedOrigins,
      allowRemember: false,
      allowRemoteTransport: false,
      reason: hasTaint ? `Export-class tool "${classification.toolName}" with untrusted session taint (${untrustedOrigins.join(", ")}) requires non-rememberable local Strong Confirmation.` : `Export-class tool "${classification.toolName}" always requires non-rememberable local Strong Confirmation.`
    };
  }
  if (classification.tier === "red") {
    return {
      action: "strong_confirm",
      tier: "red",
      untrustedOrigins,
      allowRemember: false,
      allowRemoteTransport: false,
      reason: hasTaint ? `Lethal Trifecta: red-tier tool "${classification.toolName}" cannot execute after untrusted origins (${untrustedOrigins.join(", ")}) without non-rememberable local Strong Confirmation.` : `Red-tier tool "${classification.toolName}" requires non-rememberable local Strong Confirmation.`
    };
  }
  if (classification.tier === "yellow") {
    if (hasTaint || config?.askOnCleanYellow) {
      return {
        action: "standard_ask",
        tier: "yellow",
        untrustedOrigins,
        allowRemember: false,
        allowRemoteTransport: true,
        reason: hasTaint ? `Yellow-tier tool "${classification.toolName}" after untrusted origins (${untrustedOrigins.join(", ")}) requires user approval.` : `Yellow-tier tool "${classification.toolName}" requires user approval.`
      };
    }
    return {
      action: "allow",
      tier: "yellow",
      untrustedOrigins,
      allowRemember: true,
      allowRemoteTransport: true,
      reason: "Clean yellow-tier workspace action without untrusted session taint"
    };
  }
  return {
    action: "allow",
    tier: "green",
    untrustedOrigins,
    allowRemember: true,
    allowRemoteTransport: true,
    reason: "Green-tier read-only tool"
  };
}

// src/core/protected-paths.ts
import path from "node:path";
var DEFAULT_PROTECTED_RULES = [
  {
    id: "dsh-credentials",
    description: "DSH credential store (.credentials.yaml)",
    test: (_p, base) => base === ".credentials.yaml" || base === ".credentials.yml"
  },
  {
    id: "dotenv-secrets",
    description: "Environment secret files (.env / .env.*)",
    test: (_p, base) => /^\.env(?:\..+)?$/i.test(base) && !/\.example$/i.test(base) && !/\.sample$/i.test(base)
  },
  {
    id: "ssh-private-keys",
    description: "SSH keys and authorized_keys (~/.ssh/*)",
    test: (p, base) => /(?:^|\/)\.ssh\/(?:id_[^/]+|authorized_keys|config)$/i.test(p) || /^id_(?:rsa|ed25519|ecdsa|dsa)$/i.test(base) && !base.endsWith(".pub")
  },
  {
    id: "cloud-cli-creds",
    description: "Cloud/package credentials (.aws/credentials, .kube/config, .npmrc, .netrc, .gnupg)",
    test: (p, base) => /(?:^|\/)\.aws\/credentials$/i.test(p) || /(?:^|\/)\.kube\/config$/i.test(p) || /(?:^|\/)\.gnupg(?:\/|$)/i.test(p) || base === ".npmrc" || base === ".netrc" || base === ".pypirc"
  },
  {
    id: "private-key-material",
    description: "Private key & keystore containers (*.pem, *.key, *.p12, *.pfx, *.jks)",
    test: (_p, base) => /\.(?:pem|key|p12|pfx|jks|kdbx)$/i.test(base)
  },
  {
    id: "audit-ledger-db",
    description: "Tamper-evident audit database (governance/audit.sqlite*)",
    test: (p) => /(?:^|\/)governance\/audit\.sqlite(?:-wal|-shm)?$/i.test(p)
  }
];
var PATH_KEY_RE = /(?:^|_)(?:path|file|filepath|source|src|dest|destination|target|output|outpath|cwd|dir|directory|vault)$/i;
function normalizePosix(raw) {
  return raw.replace(/\\/g, "/").replace(/\/+/g, "/");
}
function extractCandidateStrings(value, out, depth = 0) {
  if (!value || depth > 5) return;
  if (typeof value === "string") {
    if (value.length > 0 && value.length <= 2048) out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 64)) extractCandidateStrings(item, out, depth + 1);
    return;
  }
  if (typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (PATH_KEY_RE.test(k) || k === "command" || k === "cmd" || k === "script") {
        extractCandidateStrings(v, out, depth + 1);
      } else if (typeof v === "object" && v !== null) {
        extractCandidateStrings(v, out, depth + 1);
      }
    }
  }
}
function tokenizeCommandPaths(text) {
  const tokens = [text];
  for (const part of text.split(/[\s'"`=|;&<>()]+/)) {
    if (part.length >= 2 && (part.includes("/") || part.includes("\\") || part.startsWith("."))) {
      tokens.push(part);
    }
  }
  return tokens;
}
var ProtectedPathMatcher = class {
  normalizedVaultRoots;
  constructor(vaultPaths = []) {
    this.normalizedVaultRoots = vaultPaths.filter((p) => typeof p === "string" && p.trim().length > 0).map((p) => normalizePosix(path.resolve(p)).replace(/\/$/, "").toLowerCase());
  }
  getRulesSummary() {
    return [
      ...DEFAULT_PROTECTED_RULES.map((r) => `${r.id}: ${r.description}`),
      ...this.normalizedVaultRoots.map((v, i) => `vault-${i + 1}: ${v}`)
    ];
  }
  checkArguments(args) {
    const rawStrings = [];
    extractCandidateStrings(args, rawStrings);
    for (const raw of rawStrings) {
      for (const token of tokenizeCommandPaths(raw)) {
        const norm = normalizePosix(token);
        const base = path.posix.basename(norm);
        for (const rule of DEFAULT_PROTECTED_RULES) {
          if (rule.test(norm, base)) {
            return {
              blocked: true,
              matchedPath: norm,
              matchedRule: rule.id,
              reason: `Protected path blocked by monotonic guard (${rule.id}): ${rule.description}`
            };
          }
        }
        if (this.normalizedVaultRoots.length > 0) {
          const resolved = normalizePosix(path.resolve(token)).replace(/\/$/, "").toLowerCase();
          for (const vaultRoot of this.normalizedVaultRoots) {
            if (resolved === vaultRoot || resolved.startsWith(`${vaultRoot}/`)) {
              return {
                blocked: true,
                matchedPath: norm,
                matchedRule: "vault-path",
                reason: `Vault directory access blocked by monotonic guard`
              };
            }
          }
        }
      }
    }
    return { blocked: false };
  }
};

// src/host/strong-confirm-broker.ts
import { randomUUID } from "node:crypto";
var SENSITIVE_PREVIEW_KEYS = /password|passwd|secret|token|apikey|api_key|authorization|cookie|privatekey|credential/i;
var PREVIEW_FIELD_LIMIT = 14;
function sanitizePreviewValue(key, val) {
  if (SENSITIVE_PREVIEW_KEYS.test(key)) return "[REDACTED]";
  if (typeof val === "string") {
    const scrubbed = val.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi, "Bearer [REDACTED]").replace(/\b(?:sk|pk|rk|ghp|gho|xoxb|AIza)[-_A-Za-z0-9]{12,}\b/g, "[REDACTED_KEY]");
    return scrubbed.length > 260 ? `${scrubbed.slice(0, 260)}\u2026 (${val.length} chars)` : scrubbed;
  }
  if (typeof val === "number" || typeof val === "boolean" || val === null) return val;
  if (Array.isArray(val)) return `[Array(${val.length})]`;
  if (typeof val === "object") return `{Object(${Object.keys(val).length} keys)}`;
  return String(val);
}
function buildScrubbedConfirmPreview(args) {
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    return { valueType: Array.isArray(args) ? "array" : typeof args };
  }
  const rec = args;
  const out = {};
  const keys = Object.keys(rec).sort();
  for (const key of keys.slice(0, PREVIEW_FIELD_LIMIT)) {
    out[key] = sanitizePreviewValue(key, rec[key]);
  }
  if (keys.length > PREVIEW_FIELD_LIMIT) {
    out._omittedFields = keys.length - PREVIEW_FIELD_LIMIT;
  }
  return out;
}
var StrongConfirmBroker = class {
  pending = /* @__PURE__ */ new Map();
  receiptStore;
  timeoutMs;
  constructor(receiptStore, timeoutMs = 10 * 6e4) {
    this.receiptStore = receiptStore;
    this.timeoutMs = Math.max(500, timeoutMs);
  }
  request(input) {
    if (input.signal?.aborted) {
      return Promise.resolve({ approved: false, reason: "Strong confirmation cancelled before dispatch" });
    }
    const requestId = randomUUID();
    const now = Date.now();
    const req = {
      requestId,
      sessionId: input.sessionId,
      callId: input.callId,
      toolName: input.toolName,
      tier: input.tier,
      untrustedOrigins: [...input.untrustedOrigins],
      argsDigest: input.argsDigest,
      preview: buildScrubbedConfirmPreview(input.args),
      reason: input.reason,
      allowRemember: false,
      allowRemoteTransport: false,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + this.timeoutMs).toISOString()
    };
    return new Promise((resolve) => {
      const finish = (outcome) => {
        const entry = this.pending.get(requestId);
        if (!entry) return;
        this.pending.delete(requestId);
        clearTimeout(entry.timer);
        entry.cleanupAbort?.();
        resolve(outcome);
      };
      const timer = setTimeout(() => {
        finish({ approved: false, reason: "Strong confirmation expired (fail-closed)" });
      }, this.timeoutMs);
      let cleanupAbort;
      if (input.signal) {
        const onAbort = () => finish({ approved: false, reason: "Strong confirmation aborted by caller signal" });
        input.signal.addEventListener("abort", onAbort, { once: true });
        cleanupAbort = () => input.signal?.removeEventListener("abort", onAbort);
      }
      this.pending.set(requestId, {
        request: req,
        execToken: input.execToken,
        resolve: finish,
        timer,
        cleanupAbort
      });
    });
  }
  respond(input) {
    const entry = this.pending.get(input.requestId);
    if (!entry) {
      return { ok: false, error: "CONFIRMATION_NOT_FOUND_OR_SETTLED" };
    }
    if (!/^[a-f0-9]{64}$/i.test(input.expectedDigest ?? "")) {
      return { ok: false, error: "INVALID_EXPECTED_DIGEST_FORMAT" };
    }
    if (input.expectedDigest.toLowerCase() !== entry.request.argsDigest.toLowerCase()) {
      entry.resolve({
        approved: false,
        reason: "Strong confirmation digest mismatch (preview drifted from pending call)"
      });
      return { ok: false, error: "DIGEST_MISMATCH" };
    }
    if (input.decision === "approve") {
      const receipt = this.receiptStore.mint({
        execToken: entry.execToken,
        callId: entry.request.callId,
        sessionId: entry.request.sessionId,
        toolName: entry.request.toolName,
        argsDigest: entry.request.argsDigest,
        ttlMs: this.timeoutMs
      });
      entry.resolve({
        approved: true,
        reason: input.reason ?? "User explicitly approved strong confirmation with matching digest",
        receiptId: receipt.receiptId
      });
      return { ok: true };
    }
    entry.resolve({
      approved: false,
      reason: input.reason ?? "User rejected strong confirmation"
    });
    return { ok: true };
  }
  listPending() {
    return [...this.pending.values()].map((e) => e.request);
  }
  cancelAll(reason = "Plugin disposed") {
    for (const entry of [...this.pending.values()]) {
      entry.resolve({ approved: false, reason });
    }
  }
};

// src/host/taint-store.ts
var TAINT_SESSION_EVENT_TYPE = "governance/taint-observed";
var VALID_ORIGINS = /* @__PURE__ */ new Set([
  "rag",
  "email_body",
  "url_fetch",
  "browser_page",
  "browser_screenshot",
  "mcp_tool_result",
  "office_document",
  "database_result",
  "delegated_agent",
  "inferred_from_tool"
]);
function parseTaintObservation(raw) {
  if (!raw || typeof raw !== "object") return null;
  const r = raw;
  if (typeof r.origin !== "string" || !VALID_ORIGINS.has(r.origin)) return null;
  if (typeof r.toolName !== "string" || r.toolName.length === 0) return null;
  return {
    origin: r.origin,
    toolName: r.toolName,
    ...typeof r.callId === "string" ? { callId: r.callId } : {},
    observedAt: typeof r.observedAt === "string" ? r.observedAt : (/* @__PURE__ */ new Date()).toISOString()
  };
}
var PersistentTaintStore = class {
  cache = /* @__PURE__ */ new Map();
  projectionHandle;
  projectionDisposer;
  attachProjections(sessionProjections) {
    if (!sessionProjections || typeof sessionProjections.register !== "function") return;
    try {
      const reg = sessionProjections.register({
        key: "governanceTaint",
        version: 1,
        initial: () => [],
        reduce: (state, event) => {
          if (event?.type !== TAINT_SESSION_EVENT_TYPE) return state;
          const parsed = parseTaintObservation(event.data);
          if (!parsed) return state;
          return [...state, parsed];
        },
        project: (state) => state
      });
      if (typeof reg === "function") {
        this.projectionDisposer = reg;
      } else if (reg && typeof reg === "object") {
        this.projectionHandle = reg;
        if (typeof reg.dispose === "function") {
          this.projectionDisposer = () => reg.dispose();
        }
      }
    } catch {
    }
  }
  /** Rehydrate taint lineage from an existing or forked Session's durable event log. */
  hydrateFromSession(session) {
    if (!session || typeof session.id !== "string") return [];
    if (this.projectionHandle && typeof this.projectionHandle.stateOf === "function") {
      try {
        const projected = this.projectionHandle.stateOf(session);
        if (Array.isArray(projected) && projected.length > 0) {
          this.mergeIntoCache(session.id, projected);
          return this.cache.get(session.id) ?? [];
        }
      } catch {
      }
    }
    if (Array.isArray(session.events)) {
      const replayed = [];
      for (const ev of session.events) {
        if (ev?.type !== TAINT_SESSION_EVENT_TYPE) continue;
        const parsed = parseTaintObservation(ev.data ?? ev.payload);
        if (parsed) replayed.push(parsed);
      }
      if (replayed.length > 0) {
        this.mergeIntoCache(session.id, replayed);
      }
    }
    return this.cache.get(session.id) ?? [];
  }
  observeEvent(sessionId, event) {
    if (event?.type !== TAINT_SESSION_EVENT_TYPE) return;
    const parsed = parseTaintObservation(event.data ?? event.payload);
    if (!parsed) return;
    this.mergeIntoCache(sessionId, [parsed]);
  }
  record(sessionId, obs, session) {
    const full = {
      origin: obs.origin,
      toolName: obs.toolName,
      ...obs.callId ? { callId: obs.callId } : {},
      observedAt: (/* @__PURE__ */ new Date()).toISOString()
    };
    this.mergeIntoCache(sessionId, [full]);
    if (session && typeof session.append === "function") {
      try {
        session.append(TAINT_SESSION_EVENT_TYPE, full);
      } catch {
      }
    }
    return full;
  }
  get(sessionId, session) {
    if (session) this.hydrateFromSession(session);
    return this.cache.get(sessionId) ?? [];
  }
  snapshotAll() {
    const out = {};
    for (const [k, v] of this.cache.entries()) {
      out[k] = [...v];
    }
    return out;
  }
  dispose() {
    try {
      this.projectionDisposer?.();
    } catch {
    }
    this.cache.clear();
  }
  mergeIntoCache(sessionId, items) {
    const existing = this.cache.get(sessionId) ?? [];
    const seen = new Set(existing.map((e) => `${e.origin}|${e.toolName}|${e.callId ?? ""}|${e.observedAt}`));
    let mutated = false;
    for (const item of items) {
      const key = `${item.origin}|${item.toolName}|${item.callId ?? ""}|${item.observedAt}`;
      if (!seen.has(key)) {
        seen.add(key);
        existing.push(item);
        mutated = true;
      }
    }
    if (mutated || !this.cache.has(sessionId)) {
      this.cache.set(sessionId, existing);
    }
  }
};

// src/host/index.ts
var name = "dsh-camel-hitl";
var inject = { optional: ["connection", "tools", "sessions", "sessionProjections"] };
function resolveSession(exec) {
  const agent = exec?.agent;
  const sess = agent?.session;
  if (sess && typeof sess.id === "string") return { id: sess.id, raw: sess };
  if (typeof exec?.sessionId === "string") return { id: exec.sessionId };
  return { id: "default-session" };
}
function apply(ctx, config = {}) {
  let mode = config.mode ?? "enforce";
  const pathMatcher = new ProtectedPathMatcher(config.vaultPaths);
  const receiptStore = new ApprovalReceiptStore();
  const taintStore = new PersistentTaintStore();
  const broker = new StrongConfirmBroker(receiptStore, config.confirmTimeoutMs);
  taintStore.attachProjections(ctx.get("sessionProjections"));
  const recordAudit = (input) => {
    const audit = ctx.get("governanceAudit");
    try {
      audit?.recordEvent?.(input);
    } catch {
    }
  };
  const service = {
    getMode: () => mode,
    setMode: (next) => {
      mode = next;
      recordAudit({
        stream: "security",
        eventName: "camel.mode_changed",
        actorType: "user",
        actorId: "local-owner",
        resourceType: "camel_policy",
        outcome: "success",
        payload: { mode: next }
      });
    },
    getSessionTaint: (sessionId) => taintStore.get(sessionId),
    recordTaint: (sessionId, obs, session) => taintStore.record(sessionId, obs, session),
    classifyTool: (toolName, args) => classifyTool(toolName, args, config),
    checkProtectedPaths: (args) => pathMatcher.checkArguments(args),
    listPendingConfirmations: () => broker.listPending(),
    respondStrongConfirmation: (input) => {
      const res = broker.respond(input);
      recordAudit({
        stream: "security",
        eventName: res.ok ? input.decision === "approve" ? "camel.strong_confirm_approved" : "camel.strong_confirm_rejected" : "camel.strong_confirm_invalid",
        actorType: "user",
        actorId: "local-owner",
        resourceType: "strong_confirmation",
        resourceId: input.requestId,
        outcome: res.ok ? input.decision === "approve" ? "success" : "denied" : "failure",
        payload: { decision: input.decision, error: res.error ?? null }
      });
      return res;
    },
    getProtectedRulesSummary: () => pathMatcher.getRulesSummary()
  };
  if (typeof ctx.provide === "function") {
    ctx.provide("governanceTaint", service);
  }
  const disposers = [];
  const toolsService = ctx.get("tools");
  if (toolsService && typeof toolsService.guard === "function") {
    disposers.push(
      toolsService.guard((exec) => {
        const toolName = typeof exec?.name === "string" ? exec.name : "unknown_tool";
        const callId = typeof exec?.callId === "string" ? exec.callId : "unknown-call";
        const execToken = typeof exec?.token === "symbol" ? exec.token : void 0;
        const { id: sessionId, raw: session } = resolveSession(exec);
        const pathCheck = pathMatcher.checkArguments(exec?.arguments);
        if (pathCheck.blocked) {
          recordAudit({
            stream: "security",
            eventName: "camel.protected_path_blocked",
            actorType: "system",
            actorId: "dsh-camel-hitl",
            resourceType: "tool",
            resourceId: toolName,
            outcome: mode === "enforce" ? "denied" : "observed",
            sessionId,
            severity: "high",
            riskLevel: "critical",
            payload: { matchedRule: pathCheck.matchedRule, mode }
          });
          if (mode === "enforce") {
            return {
              reason: pathCheck.reason ?? "Blocked by protected-path guard",
              info: { name: "ProtectedPathDeniedError", code: "PROTECTED_PATH_DENIED" }
            };
          }
        }
        const classification = classifyTool(toolName, exec?.arguments, config);
        const taint = taintStore.get(sessionId, session);
        const decision = evaluateTrifectaDecision({ classification, sessionTaint: taint, config });
        if (decision.action === "strong_confirm") {
          if (mode === "shadow") {
            recordAudit({
              stream: "security",
              eventName: "camel.shadow_strong_confirm",
              actorType: "system",
              actorId: "dsh-camel-hitl",
              resourceType: "tool",
              resourceId: toolName,
              outcome: "observed",
              sessionId,
              payload: { tier: decision.tier, origins: decision.untrustedOrigins }
            });
            return void 0;
          }
          const argsDigest = canonicalArgsSha256(toolName, exec?.arguments);
          const verification = receiptStore.verifyAndConsume({
            execToken,
            callId,
            sessionId,
            toolName,
            argsDigest
          });
          if (!verification.valid) {
            recordAudit({
              stream: "security",
              eventName: "camel.guard_denied_missing_receipt",
              actorType: "system",
              actorId: "dsh-camel-hitl",
              resourceType: "tool",
              resourceId: toolName,
              outcome: "denied",
              sessionId,
              severity: "critical",
              riskLevel: "critical",
              payload: { reason: verification.reason, tier: decision.tier, origins: decision.untrustedOrigins }
            });
            return {
              reason: `Monotonic guard blocked "${toolName}": ${verification.reason ?? "missing valid strong-confirmation receipt"}`,
              info: { name: "CamelGuardDeniedError", code: verification.reason ?? "CAMEL_STRONG_CONFIRM_RECEIPT_MISSING" }
            };
          }
        }
        return void 0;
      })
    );
  }
  if (typeof ctx.on === "function") {
    disposers.push(
      ctx.on("tools/pre-execute", async (exec, next) => {
        const toolName = typeof exec?.name === "string" ? exec.name : "unknown_tool";
        const callId = typeof exec?.callId === "string" ? exec.callId : "unknown-call";
        const execToken = typeof exec?.token === "symbol" ? exec.token : void 0;
        const signal = exec?.signal;
        const { id: sessionId, raw: session } = resolveSession(exec);
        const pathCheck = pathMatcher.checkArguments(exec?.arguments);
        if (pathCheck.blocked && mode === "enforce") {
          return {
            kind: "deny",
            reason: pathCheck.reason ?? "Blocked by protected path policy",
            info: { name: "ProtectedPathDeniedError", code: "PROTECTED_PATH_DENIED" }
          };
        }
        const classification = classifyTool(toolName, exec?.arguments, config);
        const taint = taintStore.get(sessionId, session);
        const decision = evaluateTrifectaDecision({ classification, sessionTaint: taint, config });
        if (mode === "shadow") {
          if (decision.action !== "allow") {
            recordAudit({
              stream: "security",
              eventName: "camel.shadow_observed",
              actorType: "system",
              actorId: "dsh-camel-hitl",
              resourceType: "tool",
              resourceId: toolName,
              outcome: "observed",
              sessionId,
              payload: { plannedAction: decision.action, tier: decision.tier, origins: decision.untrustedOrigins }
            });
          }
          return next();
        }
        if (decision.action === "standard_ask") {
          const downstream = await next();
          if (downstream && downstream.kind !== "allow") return downstream;
          return {
            kind: "ask",
            reason: decision.reason,
            displayReason: {
              en: decision.reason,
              zh: `\u5DE5\u5177\u300C${toolName}\u300D\u5728\u63A5\u89E6\u4E0D\u53EF\u4FE1\u6765\u6E90\uFF08${decision.untrustedOrigins.join("\u3001")}\uFF09\u540E\u53D1\u8D77\u53D8\u66F4\uFF0C\u8BF7\u786E\u8BA4\u662F\u5426\u5355\u6B21\u653E\u884C\u3002`
            }
          };
        }
        if (decision.action === "strong_confirm") {
          const argsDigest = canonicalArgsSha256(toolName, exec?.arguments);
          const outcome = await broker.request({
            execToken,
            sessionId,
            callId,
            toolName,
            tier: decision.tier,
            untrustedOrigins: decision.untrustedOrigins,
            argsDigest,
            args: exec?.arguments,
            reason: decision.reason,
            signal
          });
          if (!outcome.approved) {
            return {
              kind: "deny",
              reason: `Strong confirmation denied for "${toolName}": ${outcome.reason}`,
              info: { name: "CamelStrongConfirmDeniedError", code: "CAMEL_STRONG_CONFIRM_DENIED" }
            };
          }
          return next();
        }
        return next();
      })
    );
    disposers.push(
      ctx.on("tools/post-execute", async (exec, result, next) => {
        if (!result?.isError) {
          const toolName = typeof exec?.name === "string" ? exec.name : "unknown_tool";
          const callId = typeof exec?.callId === "string" ? exec.callId : void 0;
          const { id: sessionId, raw: session } = resolveSession(exec);
          const classification = classifyTool(toolName, exec?.arguments, config);
          if (classification.untrustedOutput && classification.outputOrigin) {
            taintStore.record(
              sessionId,
              {
                origin: classification.outputOrigin,
                toolName,
                callId
              },
              session
            );
          }
        }
        return next();
      })
    );
    disposers.push(
      ctx.on("session/created", (session) => {
        taintStore.hydrateFromSession(session);
      })
    );
    disposers.push(
      ctx.on("session/event", (session, event) => {
        if (session?.id) taintStore.observeEvent(session.id, event);
      })
    );
  }
  const connection = ctx.get("connection");
  if (connection?.fetch?.register) {
    disposers.push(
      connection.fetch.register({
        path: "/api/dshCamelHitl",
        methods: ["POST"],
        requestBody: "buffered",
        fetch: async (request) => {
          let body;
          try {
            body = await request.json();
          } catch {
            return new Response("body is not JSON", { status: 400 });
          }
          const rpcId = typeof body?.rpcId === "string" ? body.rpcId : "00000000-0000-0000-0000-000000000000";
          const envelope = body?.payload ?? {};
          const method = typeof envelope.method === "string" ? envelope.method : "";
          const p = envelope.payload ?? {};
          const dispatch = () => {
            try {
              switch (method) {
                case "getState":
                  return {
                    ok: true,
                    value: {
                      mode,
                      pending: broker.listPending(),
                      taintBySession: taintStore.snapshotAll(),
                      protectedRules: pathMatcher.getRulesSummary()
                    }
                  };
                case "listPending":
                  return { ok: true, value: { pending: broker.listPending() } };
                case "setMode":
                  if (p.mode !== "enforce" && p.mode !== "shadow") {
                    return { ok: false, error: { code: "dsh-camel-hitl/invalid-mode", message: "Mode must be enforce or shadow", details: {} } };
                  }
                  service.setMode(p.mode);
                  return { ok: true, value: { mode } };
                case "respondConfirm": {
                  const res = service.respondStrongConfirmation({
                    requestId: String(p.requestId ?? ""),
                    decision: p.decision === "approve" ? "approve" : "reject",
                    expectedDigest: String(p.expectedDigest ?? ""),
                    reason: typeof p.reason === "string" ? p.reason : void 0
                  });
                  return { ok: true, value: res };
                }
                default:
                  return { ok: false, error: { code: "dsh-camel-hitl/not-found", message: `Unknown method: ${method}`, details: {} } };
              }
            } catch (error) {
              return {
                ok: false,
                error: { code: "dsh-camel-hitl/error", message: error instanceof Error ? error.message : String(error), details: {} }
              };
            }
          };
          return Response.json({ type: "server-response", rpcId, result: dispatch() });
        }
      })
    );
  }
  if (typeof ctx.effect === "function") {
    ctx.effect(() => () => {
      broker.cancelAll("dsh-camel-hitl disposed");
      taintStore.dispose();
      for (const dispose of disposers) {
        try {
          void dispose();
        } catch {
        }
      }
    }, "dsh-camel-hitl: lifecycle");
  }
  return service;
}
export {
  ApprovalReceiptStore,
  PersistentTaintStore,
  ProtectedPathMatcher,
  StrongConfirmBroker,
  TAINT_SESSION_EVENT_TYPE,
  apply,
  buildScrubbedConfirmPreview,
  canonicalArgsSha256,
  classifyTool,
  evaluateTrifectaDecision,
  inject,
  name,
  stableJsonStringify
};
