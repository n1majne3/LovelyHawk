import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  isEmergencyCommandCatalog,
  isEmergencyCommandOpaqueHandle,
  isEmergencyCommandResult,
  isEmergencyIocReport,
  isEmergencyPathBatchPlan,
  isEmergencyPathBatchStep,
  isEmergencyPathDetail,
  isEmergencyPathLinesPlan,
  isEmergencyPathLinesPreview,
  isEmergencyPathPlan,
  isEmergencyPathReceipt,
  isEmergencyPathUndoResult,
  isEmergencyHistoryLocation,
  type EmergencyCommandCatalog,
  type EmergencyCommandResult,
  type EmergencyPathDetail,
  type EmergencyPathPlan,
  type EmergencyPathReceipt,
} from "./emergency-command-contract";

const catalog: EmergencyCommandCatalog = {
  snapshotHandle: "snapshot-opaque",
  containers: [],
  expiresInSeconds: 300,
  commandSet: "detected",
  commands: [{
    commandHandle: "command-opaque",
    category: "network",
    title: "监听端口",
    description: "只读收集监听状态。",
    timeoutSeconds: 30,
    optIn: false,
  }],
};

const result: EmergencyCommandResult = {
  snapshotHandle: "snapshot-opaque",
  commandHandle: "command-opaque",
  resultKind: "success",
  exitCode: 0,
  output: "</pre><script>steal()</script>\nplain evidence",
  observedLineCount: 2,
  displayedLineCount: 2,
  findingLines: [],
  findingReason: null,
  truncated: false,
  command: "ss -tlnp",
  commandTruncated: false,
  rawOutput: "</pre><script>steal()</script>\nplain evidence",
  rawOutputTruncated: false,
  paths: [],
};

const detail: EmergencyPathDetail = {
  pathHandle: "path-opaque",
  path: "/usr/local/bin/.sysd",
  kind: "file",
  size: "125688",
  mode: "4755",
  ownerId: 0,
  groupId: 0,
  modifiedAt: "2026-08-25T23:31:00+00:00",
  executable: true,
};

const plan: EmergencyPathPlan = {
  planHandle: "plan-opaque",
  pathHandle: "path-opaque",
  path: "/usr/local/bin/.sysd",
  action: "disarm",
  summary: "change /usr/local/bin/.sysd permissions from 4755 to 0644",
  dangerous: true,
  restoreDescription: "restore the captured permission bits",
  state: "planned",
  expiresInSeconds: 300,
  residue: null,
};

const restorePlan: EmergencyPathPlan = {
  ...plan,
  action: "restore-residue",
  summary: "用残留 /bin/ls.bak 的内容写回 /bin/ls；当前内容留底（仅属主可读）。能运行不代表可信。",
  restoreDescription: "把留底的内容写回 /bin/ls，并删除该留底",
  path: "/bin/ls",
  residue: {
    source: { path: "/bin/ls.bak", sha256: "a".repeat(64), size: "133192", kind: "backup" },
    package: "coreutils",
    candidates: [
      { path: "/bin/ls.bak", sha256: "a".repeat(64), size: "133192", kind: "backup" },
      { path: "/bin/lsd", sha256: "b".repeat(64), size: "133192", kind: "variant" },
    ],
  },
};

const receipt: EmergencyPathReceipt = {
  planHandle: "plan-opaque",
  path: "/usr/local/bin/.sysd",
  action: "disarm",
  passed: true,
  detail: "remote mode is 0644",
  restored: false,
  untouched: false,
  undoable: true,
};

describe("emergency command contract", () => {
  it("accepts exact bounded catalog and hostile plain-text output", () => {
    expect(isEmergencyCommandCatalog(catalog)).toBe(true);
    expect(isEmergencyCommandResult(result)).toBe(true);
  });

  /** The shipped catalog now carries well over a hundred entries. */
  it("insists the catalogue says which command set it is", () => {
    // A machine that will not say what it runs still gets a workbench, but the
    // commands it gets are the portable ones. That used to happen in silence.
    expect(isEmergencyCommandCatalog({ ...catalog, commandSet: "portable" })).toBe(true);
    // A closed pair of words. Anything else — including the distribution
    // itself, which is the target's business — is not a catalogue.
    for (const wrong of ["rhel", "", "Detected", null, undefined, 1]) {
      expect(isEmergencyCommandCatalog({ ...catalog, commandSet: wrong })).toBe(false);
    }
    const { commandSet: _dropped, ...without } = catalog;
    expect(isEmergencyCommandCatalog(without)).toBe(false);
  });

  it("admits the full catalog but still bounds its size", () => {
    const many = (count: number) => ({
      ...catalog,
      commands: Array.from({ length: count }, (_item, index) => ({
        ...catalog.commands[0], commandHandle: `opaque-handle-${index}`,
      })),
    });
    expect(isEmergencyCommandCatalog(many(200))).toBe(true);
    expect(isEmergencyCommandCatalog(many(257))).toBe(false);
  });

  it("rejects unknown keys, duplicate handles and internal metadata", () => {
    expect(isEmergencyCommandCatalog({ ...catalog, family: "debian" })).toBe(false);
    expect(isEmergencyCommandCatalog({
      ...catalog,
      commands: [...catalog.commands, { ...catalog.commands[0] }],
    })).toBe(false);
    expect(isEmergencyCommandCatalog({ ...catalog, expiresInSeconds: 301 })).toBe(false);
    expect(isEmergencyCommandCatalog({
      ...catalog,
      commands: [{ ...catalog.commands[0], command: "ss -tulpen" }],
    })).toBe(false);
  });

  it("rejects malformed handles, categories, timeouts and text controls", () => {
    expect(isEmergencyCommandOpaqueHandle("opaque-good-123")).toBe(true);
    for (const invalid of ["", "space value", "slash/value", "control\n", "x".repeat(129)]) {
      expect(isEmergencyCommandOpaqueHandle(invalid)).toBe(false);
    }
    expect(isEmergencyCommandCatalog({
      ...catalog,
      commands: [{ ...catalog.commands[0], category: "unknown" }],
    })).toBe(false);
    expect(isEmergencyCommandCatalog({
      ...catalog,
      commands: [{ ...catalog.commands[0], timeoutSeconds: 0 }],
    })).toBe(false);
    expect(isEmergencyCommandCatalog({
      ...catalog,
      commands: [{ ...catalog.commands[0], description: "line\nbreak" }],
    })).toBe(false);
  });

  /**
   * The tool runs against targets the operator owns, so output is shown as the
   * target printed it. Only what breaks rendering is refused.
   */
  it("passes credential-shaped output through and still refuses control characters", () => {
    for (const verbatim of [
      "root:$6$salt$hash:19000:0:99999:7:::",
      "Failed password for invalid user admin from 10.0.0.9",
      "ctf ALL=(ALL) NOPASSWD: ALL",
      "https://user:secret@example.internal/repo.git",
    ]) {
      expect(isEmergencyCommandResult({
        ...result, output: verbatim, observedLineCount: 1, displayedLineCount: 1,
      }), verbatim).toBe(true);
    }
    expect(isEmergencyCommandResult({
      ...result,
      output: "control\u0007character",
      observedLineCount: 1,
      displayedLineCount: 1,
    })).toBe(false);
    expect(isEmergencyCommandResult({
      ...result,
      observedLineCount: 3,
      truncated: false,
    })).toBe(false);
  });

  /** A highlight must point at a line that is still here and still readable. */
  it("bounds abnormal-line marks to readable displayed lines", () => {
    expect(isEmergencyCommandResult({ ...result, findingLines: [0, 1] })).toBe(true);
    expect(isEmergencyCommandResult({ ...result, findingLines: [2] })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingLines: [1, 0] })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingLines: [0, 0] })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingLines: [-1] })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingLines: ["0"] })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingLines: 0 })).toBe(false);
  });

  it("requires the reason to be plain bounded text or nothing at all", () => {
    expect(isEmergencyCommandResult({ ...result, findingReason: "标红的行不在标准名单内。" })).toBe(true);
    expect(isEmergencyCommandResult({ ...result, findingReason: "line\nbreak" })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingReason: "x".repeat(513) })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingReason: 0 })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingReason: undefined })).toBe(false);
  });

  it("accepts only escaped, bounded command and raw-output views", () => {
    expect(isEmergencyCommandResult({ ...result, command: "docker exec id sh -c 'ls'" })).toBe(true);
    expect(isEmergencyCommandResult({ ...result, command: "ls\\x1b[0m\nline" })).toBe(true);
    // A control character arriving unescaped is exactly what must not pass.
    expect(isEmergencyCommandResult({ ...result, command: "ls" })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, rawOutput: "carriage\rreturn" })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, rawOutput: "newline\nok" })).toBe(true);
    expect(isEmergencyCommandResult({ ...result, command: "x".repeat(128 * 1_024 + 1) })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, rawOutput: "x".repeat(1_024 * 1_024 + 1) })).toBe(false);
    for (const key of ["command", "commandTruncated", "rawOutput", "rawOutputTruncated"] as const) {
      const clone = { ...result } as Record<string, unknown>;
      delete clone[key];
      expect(isEmergencyCommandResult(clone)).toBe(false);
      expect(isEmergencyCommandResult({ ...result, [key]: 0 })).toBe(false);
    }
  });

  it("enforces line, aggregate, serialized and result-kind semantics", () => {
    expect(isEmergencyCommandResult({ ...result, output: "x".repeat(4 * 1_024 + 1), observedLineCount: 1, displayedLineCount: 1 })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, resultKind: "empty", output: "", observedLineCount: 0, displayedLineCount: 0 })).toBe(true);
    expect(isEmergencyCommandResult({ ...result, resultKind: "non-zero", exitCode: 7 })).toBe(true);
    expect(isEmergencyCommandResult({ ...result, resultKind: "unknown-exit", exitCode: 0 })).toBe(false);
    const escaped = "\\\"".repeat(90_000);
    expect(isEmergencyCommandResult({
      ...result,
      output: escaped,
      observedLineCount: 1,
      displayedLineCount: 1,
    })).toBe(false);
  });

  it("declares exactly sixteen finite methods and no raw execution arguments", () => {
    const source = readFileSync(new URL("./emergency-command-contract.ts", import.meta.url), "utf8");
    const apiStart = source.indexOf("export interface EmergencyCommandApi");
    const api = source.slice(apiStart, source.indexOf("\n}\n", apiStart));
    // Sixteen methods: twelve fit on one line; planEmergencyPathAction,
    // planEmergencyPathBatch, planEmergencyPathLines and runEmergencyCommand
    // do not — the latter since it gained the container it may be pointed at.
    expect(api.match(/^  [a-zA-Z][A-Za-z]*\(/gmu)).toHaveLength(16);
    expect(api.match(/^\s{2}[a-zA-Z].*Promise<(?:unknown|void)>;/gmu)).toHaveLength(12);
    expect(api).toContain("loadEmergencyCommandCatalog(bindingHandle: string)");
    // Optional, and the only thing it may be besides absent is a handle: the
    // renderer cannot name a container by id or by name.
    expect(api).toMatch(
      /runEmergencyCommand\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*commandHandle: string,\s*containerHandle\?: string,\s*\): Promise<unknown>;/u,
    );
    expect(api).toContain("inspectEmergencyPath(bindingHandle: string, pathHandle: string)");
    expect(api).toContain("confirmEmergencyPathAction(bindingHandle: string, planHandle: string)");
    expect(api).toContain("executeEmergencyPathAction(bindingHandle: string, planHandle: string)");
    expect(api).toContain("cancelEmergencyPathAction(bindingHandle: string, planHandle: string)");
    expect(api).toContain("undoEmergencyPathAction(bindingHandle: string, planHandle: string)");
    // A history record is named by its id; which check it ran never comes from the window.
    expect(api).toContain("locateEmergencyHistoryCommand(bindingHandle: string, snapshotHandle: string, historyId: string)");
    // Leads come only from outputs the backend already holds — the page names
    // a snapshot, it never sends output text for the backend to scan.
    expect(api).toContain("extractEmergencyCommandIocs(bindingHandle: string, snapshotHandle: string)");
    // A batch names offered handles and one action — never paths.
    expect(api).toContain("confirmEmergencyPathBatch(bindingHandle: string, batchHandle: string)");
    expect(api).toContain("stepEmergencyPathBatch(bindingHandle: string, batchHandle: string)");
    expect(api).toContain("cancelEmergencyPathBatch(bindingHandle: string, batchHandle: string)");
    // Every parameter is a handle, a bounded line number, or the closed
    // action name. A window cannot put a path of its own into any of these.
    expect(api).not.toMatch(/\b(?:commandId|family|sessionId|generation|guard|host|shell|commandText)\b/u);
    expect(api).not.toMatch(/path: string/u);
  });

  it("offers a path only where the output actually shows one", () => {
    const named = {
      ...result,
      output: "-rwsr-xr-x 1 root root 125688 Jan  1  2024 /usr/local/bin/.sysd\nplain evidence",
      paths: [{ pathHandle: "path-opaque", line: 0, path: "/usr/local/bin/.sysd", lineEditable: false, xinetdService: false }],
    };
    expect(isEmergencyCommandResult(named)).toBe(true);
    // A mark past the end of the output, or on a line that does not mention
    // the file, is a mismatch the window must not draw a menu from.
    expect(isEmergencyCommandResult({ ...named, paths: [{ ...named.paths[0], line: 9 }] })).toBe(false);
    expect(isEmergencyCommandResult({ ...named, paths: [{ ...named.paths[0], line: 1 }] })).toBe(false);
    // Two offers on one line, or one handle reused, cannot both be acted on.
    expect(isEmergencyCommandResult({
      ...named,
      paths: [named.paths[0], { pathHandle: "other-opaque", line: 0, path: "/usr/local/bin/.sysd", lineEditable: false, xinetdService: false }],
    })).toBe(false);
    expect(isEmergencyCommandResult({ ...named, paths: [{ ...named.paths[0], path: "relative" }] })).toBe(false);
    expect(isEmergencyCommandResult({ ...named, paths: [{ ...named.paths[0], path: "" }] })).toBe(false);
    expect(isEmergencyCommandResult({
      ...named,
      paths: [{ ...named.paths[0], path: "/usr/local/bin/.sy\u0007sd" }],
    })).toBe(false);
    // The field itself is required, so an older reply cannot pass silently.
    const { paths: _dropped, ...without } = named;
    expect(isEmergencyCommandResult(without)).toBe(false);
  });

  it("bounds what the target may say about one file", () => {
    expect(isEmergencyPathDetail(detail)).toBe(true);
    expect(isEmergencyPathDetail({ ...detail, mode: null, ownerId: null, groupId: null, modifiedAt: null }))
      .toBe(true);
    expect(isEmergencyPathDetail({ ...detail, kind: "socket" })).toBe(false);
    expect(isEmergencyPathDetail({ ...detail, mode: "8755" })).toBe(false);
    expect(isEmergencyPathDetail({ ...detail, mode: "755" })).toBe(false);
    expect(isEmergencyPathDetail({ ...detail, size: "-1" })).toBe(false);
    expect(isEmergencyPathDetail({ ...detail, path: "../etc/passwd" })).toBe(false);
    expect(isEmergencyPathDetail({ ...detail, extra: true })).toBe(false);
  });

  it("bounds the plan and the receipt to the closed action set", () => {
    expect(isEmergencyPathPlan(plan)).toBe(true);
    expect(isEmergencyPathPlan({ ...plan, restoreDescription: null })).toBe(true);
    expect(isEmergencyPathPlan({ ...plan, state: "confirmed" })).toBe(true);
    expect(isEmergencyPathPlan({ ...plan, action: "delete" })).toBe(false);
    expect(isEmergencyPathPlan({ ...plan, state: "running" })).toBe(false);
    expect(isEmergencyPathPlan({ ...plan, expiresInSeconds: 0 })).toBe(false);
    expect(isEmergencyPathPlan({ ...plan, expiresInSeconds: 301 })).toBe(false);
    expect(isEmergencyPathPlan({ ...plan, summary: "x".repeat(513) })).toBe(false);

    expect(isEmergencyPathReceipt(receipt)).toBe(true);
    expect(isEmergencyPathReceipt({ ...receipt, passed: false, restored: true, undoable: false })).toBe(true);
    expect(isEmergencyPathReceipt({ ...receipt, passed: false, untouched: true, undoable: false })).toBe(true);
    // Untouched means refused before writing: never with a pass or a restore.
    expect(isEmergencyPathReceipt({ ...receipt, passed: true, untouched: true })).toBe(false);
    expect(isEmergencyPathReceipt({ ...receipt, passed: false, restored: true, untouched: true, undoable: false })).toBe(false);
    const { untouched: _untouched, ...withoutUntouched } = receipt;
    expect(isEmergencyPathReceipt(withoutUntouched)).toBe(false);
    expect(isEmergencyPathReceipt({ ...receipt, action: "shred" })).toBe(false);
    expect(isEmergencyPathReceipt({ ...receipt, detail: "line\nbreak" })).toBe(false);
    // Only a verified action is offered for undo; a failed one has nothing to put back.
    expect(isEmergencyPathReceipt({ ...receipt, undoable: false })).toBe(true);
    expect(isEmergencyPathReceipt({ ...receipt, passed: false, restored: true, undoable: true })).toBe(false);
    const { undoable: _undoable, ...withoutUndoable } = receipt;
    expect(isEmergencyPathReceipt(withoutUndoable)).toBe(false);
  });

  it("carries restore residue only as bounded candidates with a chosen source", () => {
    expect(isEmergencyPathPlan(restorePlan)).toBe(true);
    expect(isEmergencyPathPlan({ ...restorePlan, residue: { ...restorePlan.residue, package: null } })).toBe(true);
    // The action stays inside the closed set, and the residue key is required.
    expect(isEmergencyPathPlan({ ...restorePlan, action: "restore" })).toBe(false);
    const { residue: _residue, ...withoutResidue } = restorePlan;
    expect(isEmergencyPathPlan(withoutResidue)).toBe(false);
    const residue = restorePlan.residue as NonNullable<EmergencyPathPlan["residue"]>;
    // A source the probe never offered cannot be chosen.
    expect(isEmergencyPathPlan({
      ...restorePlan,
      residue: { ...residue, source: { path: "/bin/evil", sha256: "c".repeat(64), size: "1", kind: "backup" } },
    })).toBe(false);
    // Digests are hex and bounded; kinds are closed; candidates stay few.
    expect(isEmergencyPathPlan({
      ...restorePlan,
      residue: { ...residue, source: { ...residue.source, sha256: "not-hex" } },
    })).toBe(false);
    expect(isEmergencyPathPlan({
      ...restorePlan,
      residue: { ...residue, source: { ...residue.source, sha256: "a".repeat(65) } },
    })).toBe(false);
    expect(isEmergencyPathPlan({
      ...restorePlan,
      residue: {
        ...residue,
        source: residue.candidates[1] as NonNullable<EmergencyPathPlan["residue"]>["source"],
        candidates: residue.candidates.map((c) => ({ ...c, kind: "leftover" })),
      },
    })).toBe(false);
    expect(isEmergencyPathPlan({
      ...restorePlan,
      residue: {
        ...residue,
        candidates: Array.from({ length: 10 }, (_c, index) => ({ ...residue.candidates[0], path: `/bin/x${index}` })),
      },
    })).toBe(false);
    expect(isEmergencyPathPlan({
      ...restorePlan,
      residue: { ...residue, package: "pkg", extra: true },
    })).toBe(false);
  });

  it("finds a history check only as a handle, and says why when it cannot", () => {
    expect(isEmergencyHistoryLocation({ status: "found", commandHandle: "command-opaque" })).toBe(true);
    for (const status of ["missing", "not-recorded", "not-in-catalog"]) {
      expect(isEmergencyHistoryLocation({ status, commandHandle: null })).toBe(true);
      // No handle without a find.
      expect(isEmergencyHistoryLocation({ status, commandHandle: "command-opaque" })).toBe(false);
    }
    expect(isEmergencyHistoryLocation({ status: "found", commandHandle: null })).toBe(false);
    expect(isEmergencyHistoryLocation({ status: "found", commandHandle: "network-listen; id" })).toBe(false);
    expect(isEmergencyHistoryLocation({ status: "run", commandHandle: null })).toBe(false);
    expect(isEmergencyHistoryLocation({ status: "found", commandHandle: "command-opaque", entry: "network-listen" })).toBe(false);
  });

  it("bounds what an undo may report", () => {
    const undone = { planHandle: "plan-opaque", path: "/usr/local/bin/.sysd", undone: true, detail: "权限已经恢复为 4755" };
    expect(isEmergencyPathUndoResult(undone)).toBe(true);
    expect(isEmergencyPathUndoResult({ ...undone, undone: false, detail: "那次操作之后，目标机上的这个位置又有了变化" })).toBe(true);
    expect(isEmergencyPathUndoResult({ ...undone, path: "relative" })).toBe(false);
    expect(isEmergencyPathUndoResult({ ...undone, undone: "yes" })).toBe(false);
    expect(isEmergencyPathUndoResult({ ...undone, detail: "x".repeat(513) })).toBe(false);
    expect(isEmergencyPathUndoResult({ ...undone, extra: true })).toBe(false);
    const { detail: _detail, ...withoutDetail } = undone;
    expect(isEmergencyPathUndoResult(withoutDetail)).toBe(false);
  });

  it("bounds a lead report to typed, capped entries", () => {
    const entry = { kind: "ipv4", value: "198.51.100.7", scope: "public", hits: 3, sources: ["检查计划任务"], common: false };
    const report = { entries: [entry], truncated: false };
    expect(isEmergencyIocReport(report)).toBe(true);
    expect(isEmergencyIocReport({ entries: [], truncated: true })).toBe(true);
    // Exact fields: a missing flag or an extra one both fail.
    const { common: _common, ...noCommon } = entry;
    expect(isEmergencyIocReport({ entries: [noCommon], truncated: false })).toBe(false);
    expect(isEmergencyIocReport({ entries: [{ ...entry, extra: true }], truncated: false })).toBe(false);
    expect(isEmergencyIocReport({ ...report, count: 1 })).toBe(false);
    // Closed kind and scope sets.
    expect(isEmergencyIocReport({ entries: [{ ...entry, kind: "hostname" }], truncated: false })).toBe(false);
    expect(isEmergencyIocReport({ entries: [{ ...entry, scope: "internet" }], truncated: false })).toBe(false);
    // Bounded numbers, text and lists.
    expect(isEmergencyIocReport({ entries: [{ ...entry, hits: -1 }], truncated: false })).toBe(false);
    expect(isEmergencyIocReport({ entries: [{ ...entry, hits: 3.5 }], truncated: false })).toBe(false);
    expect(isEmergencyIocReport({ entries: [{ ...entry, common: "yes" }], truncated: false })).toBe(false);
    expect(isEmergencyIocReport({ entries: [{ ...entry, value: "x".repeat(513) }], truncated: false })).toBe(false);
    expect(isEmergencyIocReport({ entries: [{ ...entry, sources: ["s".repeat(129)] }], truncated: false })).toBe(false);
    expect(isEmergencyIocReport({ entries: [{ ...entry, sources: Array(9).fill("a") }], truncated: false })).toBe(false);
    expect(isEmergencyIocReport({ entries: Array(501).fill(entry), truncated: true })).toBe(false);
    expect(isEmergencyIocReport({ entries: [entry], truncated: "no" })).toBe(false);
    expect(isEmergencyIocReport({ entries: [entry] })).toBe(false);
  });

  it("bounds a batch plan to typed rows where plan and refusal never mix", () => {
    const plannedItem = {
      pathHandle: "ph-planned", path: "/tmp/.x", kind: "file", size: "12", mode: "0755",
      executable: true, planHandle: "plan-a", summary: "将该文件移入隔离区",
      restoreDescription: "把文件放回原位置", refusal: null,
    };
    const refusedItem = {
      pathHandle: "ph-refused", path: "/tmp/.y", kind: "file", size: "4", mode: "0644",
      executable: false, planHandle: null, summary: null, restoreDescription: null,
      refusal: "not-executable",
    };
    const staleItem = {
      pathHandle: "ph-stale", path: "", kind: "", size: "", mode: null,
      executable: false, planHandle: null, summary: null, restoreDescription: null,
      refusal: "path-stale",
    };
    const plan = {
      batchHandle: "batch-1", action: "quarantine",
      items: [plannedItem, refusedItem, staleItem],
      planned: 1, refused: 2, state: "planned", expiresInSeconds: 300,
    };
    expect(isEmergencyPathBatchPlan(plan)).toBe(true);
    expect(isEmergencyPathBatchPlan({ ...plan, state: "confirmed" })).toBe(true);
    // Exact fields, closed sets and counted rows.
    expect(isEmergencyPathBatchPlan({ ...plan, extra: 1 })).toBe(false);
    // Single-path-only actions are not a batch answer the backend makes.
    expect(isEmergencyPathBatchPlan({ ...plan, action: "remove-capabilities" })).toBe(false);
    expect(isEmergencyPathBatchPlan({ ...plan, action: "restore-residue" })).toBe(false);
    expect(isEmergencyPathBatchPlan({ ...plan, action: "wipe" })).toBe(false);
    expect(isEmergencyPathBatchPlan({ ...plan, items: [] })).toBe(false);
    expect(isEmergencyPathBatchPlan({ ...plan, items: Array(51).fill(plannedItem), planned: 51, refused: 0 })).toBe(false);
    expect(isEmergencyPathBatchPlan({ ...plan, planned: 2 })).toBe(false);
    expect(isEmergencyPathBatchPlan({ ...plan, refused: 0 })).toBe(false);
    expect(isEmergencyPathBatchPlan({ ...plan, state: "running" })).toBe(false);
    expect(isEmergencyPathBatchPlan({ ...plan, expiresInSeconds: 0 })).toBe(false);
    // A planned row must carry plan facts and nothing of a refusal; a refused
    // row the other way round.
    expect(isEmergencyPathBatchPlan({ ...plan, items: [{ ...plannedItem, planHandle: null }] })).toBe(false);
    expect(isEmergencyPathBatchPlan({ ...plan, items: [{ ...plannedItem, refusal: "x" }] })).toBe(false);
    expect(isEmergencyPathBatchPlan({ ...plan, items: [{ ...refusedItem, planHandle: "p" }] })).toBe(false);
    expect(isEmergencyPathBatchPlan({ ...plan, items: [{ ...refusedItem, refusal: "x".repeat(65) }] })).toBe(false);
    expect(isEmergencyPathBatchPlan({ ...plan, items: [{ ...plannedItem, path: "relative" }] })).toBe(false);
    expect(isEmergencyPathBatchPlan({ ...plan, items: [{ ...plannedItem, mode: "8888" }] })).toBe(false);
    const { summary: _s, ...noSummary } = plannedItem;
    expect(isEmergencyPathBatchPlan({ ...plan, items: [noSummary, refusedItem, staleItem] })).toBe(false);
  });

  it("bounds a batch step to a receipt that belongs to the batch", () => {
    const receipt = {
      planHandle: "plan-a", path: "/tmp/.x", action: "quarantine", passed: true,
      detail: "已移入隔离区并核对", restored: false, untouched: false, undoable: true,
    };
    expect(isEmergencyPathBatchStep({
      batchHandle: "batch-1", receipt, remaining: 1, refused: 0, finished: false,
    })).toBe(true);
    expect(isEmergencyPathBatchStep({
      batchHandle: "batch-1", receipt: null, remaining: 0, refused: 1, finished: true,
    })).toBe(true);
    // An unfinished step must have run something; a finished one has nothing left.
    expect(isEmergencyPathBatchStep({
      batchHandle: "batch-1", receipt: null, remaining: 1, refused: 0, finished: false,
    })).toBe(false);
    expect(isEmergencyPathBatchStep({
      batchHandle: "batch-1", receipt, remaining: 1, refused: 0, finished: true,
    })).toBe(false);
    expect(isEmergencyPathBatchStep({
      batchHandle: "batch-1", receipt: { ...receipt, extra: true }, remaining: 0, refused: 0, finished: true,
    })).toBe(false);
    expect(isEmergencyPathBatchStep({
      batchHandle: "batch-1", receipt, remaining: 51, refused: 0, finished: false,
    })).toBe(false);
    expect(isEmergencyPathBatchStep({
      batchHandle: "batch-1", receipt, remaining: 0, refused: 0, finished: true, extra: 1,
    })).toBe(false);
  });

  it("accepts a bounded lines preview and a contiguous removal list, and refuses everything else", () => {
    const preview = {
      previewHandle: "preview-one", pathHandle: "path-opaque", path: "/etc/crontab",
      totalLines: 3, truncated: false,
      lines: [
        { number: 1, text: "one", clipped: false },
        { number: 2, text: "", clipped: false },
        { number: 3, text: "three", clipped: true },
      ],
    };
    expect(isEmergencyPathLinesPreview(preview)).toBe(true);
    // A truncated preview must name exactly the displayed cap of lines.
    expect(isEmergencyPathLinesPreview({ ...preview, truncated: true })).toBe(false);
    // Numbering must be the file's own sequence, controls never display.
    expect(isEmergencyPathLinesPreview({
      ...preview, lines: preview.lines.map((line) => ({ ...line, number: line.number + 1 })),
    })).toBe(false);
    expect(isEmergencyPathLinesPreview({
      ...preview, lines: [{ ...preview.lines[0], text: "esc[31m" }],
    })).toBe(false);
    expect(isEmergencyPathLinesPreview({ ...preview, extra: 1 })).toBe(false);
    expect(isEmergencyPathLinesPreview({ ...preview, previewHandle: "preview two" })).toBe(false);

    const plan = {
      planHandle: "plan-one", pathHandle: "path-opaque", path: "/etc/crontab",
      action: "delete-lines", summary: "删除 /etc/crontab 第 2 行", dangerous: true,
      restoreDescription: "放回删除前的完整文件", state: "planned", expiresInSeconds: 300,
      residue: null,
      removedLines: [{ number: 2, text: "", clipped: false }],
    };
    expect(isEmergencyPathLinesPlan(plan)).toBe(true);
    // A lines plan only exists for the delete action, never for another label.
    expect(isEmergencyPathLinesPlan({ ...plan, action: "disarm" })).toBe(false);
    expect(isEmergencyPathPlan(plan)).toBe(false);
    // The removal list stays bounded and contiguous: a gap or a forged extra
    // line is a different delete than the operator approved.
    expect(isEmergencyPathLinesPlan({
      ...plan,
      removedLines: [
        { number: 2, text: "a", clipped: false },
        { number: 4, text: "b", clipped: false },
      ],
    })).toBe(false);
    expect(isEmergencyPathLinesPlan({ ...plan, removedLines: [] })).toBe(false);
    expect(isEmergencyPathLinesPlan({
      ...plan,
      removedLines: Array.from({ length: 201 }, (_, index) => ({
        number: index + 1, text: "x", clipped: false,
      })),
    })).toBe(false);
    expect(isEmergencyPathLinesPlan({ ...plan, removedLines: undefined })).toBe(false);
  });
});
