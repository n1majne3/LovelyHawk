import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  isSftpBrowserOpaqueHandle,
  isSftpDirectoryDownloadResult,
  isSftpDirectorySnapshot,
  isSftpDirectoryUploadPrepare,
  isSftpDirectoryUploadResult,
  isSftpOperationReceipt,
  isSftpOperationUndoResult,
  isSftpQueueEnqueueResult,
  isSftpQueueItem,
  isSftpRelay,
  isSftpRelayTarget,
  isSftpRelayTargetList,
  isSftpTransferCancelResult,
  isSftpTransferQueue,
  isSftpTextPreview,
  type SftpDirectorySnapshot,
  type SftpTextPreview,
} from "./sftp-browser-contract";

const directory: SftpDirectorySnapshot = {
  browserHandle: "opaque-browser",
  directoryHandle: "opaque-directory",
  parentDirectoryHandle: null,
  directoryLabel: "根目录",
  directoryLabelTruncated: false,
  expiresInSeconds: 300,
  observedEntryCount: 4,
  displayedEntryCount: 4,
  truncated: false,
  degradedSftp: false,
  entries: [
    { entryHandle: "opaque-dir", name: "etc", nameTruncated: false,
      kind: "directory", action: "browse", sizeBytes: "4096", modifiedAt: "2026-08-24T10:00:00+00:00", mode: "0755", ownerId: 0, groupId: 0 },
    { entryHandle: "opaque-file", name: "<script>evidence()", nameTruncated: false,
      kind: "file", action: "preview", sizeBytes: "42", modifiedAt: null, mode: "0644", ownerId: 1000, groupId: 1000 },
    { entryHandle: "opaque-link", name: "latest", nameTruncated: false,
      kind: "symlink", action: "none", sizeBytes: "12", modifiedAt: null, mode: "0777", ownerId: 0, groupId: 0 },
    { entryHandle: "opaque-secret-name", name: "[SENSITIVE NAME REDACTED]",
      nameTruncated: false, kind: "other", action: "none", sizeBytes: "0", modifiedAt: null, mode: null, ownerId: null, groupId: null },
  ],
};

const preview: SftpTextPreview = {
  browserHandle: "opaque-browser",
  fileHandle: "opaque-file",
  text: "<script>evidence()</script>\n[SENSITIVE SFTP TEXT REDACTED]",
  observedLineCount: 4,
  displayedLineCount: 2,
  truncated: true,
  sha256: "a".repeat(64),
  exact: false,
};

describe("sftp browser standalone contract", () => {
  it("accepts an exact bounded directory capability response", () => {
    expect(isSftpDirectorySnapshot(directory)).toBe(true);
  });

  /**
   * Remote names are the operator's evidence, so they cross as written. Only
   * what breaks rendering is refused.
   */
  it("accepts hostile names as data and refuses only control characters", () => {
    expect(isSftpDirectorySnapshot(directory)).toBe(true);
    for (const verbatim of ["password=keep-this", "id_rsa", "secret_key.pem", "</pre><script>"]) {
      const named = structuredClone(directory);
      named.entries[1]!.name = verbatim;
      expect(isSftpDirectorySnapshot(named), verbatim).toBe(true);
    }
    const control = structuredClone(directory);
    control.entries[1]!.name = "tab\u0009name";
    expect(isSftpDirectorySnapshot(control)).toBe(false);
  });

  it("rejects symlink/file actions and handle aliasing", () => {
    for (const mutation of [
      (value: SftpDirectorySnapshot) => { value.entries[2]!.action = "browse"; },
      (value: SftpDirectorySnapshot) => { value.entries[1]!.action = "browse"; },
      (value: SftpDirectorySnapshot) => { value.entries[0]!.entryHandle = value.directoryHandle; },
      (value: SftpDirectorySnapshot) => { value.parentDirectoryHandle = value.directoryHandle; },
    ]) {
      const changed = structuredClone(directory);
      mutation(changed);
      expect(isSftpDirectorySnapshot(changed)).toBe(false);
    }
  });

  it("rejects extra keys, inconsistent counts, invalid timestamps and oversized lists", () => {
    expect(isSftpDirectorySnapshot({ ...directory, remotePath: "/etc" })).toBe(false);
    expect(isSftpDirectorySnapshot({ ...directory, displayedEntryCount: 3 })).toBe(false);
    expect(isSftpDirectorySnapshot({ ...directory, truncated: true })).toBe(false);
    const invalidDate = structuredClone(directory);
    invalidDate.entries[0]!.modifiedAt = "not-a-date";
    expect(isSftpDirectorySnapshot(invalidDate)).toBe(false);
    expect(isSftpDirectorySnapshot({ ...directory, degradedSftp: "yes" })).toBe(false);
    expect(isSftpDirectorySnapshot({ ...directory, degradedSftp: undefined })).toBe(false);
    expect(isSftpDirectorySnapshot({ ...directory, degradedSftp: true })).toBe(true);
    expect(isSftpDirectorySnapshot({ ...directory, entries: Array.from({ length: 129 }, (_, index) => ({
      ...directory.entries[1]!, entryHandle: `opaque-${index}`,
    })), displayedEntryCount: 129, observedEntryCount: 129 })).toBe(false);
  });

  it("accepts bounded hostile preview text and enforces redaction semantics", () => {
    expect(isSftpTextPreview(preview)).toBe(true);
    expect(isSftpTextPreview({ ...preview, text: "token=do-not-render\nplain", redactedLineCount: 0 })).toBe(false);
    expect(isSftpTextPreview({ ...preview, text: "[SENSITIVE SFTP TEXT REDACTED] spoof",
      displayedLineCount: 1, redactedLineCount: 0 })).toBe(false);
    expect(isSftpTextPreview({ ...preview, text: "x".repeat(4 * 1_024 + 1),
      observedLineCount: 1, displayedLineCount: 1, truncated: true })).toBe(false);
  });

  it("handles empty text without inventing content", () => {
    expect(isSftpTextPreview({ ...preview, text: "", observedLineCount: 0, displayedLineCount: 0, truncated: false })).toBe(true);
    // A file that is a single empty line is "\n", not "": the projection keeps
    // the newline, so the text and the count describe the same thing.
    expect(isSftpTextPreview({ ...preview, text: "\n", observedLineCount: 1, displayedLineCount: 1, truncated: false })).toBe(true);
    expect(isSftpTextPreview({ ...preview, text: "", observedLineCount: 1, displayedLineCount: 1, truncated: false })).toBe(false);
  });

  /**
   * The shape almost every real file has.
   *
   * Every fixture above stops without a final newline, and text files do not:
   * the projection keeps the trailing newline so that opening a file and
   * saving it back does not silently remove one. Splitting the raw text on
   * "\n" counts a line that is not there, which rejected every ordinary file
   * the moment the projection started being faithful — and no fixture noticed,
   * because none of them ended the way files end.
   */
  it("accepts text that ends the way text files end", () => {
    const cases: readonly (readonly [string, number])[] = [
      ["one\ntwo\nthree\n", 3],
      ["one\ntwo\nthree", 3],
      ["only\n", 1],
      ["only", 1],
      ["\n", 1],
      ["a\n\n", 2],
    ];
    for (const [text, displayedLineCount] of cases) {
      expect(
        isSftpTextPreview({ ...preview, text, displayedLineCount, observedLineCount: displayedLineCount, truncated: false }),
        text,
      ).toBe(true);
    }
    // The count still has to be the truth: one line too many or too few is
    // rejected exactly as before.
    for (const [text, displayedLineCount] of [["one\ntwo\n", 3], ["one\ntwo\n", 1]] as const) {
      expect(
        isSftpTextPreview({ ...preview, text, displayedLineCount, observedLineCount: displayedLineCount, truncated: false }),
        text,
      ).toBe(false);
    }
  });

  it("restricts opaque handles to bounded inert tokens", () => {
    expect(isSftpBrowserOpaqueHandle("opaque-ABC-123")).toBe(true);
    for (const invalid of ["", "has space", "../escape", "slash/value", "x".repeat(129)]) {
      expect(isSftpBrowserOpaqueHandle(invalid)).toBe(false);
    }
  });

  it("validates the directory-download result exactly, including its refusal states", () => {
    expect(isSftpDirectoryDownloadResult({ saved: false })).toBe(true);
    const done = {
      saved: true, state: "done", fileCount: "12", totalBytes: "4096",
      archiveBytes: "2048", extractedEntries: "10", detail: "目录已打包为 tar 下载。",
      fileName: "var.tar",
    };
    expect(isSftpDirectoryDownloadResult(done)).toBe(true);
    expect(isSftpDirectoryDownloadResult({
      ...done, state: "refused-over-cap", archiveBytes: null, extractedEntries: null,
    })).toBe(true);
    expect(isSftpDirectoryDownloadResult({ ...done, state: "extract-refused" })).toBe(true);
    expect(isSftpDirectoryDownloadResult({ ...done, state: "extract-failed" })).toBe(true);
    for (const invalid of [
      { saved: false, extra: 1 },
      { ...done, state: "running" },
      { ...done, fileCount: 12 },
      { ...done, archiveBytes: "not-a-number" },
      { ...done, extractedEntries: -1 },
      { ...done, detail: "line\nbreak" },
      { ...done, fileName: "has\nnewline" },
      { ...done, localPath: "C:\\x" },
      { ...done, remotePath: "/etc" },
      null,
    ]) {
      expect(isSftpDirectoryDownloadResult(invalid)).toBe(false);
    }
  });

  it("validates the directory-upload preview and result exactly", () => {
    expect(isSftpDirectoryUploadPrepare({ prepared: false })).toBe(true);
    const prepared = {
      prepared: true, stagedHandle: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      folderName: "site", fileCount: "12", totalBytes: "4096",
    };
    expect(isSftpDirectoryUploadPrepare(prepared)).toBe(true);
    for (const invalid of [
      { prepared: false, extra: 1 },
      { ...prepared, stagedHandle: "bad handle!" },
      { ...prepared, fileCount: 12 },
      { ...prepared, localPath: "C:\\x" },
      { ...prepared, folderName: "has\nnewline" },
      null,
    ]) {
      expect(isSftpDirectoryUploadPrepare(invalid)).toBe(false);
    }

    expect(isSftpDirectoryUploadResult({ saved: false })).toBe(true);
    const done = {
      saved: true, state: "done", detail: "目录已上传。",
      planHandle: "a1b2c3d4-e5f6-7890-abcd-ef1234567890", undoable: true,
    };
    expect(isSftpDirectoryUploadResult(done)).toBe(true);
    expect(isSftpDirectoryUploadResult({
      ...done, state: "refused-destination", planHandle: null, undoable: false,
    })).toBe(true);
    expect(isSftpDirectoryUploadResult({ ...done, state: "cancelled", planHandle: null, undoable: false })).toBe(true);
    for (const invalid of [
      { saved: false, extra: 1 },
      { ...done, state: "running" },
      { ...done, undoable: true, planHandle: null },
      { ...done, undoable: false },
      { ...done, detail: "line\nbreak" },
      { ...done, localPath: "C:\\x" },
      null,
    ]) {
      expect(isSftpDirectoryUploadResult(invalid)).toBe(false);
    }
    // The upload-directory undo kind is accepted on undo receipts only.
    const undone = {
      planHandle: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      kind: "upload-directory", undone: true, detail: "已删除。",
    };
    expect(isSftpOperationUndoResult(undone)).toBe(true);
  });

  /**
   * Reading, plus the one transfer that needs no plan. Everything that changes
   * the target has to arrive through the plan/confirm pipeline instead, so
   * those names stay forbidden here until that pipeline exists.
   */
  /**
   * Reading, one transfer, and the plan pipeline. There is deliberately no
   * method that changes a target directly: every change is planned, confirmed
   * and executed as three separate steps.
   */
  it("offers an undo only on verified work, and bounds what the undo reports", () => {
    const receipt = {
      planHandle: "opaque-plan", kind: "remove", passed: true, detail: "原路径已不存在，可以恢复的备份还在。",
      restored: false, undoable: true, cancelled: false,
    };
    expect(isSftpOperationReceipt(receipt)).toBe(true);
    // A cancelled upload neither passed, nor was restored, nor can be undone.
    const cancelled = { ...receipt, kind: "upload", passed: false, undoable: false, cancelled: true };
    expect(isSftpOperationReceipt(cancelled)).toBe(true);
    expect(isSftpOperationReceipt({ ...cancelled, passed: true })).toBe(false);
    expect(isSftpOperationReceipt({ ...cancelled, restored: true })).toBe(false);
    expect(isSftpOperationReceipt({ ...cancelled, passed: true, undoable: true })).toBe(false);
    expect(isSftpTransferCancelResult({ cancelled: 0 })).toBe(true);
    expect(isSftpTransferCancelResult({ cancelled: 2 })).toBe(true);
    expect(isSftpTransferCancelResult({ cancelled: -1 })).toBe(false);
    expect(isSftpTransferCancelResult({ cancelled: 1, path: "C:\\x" })).toBe(false);
    expect(isSftpOperationReceipt({ ...receipt, undoable: false })).toBe(true);
    expect(isSftpOperationReceipt({ ...receipt, passed: false, undoable: false })).toBe(true);
    // A failed operation has nothing of its own to put back.
    expect(isSftpOperationReceipt({ ...receipt, passed: false, undoable: true })).toBe(false);
    const { undoable: _undoable, ...older } = receipt;
    expect(isSftpOperationReceipt(older)).toBe(false);

    const undone = { planHandle: "opaque-plan", kind: "remove", undone: true, detail: "文件已从备份移回原来的位置，并在目标机上核对过。" };
    expect(isSftpOperationUndoResult(undone)).toBe(true);
    expect(isSftpOperationUndoResult({ ...undone, undone: false })).toBe(true);
    expect(isSftpOperationUndoResult({ ...undone, kind: "shred" })).toBe(false);
    expect(isSftpOperationUndoResult({ ...undone, detail: "line\nbreak" })).toBe(false);
    expect(isSftpOperationUndoResult({ ...undone, path: "/etc/passwd" })).toBe(false);
  });

  it("keeps the public surface at exactly thirty-four finite methods", () => {
    const source = readFileSync(new URL("./sftp-browser-contract.ts", import.meta.url), "utf8");
    const api = source.split("export interface SftpBrowserApi")[1]!.split("\n}")[0]!;
    expect([...api.matchAll(/^\s{2}([A-Za-z0-9]+)\(/gmu)].map((match) => match[1])).toEqual([
      "openSftpBrowser", "listSftpDirectory", "readSftpText", "downloadSftpEntry",
      "downloadSftpDirectory",
      "planSftpOperation", "confirmSftpOperation", "executeSftpOperation",
      "cancelSftpOperation", "undoSftpOperation",
      "sqliteInspectSftp", "sqliteRowsSftp",
      "sqliteDeletePlanSftp", "sqliteDeleteExecuteSftp", "sqliteDeleteUndoSftp",
      "copySelection",
      "prepareSftpDirectoryUpload", "runSftpDirectoryUpload", "discardSftpDirectoryUpload",
      "cancelSftpTransfer",
      "queueSftpDownload", "queueSftpUpload", "pollSftpQueue", "cancelSftpQueue",
      "retrySftpQueueItem",
      "listSftpRelayTargets", "startSftpRelay", "pollSftpRelay", "cancelSftpRelay",
      "setUnsavedChanges", "onBeforeClose",
      "stageSftpUpload", "openFileEditor",
      "openDirectoryTerminal",
    ]);
    // Transfers and operations name capabilities, never paths: main owns both
    // dialogs and the sidecar owns the staging area.
    expect(api).toContain("downloadSftpEntry(browserHandle: string, fileHandle: string)");
    // Staging takes at most a capability from the local pane, never a path.
    expect(api).toContain("stageSftpUpload(localFileHandle?: string): Promise<unknown>");
    // A terminal opens only in a folder the pane listed, named by its handles.
    expect(api).toContain(
      "openDirectoryTerminal(browserHandle: string, directoryHandle: string, name: string): Promise<unknown>",
    );
    for (const forbidden of [
      "sessionId:", "guard:", "generation:", "remotePath:", "localPath:", "command:", "shell:", "path:",
      ["delete", "Sftp"].join(""), ["rename", "Sftp"].join(""), ["chmod", "Sftp"].join(""),
      ["write", "Sftp"].join(""), ["open", "Terminal("].join(""), ["export", "Sftp"].join(""),
    ]) expect(api).not.toContain(forbidden);
  });
});

describe("transfer queue contract", () => {
  const item = {
    itemId: 3,
    name: "access.log",
    state: "running",
    doneBytes: "1024",
    totalBytes: "4096",
    detail: "从 1024 字节处续传。",
  };
  const queue = { active: true, degraded: false, items: [item] };

  it("accepts a well-formed queue and item", () => {
    expect(isSftpQueueItem(item)).toBe(true);
    expect(isSftpTransferQueue(queue)).toBe(true);
    expect(isSftpQueueEnqueueResult({ queued: false, queue: null })).toBe(true);
    expect(isSftpQueueEnqueueResult({ queued: true, queue })).toBe(true);
    for (const state of ["queued", "running", "done", "failed", "cancelled"]) {
      expect(isSftpQueueItem({ ...item, state })).toBe(true);
    }
  });

  it("rejects unknown fields, bad states, over-cap lists and non-queue values", () => {
    expect(isSftpQueueItem({ ...item, path: "/etc/passwd" })).toBe(false);
    expect(isSftpQueueItem({ ...item, state: "resumed" })).toBe(false);
    expect(isSftpQueueItem({ ...item, doneBytes: -1 })).toBe(false);
    expect(isSftpQueueItem({ ...item, detail: "x".repeat(2048) })).toBe(false);
    expect(isSftpTransferQueue({ ...queue, binding: "b" })).toBe(false);
    expect(isSftpTransferQueue({ ...queue, items: Array.from({ length: 65 }, () => item) })).toBe(false);
    expect(isSftpTransferQueue({ ...queue, items: [{ ...item, itemId: "3" }] })).toBe(false);
    expect(isSftpQueueEnqueueResult({ queued: true, queue: null })).toBe(false);
    expect(isSftpQueueEnqueueResult({ queued: false, queue })).toBe(false);
    expect(isSftpQueueEnqueueResult({ queued: true, queue, localPath: "/x" })).toBe(false);
  });
});

describe("dual-host relay contract", () => {
  const target = { connectionId: "conn-b", label: "root@10.0.0.2:22" };
  const relay = {
    relayHandle: "opaque-relay",
    state: "running",
    leg: "download",
    doneBytes: "1024",
    totalBytes: "4096",
    detail: "正在取回本机。",
  };

  it("accepts a well-formed target list and relay state", () => {
    expect(isSftpRelayTarget(target)).toBe(true);
    expect(isSftpRelayTargetList([target])).toBe(true);
    expect(isSftpRelayTargetList([])).toBe(true);
    expect(isSftpRelay(relay)).toBe(true);
    for (const state of ["running", "done", "failed", "cancelled"]) {
      expect(isSftpRelay({ ...relay, state })).toBe(true);
    }
    for (const leg of ["", "download", "upload"]) {
      expect(isSftpRelay({ ...relay, leg })).toBe(true);
    }
  });

  it("rejects unknown fields, bad states and non-relay values", () => {
    expect(isSftpRelayTarget({ ...target, localPath: "/x" })).toBe(false);
    expect(isSftpRelayTarget({ ...target, credential: "pw" })).toBe(false);
    expect(isSftpRelayTargetList(Array.from({ length: 33 }, () => target))).toBe(false);
    expect(isSftpRelayTargetList([target, { connectionId: 7, label: "x" }])).toBe(false);
    expect(isSftpRelay({ ...relay, state: "stalled" })).toBe(false);
    expect(isSftpRelay({ ...relay, leg: "sideways" })).toBe(false);
    expect(isSftpRelay({ ...relay, tempPath: "/tmp/x" })).toBe(false);
    expect(isSftpRelay({ ...relay, doneBytes: -1 })).toBe(false);
    expect(isSftpRelay({ ...relay, detail: "x".repeat(2048) })).toBe(false);
  });
});
