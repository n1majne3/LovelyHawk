export const sftpBrowserEntryKinds = ["directory", "file", "symlink", "other"] as const;
export const sftpBrowserEntryActions = ["browse", "preview", "none"] as const;

export type SftpBrowserEntryKind = typeof sftpBrowserEntryKinds[number];
export type SftpBrowserEntryAction = typeof sftpBrowserEntryActions[number];

export interface SftpBrowserEntry {
  entryHandle: string;
  name: string;
  nameTruncated: boolean;
  kind: SftpBrowserEntryKind;
  action: SftpBrowserEntryAction;
  sizeBytes: string;
  modifiedAt: string | null;
  /** Permission bits as four octal digits, when the server reports them. */
  mode: string | null;
  /** Numeric owner and group, reported as they arrive. */
  ownerId: number | null;
  groupId: number | null;
}

export interface SftpDirectorySnapshot {
  browserHandle: string;
  directoryHandle: string;
  parentDirectoryHandle: string | null;
  directoryLabel: string;
  directoryLabelTruncated: boolean;
  expiresInSeconds: number;
  observedEntryCount: number;
  displayedEntryCount: number;
  truncated: boolean;
  entries: SftpBrowserEntry[];
  /** The target has no SFTP subsystem: read-only exec listing, SCP transfers. */
  degradedSftp: boolean;
}

export interface SftpTextPreview {
  browserHandle: string;
  fileHandle: string;
  text: string;
  observedLineCount: number;
  displayedLineCount: number;
  truncated: boolean;
  /**
   * The hash of the file as read, not of the text above.
   *
   * The editor sends it back when it saves, and the write lands only if the
   * file still hashes to it — so an edit begun before somebody else changed
   * the file is refused rather than quietly overwriting their change. When
   * `truncated` is true this still covers the whole file while the text does
   * not, which is exactly why a truncated read may not be saved at all.
   */
  sha256: string;
  /**
   * Whether the text above is the file byte for byte.
   *
   * False means the projection changed something — a CRLF line ending, a
   * control character, a dropped tail. Saving then would write the
   * projection's change rather than the operator's, so the editor does not
   * offer to save at all.
   */
  exact: boolean;
}

/**
 * The browser lives in the SSH terminal window, which exists for exactly one
 * target, so the binding is implicit: main resolves it from the calling window
 * and the renderer never holds it.
 */
export interface SftpTransferResult {
  /** False when the operator dismissed the save dialog. */
  saved: boolean;
  /** The name the file was written under, for the operator's confirmation. */
  fileName: string | null;
  bytes: string | null;
}

export const sftpOperationKinds = [
  "create-directory", "rename", "chmod", "remove", "archive", "upload", "write-text",
] as const;
export const sftpArchiveFormats = ["tar", "tar-gzip", "tar-zstd"] as const;

export type SftpOperationKind = typeof sftpOperationKinds[number];
export type SftpArchiveFormat = typeof sftpArchiveFormats[number];

/** What the core will do, written out before anything is touched. */
export interface SftpOperationPlan {
  planHandle: string;
  browserHandle: string;
  kind: SftpOperationKind;
  summary: string;
  dangerous: boolean;
  /** What could be put back if verification fails, when a backup was taken. */
  restoreDescription: string | null;
  state: "planned" | "confirmed" | "spent";
  expiresInSeconds: number;
}

/** What actually happened, after the core verified its own work. */
export interface SftpOperationReceipt {
  planHandle: string;
  kind: SftpOperationKind;
  passed: boolean;
  detail: string;
  /** True when verification failed and the backup was put back. */
  restored: boolean;
  /** Verified and reversible: the window may offer one undo for a while. */
  undoable: boolean;
  /** The operator stopped the upload; what it had written was removed. */
  cancelled: boolean;
}

/** How many running transfers a cancel reached; zero when none was running. */
export interface SftpTransferCancelResult {
  cancelled: number;
}

/**
 * The result of a whole-directory download: the tar reached the chosen save
 * path, or it was refused/cancelled before that. `state` says which; the
 * counts are always the preflight numbers so a refusal shows them.
 */
export interface SftpDirectoryDownloadResult {
  saved: boolean;
  state?: "done" | "refused-over-cap" | "extract-refused" | "extract-failed";
  fileCount?: string;
  totalBytes?: string;
  archiveBytes?: string | null;
  extractedEntries?: string | null;
  detail?: string;
  fileName?: string;
}

/**
 * The staged half of a directory upload: the host packed the picked folder
 * and the archive waits for confirmation under this handle. Counts come from
 * the pack, so the preview shows exactly what will land remotely.
 */
export interface SftpDirectoryUploadPrepare {
  prepared: boolean;
  stagedHandle?: string;
  folderName?: string;
  fileCount?: string;
  totalBytes?: string;
}

/**
 * The result of a whole-directory upload: the archive went up, extracted and
 * verified — or it was refused, failed or cancelled before that. When
 * `undoable` the plan handle puts the extracted tree away again.
 */
export interface SftpDirectoryUploadResult {
  saved: boolean;
  state?: "done" | "refused-destination" | "failed" | "cancelled";
  detail?: string;
  planHandle?: string | null;
  undoable?: boolean;
}

/** What an undo did: put back and read back, or refused with the reason. */
export interface SftpOperationUndoResult {
  planHandle: string;
  kind: SftpOperationKind | "upload-directory";
  undone: boolean;
  detail: string;
}

export interface SftpStagedUpload {
  stagedHandle: string;
  name: string;
  bytes: string;
}

/** The capabilities an operation names, never a path, a mode owner or a target. */
export interface SftpOperationInput {
  kind: SftpOperationKind;
  entryHandles: string[];
  name?: string;
  mode?: number;
  format?: SftpArchiveFormat;
  stagedHandle?: string;
  /** `write-text` only: the edited content, and the hash it was read at. */
  text?: string;
  expectedSha256?: string;
}

export interface SftpBrowserApi {
  openSftpBrowser(): Promise<unknown>;
  listSftpDirectory(browserHandle: string, directoryHandle: string): Promise<unknown>;
  readSftpText(browserHandle: string, fileHandle: string): Promise<unknown>;
  /** Asks main for a save location, then copies the file there. */
  downloadSftpEntry(browserHandle: string, fileHandle: string): Promise<unknown>;
  /**
   * Packs a remote directory server-side and downloads the tar to a location
   * the native dialog picks — or unpacks it into a picked empty folder. The
   * page passes a suggested file name only; it never names a path.
   */
  downloadSftpDirectory(
    browserHandle: string,
    directoryHandle: string,
    defaultName: string,
    extract: boolean,
  ): Promise<unknown>;
  /** Nothing changes until confirm and execute follow this plan. */
  planSftpOperation(browserHandle: string, input: SftpOperationInput): Promise<unknown>;
  confirmSftpOperation(planHandle: string): Promise<unknown>;
  executeSftpOperation(planHandle: string): Promise<unknown>;
  cancelSftpOperation(planHandle: string): Promise<unknown>;
  /** Puts a verified operation back, once, while its receipt offers it. */
  undoSftpOperation(planHandle: string): Promise<unknown>;
  /**
   * Read-only SQLite view of one file this browser offered. The host resolves
   * which target and file the handles are; the page never names a path.
   */
  sqliteInspectSftp(browserHandle: string, entryHandle: string): Promise<unknown>;
  sqliteRowsSftp(browserHandle: string, entryHandle: string, table: string, offset: number): Promise<unknown>;
  sqliteDeletePlanSftp(browserHandle: string, entryHandle: string, table: string, rowids: number[]): Promise<unknown>;
  sqliteDeleteExecuteSftp(planHandle: string): Promise<unknown>;
  sqliteDeleteUndoSftp(planHandle: string): Promise<unknown>;
  /** Clipboard goes through the host; the page never touches it directly. */
  copySelection(text: string): Promise<void>;
  /**
   * Picks a local folder through the host dialog, packs it into a bounded
   * tar (no links, junctions or reparse points) and stages it. Nothing remote
   * changes; the page previews the counts and asks before running.
   */
  prepareSftpDirectoryUpload(browserHandle: string): Promise<unknown>;
  /**
   * Runs a confirmed directory upload against `directoryHandle`: the staged
   * tar goes to a remote temp path and extracts under `<dir>/<folder name>`.
   */
  runSftpDirectoryUpload(
    browserHandle: string,
    directoryHandle: string,
    stagedHandle: string,
  ): Promise<unknown>;
  /** Drops a staged archive the operator declined at the preview. */
  discardSftpDirectoryUpload(stagedHandle: string): Promise<unknown>;
  /** Stops this browser's running upload or download; it removes what it wrote. */
  cancelSftpTransfer(browserHandle: string): Promise<unknown>;
  /**
   * Queues the checked files for download into one host-picked folder;
   * `rateLimitKiB` throttles the read loop, 0 means unlimited.
   */
  queueSftpDownload(
    browserHandle: string,
    fileHandles: string[],
    rateLimitKiB: number,
  ): Promise<unknown>;
  /** Queues host-picked files for upload into the shown remote directory. */
  queueSftpUpload(browserHandle: string, directoryHandle: string): Promise<unknown>;
  /** Live queue state for the poll loop; null when this window has none. */
  pollSftpQueue(browserHandle: string): Promise<unknown>;
  /** Cancels every queued and running item of this window's queue. */
  cancelSftpQueue(browserHandle: string): Promise<unknown>;
  /** Requeues one failed or cancelled queue item. */
  retrySftpQueueItem(browserHandle: string, itemId: number): Promise<unknown>;
  /**
   * Saved connections a file could be relayed to, minus this binding's own.
   * A relay opens its own session to the peer; credentials never cross.
   */
  listSftpRelayTargets(browserHandle: string): Promise<unknown>;
  /**
   * Starts a single-file relay to `destDir` on the peer connection; the
   * destination must not already exist.
   */
  startSftpRelay(
    browserHandle: string,
    fileHandle: string,
    connectionId: string,
    destDir: string,
  ): Promise<unknown>;
  /** Live relay state for the poll loop; null when the handle is gone. */
  pollSftpRelay(browserHandle: string, relayHandle: string): Promise<unknown>;
  /** Throws the switch on both legs of one relay. */
  cancelSftpRelay(browserHandle: string, relayHandle: string): Promise<unknown>;
  /**
   * Reports whether the window holds unfinished work, so closing it from
   * outside the page waits for `onBeforeClose` to answer first.
   */
  setUnsavedChanges(unsaved: boolean): Promise<void>;
  /** Answers the host's close question; resolves to "may close". */
  onBeforeClose(handler: () => Promise<boolean>): () => void;
  /**
   * Stages a file where an upload plan can name it. With a handle from the
   * local pane it stages that file; without one main asks the operator to pick
   * a file. Either way the renderer never sees a local path.
   */
  stageSftpUpload(localFileHandle?: string): Promise<unknown>;
  /**
   * Opens one file in a window of its own, for reading or for editing.
   *
   * The pane passes only the two opaque handles it already holds. Whether the
   * window may write is decided here and recorded by main; the window itself
   * cannot change it.
   */
  openFileEditor(
    browserHandle: string,
    entryHandle: string,
    name: string,
    editable: boolean,
  ): Promise<unknown>;
  /**
   * Opens a terminal window that starts in one listed folder.
   *
   * Again only the handles the pane holds, plus the folder's name for the new
   * window's title. The host turns the handles back into the path; the pane
   * never names a path, a shell or a command.
   */
  openDirectoryTerminal(browserHandle: string, directoryHandle: string, name: string): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const kindSet = new Set<string>(sftpBrowserEntryKinds);
const actionSet = new Set<string>(sftpBrowserEntryActions);
const maximumU64 = "18446744073709551615";
// Written as an escape so the source file stays plain text.
const CONTROL_CHARACTERS = new RegExp("[\u0000-\u001f\u007f]", "u");

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function text(value: unknown, maximumBytes: number, allowEmpty = true): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes;
}

function unsigned(value: unknown, maximum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function serializedWithin(value: unknown, maximumBytes: number): boolean {
  try {
    const encoded = JSON.stringify(value);
    return typeof encoded === "string" && encoder.encode(encoded).byteLength <= maximumBytes;
  } catch {
    return false;
  }
}

export function isSftpBrowserOpaqueHandle(value: unknown): value is string {
  return text(value, 128, false) && /^[A-Za-z0-9-]+$/u.test(value);
}

/** A remote name is shown as it is; only control characters are refused. */
function safeName(value: unknown, truncated: unknown, maximumBytes: number): value is string {
  return text(value, maximumBytes, false) && typeof truncated === "boolean" &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function u64String(value: unknown): value is string {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/u.test(value)) return false;
  return value.length < maximumU64.length || value.length === maximumU64.length && value <= maximumU64;
}

function timestampOrNull(value: unknown): value is string | null {
  return value === null || text(value, 64, false) &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u.test(value) &&
    Number.isFinite(Date.parse(value));
}

/** Four octal digits, or nothing: anything else is not a mode we can show. */
function modeOrNull(value: unknown): value is string | null {
  return value === null || typeof value === "string" && /^[0-7]{4}$/u.test(value);
}

/** A POSIX id fits in 32 bits and is never negative. */
function idOrNull(value: unknown): value is number | null {
  return value === null ||
    typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 4_294_967_295;
}

function entry(value: unknown): value is SftpBrowserEntry {
  if (!record(value) || !exact(value, [
    "entryHandle", "name", "nameTruncated", "kind", "action", "sizeBytes", "modifiedAt",
    "mode", "ownerId", "groupId",
  ]) || !isSftpBrowserOpaqueHandle(value.entryHandle) ||
    !safeName(value.name, value.nameTruncated, 256) ||
    typeof value.kind !== "string" || !kindSet.has(value.kind) ||
    typeof value.action !== "string" || !actionSet.has(value.action) ||
    !u64String(value.sizeBytes) || !timestampOrNull(value.modifiedAt) ||
    !modeOrNull(value.mode) || !idOrNull(value.ownerId) || !idOrNull(value.groupId)) return false;
  if (value.kind === "file") return value.action === "preview";
  if (value.kind === "directory") return value.action === "browse" || value.action === "none";
  return value.action === "none";
}

export function isSftpDirectorySnapshot(value: unknown): value is SftpDirectorySnapshot {
  if (!record(value) || !exact(value, [
    "browserHandle", "directoryHandle", "parentDirectoryHandle", "directoryLabel",
    "directoryLabelTruncated", "expiresInSeconds", "observedEntryCount",
    "displayedEntryCount", "truncated", "entries", "degradedSftp",
  ]) || !isSftpBrowserOpaqueHandle(value.browserHandle) ||
    !isSftpBrowserOpaqueHandle(value.directoryHandle) ||
    !(value.parentDirectoryHandle === null || isSftpBrowserOpaqueHandle(value.parentDirectoryHandle)) ||
    value.parentDirectoryHandle === value.directoryHandle ||
    !safeName(value.directoryLabel, value.directoryLabelTruncated, 256) ||
    !unsigned(value.expiresInSeconds, 300) || value.expiresInSeconds === 0 ||
    !unsigned(value.observedEntryCount, 50_000) || !unsigned(value.displayedEntryCount, 128) ||
    typeof value.truncated !== "boolean" || !Array.isArray(value.entries) ||
    typeof value.degradedSftp !== "boolean" ||
    value.entries.length !== value.displayedEntryCount || !value.entries.every(entry) ||
    value.displayedEntryCount > value.observedEntryCount ||
    value.truncated !== (value.observedEntryCount > value.displayedEntryCount) ||
    !serializedWithin(value, 128 * 1_024)) return false;
  const entries = value.entries as SftpBrowserEntry[];
  return new Set(entries.map((item) => item.entryHandle)).size === entries.length &&
    !entries.some((item) => item.entryHandle === value.directoryHandle ||
      item.entryHandle === value.parentDirectoryHandle);
}

/** File text is shown as the target has it; only control characters are refused. */
function outputLine(value: string): boolean {
  return encoder.encode(value).byteLength <= 4 * 1_024 &&
    !/[\r\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value);
}

/**
 * The lines of a preview, or null when the count does not match what was
 * declared.
 *
 * The final newline is dropped before splitting. The projection keeps a file's
 * trailing newline — an editor that silently removed it would change every
 * file it opened — and `"a\nb\n".split("\n")` is three entries for two lines,
 * so splitting the raw text made this reject every text file that ends the way
 * text files normally end.
 */
function textLines(value: string, displayedLineCount: number): string[] | null {
  if (value.length === 0) return displayedLineCount === 0 ? [] : null;
  const body = value.endsWith("\n") ? value.slice(0, -1) : value;
  const lines = body.split("\n");
  return lines.length === displayedLineCount ? lines : null;
}

export function isSftpTransferResult(value: unknown): value is SftpTransferResult {
  if (!record(value) || !exact(value, ["saved", "fileName", "bytes"]) ||
    typeof value.saved !== "boolean") return false;
  if (!value.saved) return value.fileName === null && value.bytes === null;
  return safeName(value.fileName, false, 256) && u64String(value.bytes);
}

const operationKindSet = new Set<string>(sftpOperationKinds);

/** Plan text is drawn in a dialog, so it stays one bounded line. */
function planText(value: unknown, maximumBytes: number): value is string {
  return text(value, maximumBytes, false) && !CONTROL_CHARACTERS.test(value);
}

const archiveFormatSet = new Set<string>(sftpArchiveFormats);

/**
 * The renderer's request, checked before it reaches the sidecar. Each kind
 * names exactly the capabilities it needs, and nothing carries a path.
 */
export function isSftpOperationInput(value: unknown): value is SftpOperationInput {
  if (!record(value) || typeof value.kind !== "string" || !operationKindSet.has(value.kind) ||
    !Array.isArray(value.entryHandles) || value.entryHandles.length === 0 ||
    value.entryHandles.length > 64 ||
    !value.entryHandles.every(isSftpBrowserOpaqueHandle)) return false;
  const named = value.name === null || value.name === undefined
    ? null
    : safeName(value.name, false, 255) ? value.name : false;
  if (named === false) return false;
  const single = value.entryHandles.length === 1;
  switch (value.kind) {
    case "create-directory":
    case "rename":
      return single && named !== null;
    case "chmod":
      return single && named === null && unsigned(value.mode, 0o7777);
    case "remove":
      return single && named === null;
    case "archive":
      return named !== null && typeof value.format === "string" &&
        archiveFormatSet.has(value.format);
    case "upload":
      return single && named !== null && isSftpBrowserOpaqueHandle(value.stagedHandle);
    case "write-text":
      // The same ceiling the read side works to. Content is passed through
      // exactly as typed — a file being repaired may legitimately contain
      // anything, and this is not the layer that decides what a file may say.
      return single && named === null &&
        typeof value.text === "string" &&
        encoder.encode(value.text).byteLength <= 2 * 1_024 * 1_024 &&
        isSftpContentDigest(value.expectedSha256);
    default:
      return false;
  }
}

export function isSftpOperationPlan(value: unknown): value is SftpOperationPlan {
  return record(value) && exact(value, [
    "planHandle", "browserHandle", "kind", "summary", "dangerous", "restoreDescription",
    "state", "expiresInSeconds",
  ]) && isSftpBrowserOpaqueHandle(value.planHandle) &&
    isSftpBrowserOpaqueHandle(value.browserHandle) &&
    typeof value.kind === "string" && operationKindSet.has(value.kind) &&
    planText(value.summary, 1_024) && typeof value.dangerous === "boolean" &&
    (value.restoreDescription === null || planText(value.restoreDescription, 1_024)) &&
    (value.state === "planned" || value.state === "confirmed" || value.state === "spent") &&
    unsigned(value.expiresInSeconds, 300) && value.expiresInSeconds > 0;
}

export function isSftpOperationReceipt(value: unknown): value is SftpOperationReceipt {
  return record(value) &&
    exact(value, ["planHandle", "kind", "passed", "detail", "restored", "undoable", "cancelled"]) &&
    isSftpBrowserOpaqueHandle(value.planHandle) &&
    typeof value.kind === "string" && operationKindSet.has(value.kind) &&
    typeof value.passed === "boolean" && planText(value.detail, 1_024) &&
    typeof value.restored === "boolean" && typeof value.undoable === "boolean" &&
    typeof value.cancelled === "boolean" &&
    // Nothing is put back when the work passed.
    !(value.passed && value.restored) &&
    // Only verified work can be offered for undo.
    (!value.undoable || value.passed) &&
    // A cancelled upload neither passed nor needed restoring.
    (!value.cancelled || (!value.passed && !value.restored && !value.undoable));
}

export function isSftpTransferCancelResult(value: unknown): value is SftpTransferCancelResult {
  return record(value) && exact(value, ["cancelled"]) && unsigned(value.cancelled, 64);
}

const directoryDownloadStates = new Set([
  "done",
  "refused-over-cap",
  "extract-refused",
  "extract-failed",
]);

export function isSftpDirectoryDownloadResult(
  value: unknown,
): value is SftpDirectoryDownloadResult {
  if (!record(value) || typeof value.saved !== "boolean") return false;
  if (!value.saved) return exact(value, ["saved"]);
  return exact(value, [
    "saved", "state", "fileCount", "totalBytes", "archiveBytes",
    "extractedEntries", "detail", "fileName",
  ]) &&
    typeof value.state === "string" && directoryDownloadStates.has(value.state) &&
    u64String(value.fileCount) && u64String(value.totalBytes) &&
    (value.archiveBytes === null || u64String(value.archiveBytes)) &&
    (value.extractedEntries === null || u64String(value.extractedEntries)) &&
    planText(value.detail, 1_024) && safeName(value.fileName, false, 256);
}

const directoryUploadStates = new Set<string>([
  "done",
  "refused-destination",
  "failed",
  "cancelled",
]);

export function isSftpDirectoryUploadPrepare(
  value: unknown,
): value is SftpDirectoryUploadPrepare {
  if (!record(value) || typeof value.prepared !== "boolean") return false;
  if (!value.prepared) return exact(value, ["prepared"]);
  return exact(value, ["prepared", "stagedHandle", "folderName", "fileCount", "totalBytes"]) &&
    isSftpBrowserOpaqueHandle(value.stagedHandle) &&
    safeName(value.folderName, false, 256) &&
    u64String(value.fileCount) && u64String(value.totalBytes);
}

export function isSftpDirectoryUploadResult(
  value: unknown,
): value is SftpDirectoryUploadResult {
  if (!record(value) || typeof value.saved !== "boolean") return false;
  if (!value.saved) return exact(value, ["saved"]);
  return exact(value, ["saved", "state", "detail", "planHandle", "undoable"]) &&
    typeof value.state === "string" && directoryUploadStates.has(value.state) &&
    planText(value.detail, 1_024) &&
    (value.planHandle === null || isSftpBrowserOpaqueHandle(value.planHandle)) &&
    typeof value.undoable === "boolean" &&
    (value.undoable ? value.planHandle !== null : value.planHandle === null);
}

export function isSftpOperationUndoResult(value: unknown): value is SftpOperationUndoResult {
  return record(value) && exact(value, ["planHandle", "kind", "undone", "detail"]) &&
    isSftpBrowserOpaqueHandle(value.planHandle) &&
    typeof value.kind === "string" &&
    (operationKindSet.has(value.kind) || value.kind === "upload-directory") &&
    typeof value.undone === "boolean" && planText(value.detail, 1_024);
}

export function isSftpStagedUpload(value: unknown): value is SftpStagedUpload {
  return record(value) && exact(value, ["stagedHandle", "name", "bytes"]) &&
    isSftpBrowserOpaqueHandle(value.stagedHandle) &&
    safeName(value.name, false, 256) && u64String(value.bytes);
}

/** Exactly 64 lowercase hex characters, the form the core writes and expects. */
export function isSftpContentDigest(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}

export function isSftpTextPreview(value: unknown): value is SftpTextPreview {
  if (!record(value) || !exact(value, [
    "browserHandle", "fileHandle", "text", "observedLineCount", "displayedLineCount", "truncated",
    "sha256", "exact",
  ]) || !isSftpBrowserOpaqueHandle(value.browserHandle) || !isSftpBrowserOpaqueHandle(value.fileHandle) ||
    !text(value.text, 256 * 1_024) || !unsigned(value.observedLineCount, 2 * 1_024 * 1_024) ||
    !unsigned(value.displayedLineCount, 2_000) || !isSftpContentDigest(value.sha256) ||
    typeof value.exact !== "boolean" ||
    typeof value.truncated !== "boolean" || !serializedWithin(value, 384 * 1_024)) return false;
  const lines = textLines(value.text, value.displayedLineCount);
  return lines !== null && value.displayedLineCount <= value.observedLineCount &&
    lines.every(outputLine) && !(value.observedLineCount > value.displayedLineCount && !value.truncated);
}

/** One batch-transfer queue item as the page shows it. */
export interface SftpQueueItem {
  itemId: number;
  name: string;
  /** queued | running | done | failed | cancelled */
  state: "queued" | "running" | "done" | "failed" | "cancelled";
  doneBytes: string;
  totalBytes: string;
  /** Failure reason, or the integrity/resume note a finished item carries. */
  detail: string;
}

/** A browser window's batch transfer queue; absent when it has none. */
export interface SftpTransferQueue {
  active: boolean;
  /** No SFTP on the target: items run one at a time and downloads cannot resume. */
  degraded: boolean;
  items: SftpQueueItem[];
}

/** What a queue download/upload enqueue answers: the picked folder was used (or not). */
export interface SftpQueueEnqueueResult {
  queued: boolean;
  queue: SftpTransferQueue | null;
}

const queueItemStates = new Set(["queued", "running", "done", "failed", "cancelled"]);

export function isSftpQueueItem(value: unknown): value is SftpQueueItem {
  return record(value) && exact(value, [
    "itemId", "name", "state", "doneBytes", "totalBytes", "detail",
  ]) && unsigned(value.itemId, 64) &&
    safeName(value.name, false, 512) &&
    typeof value.state === "string" && queueItemStates.has(value.state) &&
    u64String(value.doneBytes) && u64String(value.totalBytes) &&
    planText(value.detail, 1_024);
}

export function isSftpTransferQueue(value: unknown): value is SftpTransferQueue {
  return record(value) && exact(value, ["active", "degraded", "items"]) &&
    typeof value.active === "boolean" && typeof value.degraded === "boolean" &&
    Array.isArray(value.items) && value.items.length <= 64 &&
    value.items.every(isSftpQueueItem);
}

export function isSftpQueueEnqueueResult(value: unknown): value is SftpQueueEnqueueResult {
  if (!record(value) || typeof value.queued !== "boolean") return false;
  if (!value.queued) return exact(value, ["queued", "queue"]) && value.queue === null;
  return exact(value, ["queued", "queue"]) && isSftpTransferQueue(value.queue);
}

/** A saved connection the relay dialog may offer, label plus host identity. */
export interface SftpRelayTarget {
  connectionId: string;
  label: string;
}

const relayStates = new Set(["running", "done", "failed", "cancelled"]);
const relayLegs = new Set(["", "download", "upload"]);

export function isSftpRelayTarget(value: unknown): value is SftpRelayTarget {
  return record(value) && exact(value, ["connectionId", "label"]) &&
    safeName(value.connectionId, false, 256) && planText(value.label, 512);
}

export function isSftpRelayTargetList(value: unknown): value is SftpRelayTarget[] {
  return Array.isArray(value) && value.length <= 32 && value.every(isSftpRelayTarget);
}

/** One relay between two targets through a managed host temp file. */
export interface SftpRelay {
  relayHandle: string;
  /** running | done | failed | cancelled. */
  state: string;
  /** download | upload, empty before the first leg starts. */
  leg: string;
  doneBytes: string;
  totalBytes: string;
  detail: string;
}

export function isSftpRelay(value: unknown): value is SftpRelay {
  return record(value) && exact(value, [
    "relayHandle", "state", "leg", "doneBytes", "totalBytes", "detail",
  ]) && safeName(value.relayHandle, false, 128) &&
    typeof value.state === "string" && relayStates.has(value.state) &&
    typeof value.leg === "string" && relayLegs.has(value.leg) &&
    u64String(value.doneBytes) && u64String(value.totalBytes) &&
    planText(value.detail, 1_024);
}
