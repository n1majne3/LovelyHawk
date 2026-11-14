export const emergencyCommandCategories = [
  "permissions", "accounts", "network", "processes", "persistence", "logs", "files", "containers", "system",
] as const;
export const emergencyCommandResultKinds = [
  "success", "empty", "non-zero", "timeout", "missing-command", "permission-denied", "unknown-exit",
] as const;

export const emergencyPathActions = [
  "disarm", "quarantine", "remove-capabilities", "restore-residue", "delete-lines",
  "disable-xinetd-service",
] as const;

export type EmergencyCommandCategory = typeof emergencyCommandCategories[number];
export type EmergencyCommandResultKind = typeof emergencyCommandResultKinds[number];
export type EmergencyPathAction = typeof emergencyPathActions[number];

export interface EmergencyCommandCatalogItem {
  commandHandle: string;
  category: EmergencyCommandCategory;
  title: string;
  description: string;
  timeoutSeconds: number;
  optIn: boolean;
}

export const emergencyCommandPlaces = ["container", "pod"] as const;
export type EmergencyCommandPlace = typeof emergencyCommandPlaces[number];

/**
 * A place on this target that a check can be pointed at.
 *
 * A container of its runtime, or a pod of the cluster it can reach. Name and
 * image so a person can pick the right one; a handle so the run can name it.
 * No container id and no raw pod reference — the same rule the Docker and
 * Kubernetes panes follow.
 */
export interface EmergencyCommandContainer {
  containerHandle: string;
  /**
   * Which kind of place this is.
   *
   * Carried rather than guessed from the name, so the pane can say "容器" or
   * "Pod" truthfully instead of calling everything a container.
   */
  kind: EmergencyCommandPlace;
  /** A container's name, or a pod as `namespace/name`. */
  name: string;
  image: string;
}

/**
 * Whether the commands were chosen for this machine or are the portable set.
 *
 * A closed pair of words, never the distribution itself: what the operator
 * needs to know is whether the answers they are about to get are the good ones.
 */
export type EmergencyCommandSet = "detected" | "portable";

export interface EmergencyCommandCatalog {
  snapshotHandle: string;
  expiresInSeconds: number;
  commandSet: EmergencyCommandSet;
  commands: EmergencyCommandCatalogItem[];
  /**
   * Empty when the target has no container runtime, which is the ordinary
   * case and not an error.
   */
  containers: EmergencyCommandContainer[];
}

/**
 * A file one output line named, offered back as a capability.
 *
 * The window shows `path` and acts through `pathHandle`. It never sends a path
 * of its own, so an action can only ever reach a file the target itself
 * printed into this result.
 */
export interface EmergencyCommandPathOffer {
  pathHandle: string;
  /** Which displayed output line this path was read from. */
  line: number;
  path: string;
  /** Whether the path sits in the line-delete allow-list, so the menu only offers it where it can apply. */
  lineEditable: boolean;
  /** Whether the path is a file xinetd would load, so the menu only offers the service action there. */
  xinetdService: boolean;
}

export interface EmergencyCommandResult {
  snapshotHandle: string;
  commandHandle: string;
  resultKind: EmergencyCommandResultKind;
  exitCode: number | null;
  output: string;
  observedLineCount: number;
  displayedLineCount: number;
  /** Displayed line indexes the core judged abnormal, ascending. */
  findingLines: number[];
  /** Why those lines were marked, or null when the command marks nothing. */
  findingReason: string | null;
  truncated: boolean;
  /** The literal command handed to the target, control characters escaped. */
  command: string;
  commandTruncated: boolean;
  /** What the target returned before projection, control characters escaped. */
  rawOutput: string;
  rawOutputTruncated: boolean;
  /** The files this output named, at most one per displayed line. */
  paths: EmergencyCommandPathOffer[];
}

/** What the target says about one of those files right now. */
export interface EmergencyPathDetail {
  pathHandle: string;
  path: string;
  kind: "file" | "directory" | "symlink" | "other";
  /** Byte count as text, because a file can be larger than a safe integer. */
  size: string;
  /** Four octal digits, or null when the target did not report permissions. */
  mode: string | null;
  ownerId: number | null;
  groupId: number | null;
  modifiedAt: string | null;
  executable: boolean;
}

/** A regular file a restore probe saw beside the command. */
export interface EmergencyPathResidueCandidate {
  path: string;
  /** Host-reported digest, bounded to the 64 hex characters a sha256 can be. */
  sha256: string;
  /** Byte count as text, because a file can be larger than a safe integer. */
  size: string;
  /** `backup` is an explicit backup spelling; `variant` a known `name+d` copy. */
  kind: "backup" | "variant";
}

/** The residue a restore plan would write over the command, and the rest it saw. */
export interface EmergencyPathResiduePlan {
  source: EmergencyPathResidueCandidate;
  /** The owning package name, or null when no package manager named one. */
  package: string | null;
  candidates: EmergencyPathResidueCandidate[];
}

/** What an action would do, before any of it is done. */
export interface EmergencyPathPlan {
  planHandle: string;
  pathHandle: string;
  path: string;
  action: EmergencyPathAction;
  summary: string;
  dangerous: boolean;
  restoreDescription: string | null;
  state: "planned" | "confirmed" | "spent";
  expiresInSeconds: number;
  /** What a restore-residue plan found; null for every other action. */
  residue: EmergencyPathResiduePlan | null;
}

/** One display-safe line of a file preview or a removal list. */
export interface EmergencyPathLine {
  number: number;
  /** Lossy text with control characters flattened; display only. */
  text: string;
  clipped: boolean;
}

/**
 * The numbered, sanitized lines of a managed file. The preview handle binds
 * the digest of exactly these bytes server-side; it never leaves the backend.
 */
export interface EmergencyPathLinesPreview {
  previewHandle: string;
  pathHandle: string;
  path: string;
  totalLines: number;
  lines: EmergencyPathLine[];
  /** The file has more lines than `lines` carries. */
  truncated: boolean;
}

/**
 * A line-deletion plan: the same fields a path plan carries, plus the exact
 * lines the delete would take out so the confirmation lists all of them.
 */
export interface EmergencyPathLinesPlan extends EmergencyPathPlan {
  removedLines: EmergencyPathLine[];
}

/** What happened, after the target was checked. */
export interface EmergencyPathReceipt {
  planHandle: string;
  path: string;
  action: EmergencyPathAction;
  passed: boolean;
  detail: string;
  restored: boolean;
  /** Refused by a check before anything was written; nothing needed restoring. */
  untouched: boolean;
  /** Done, verified and reversible: the receipt may offer to undo it for a while. */
  undoable: boolean;
}

export interface EmergencyCommandApi {
  loadEmergencyCommandCatalog(bindingHandle: string): Promise<unknown>;
  /**
   * Runs one catalogue check.
   *
   * With a container handle the same check runs inside that container instead
   * of on the target itself; the handle must come from the same catalogue.
   */
  runEmergencyCommand(
    bindingHandle: string,
    snapshotHandle: string,
    commandHandle: string,
    containerHandle?: string,
  ): Promise<unknown>;
  inspectEmergencyPath(bindingHandle: string, pathHandle: string): Promise<unknown>;
  planEmergencyPathAction(
    bindingHandle: string,
    pathHandle: string,
    action: EmergencyPathAction,
  ): Promise<unknown>;
  /**
   * The numbered lines of a managed startup or cron file, for picking the
   * range to delete. Refused for any other path kind or location.
   */
  previewEmergencyPathLines(bindingHandle: string, pathHandle: string): Promise<unknown>;
  /**
   * Plans a contiguous-line delete bound to the preview the range was picked
   * on. The returned plan is confirmed and executed through the same calls
   * every other path plan uses.
   */
  planEmergencyPathLines(
    bindingHandle: string,
    previewHandle: string,
    firstLine: number,
    lastLine: number,
  ): Promise<unknown>;
  confirmEmergencyPathAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  executeEmergencyPathAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  cancelEmergencyPathAction(bindingHandle: string, planHandle: string): Promise<void>;
  /** Puts a finished action back, only while the file is as the action left it. */
  undoEmergencyPathAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  /**
   * Finds, in this catalogue, the check a command-history record ran. Which
   * check that was stays with the backend; only this snapshot's handle comes
   * back, or why there is none.
   */
  locateEmergencyHistoryCommand(bindingHandle: string, snapshotHandle: string, historyId: string): Promise<unknown>;
  /**
   * Leads mined from the outputs this snapshot's runs left in the backend.
   * The page sends no output text; it only names the snapshot.
   */
  extractEmergencyCommandIocs(bindingHandle: string, snapshotHandle: string): Promise<unknown>;
  /**
   * Plans the same containment action for up to fifty offered handles. Each
   * row comes back with its own plan or its own refusal; one confirmation
   * covers the previewed set.
   */
  planEmergencyPathBatch(
    bindingHandle: string,
    pathHandles: readonly string[],
    action: EmergencyPathAction,
  ): Promise<unknown>;
  confirmEmergencyPathBatch(bindingHandle: string, batchHandle: string): Promise<unknown>;
  stepEmergencyPathBatch(bindingHandle: string, batchHandle: string): Promise<unknown>;
  cancelEmergencyPathBatch(bindingHandle: string, batchHandle: string): Promise<void>;
}

export const emergencyPathBatchStates = ["planned", "confirmed"] as const;
export type EmergencyPathBatchState = typeof emergencyPathBatchStates[number];

/**
 * One row of a batch preview: the file as it stood, and either what would
 * happen to it or the refusal key standing instead.
 */
export interface EmergencyPathBatchItem {
  pathHandle: string;
  /** The stored path; empty where the offered handle already went stale. */
  path: string;
  /** Empty where the handle was stale before the file could be read. */
  kind: "file" | "directory" | "symlink" | "other" | "";
  size: string;
  mode: string | null;
  executable: boolean;
  /** The item's own plan identity — receipts and undo still name it. */
  planHandle: string | null;
  summary: string | null;
  restoreDescription: string | null;
  refusal: string | null;
}

export interface EmergencyPathBatchPlan {
  batchHandle: string;
  action: EmergencyPathAction;
  items: EmergencyPathBatchItem[];
  planned: number;
  refused: number;
  state: EmergencyPathBatchState;
  expiresInSeconds: number;
}

/** One finished item's own receipt plus where the batch stands after it. */
export interface EmergencyPathBatchStep {
  batchHandle: string;
  receipt: EmergencyPathReceipt | null;
  remaining: number;
  refused: number;
  finished: boolean;
}

export const emergencyIocKinds = ["ipv4", "ipv6", "domain", "url"] as const;
export const emergencyIocScopes = ["public", "private", "loopback", "reserved"] as const;
export type EmergencyIocKind = typeof emergencyIocKinds[number];
export type EmergencyIocScope = typeof emergencyIocScopes[number];

/**
 * One address-like lead and where it was seen. A lead is something to check,
 * never a confirmed indicator — the report carries no verdict.
 */
export interface EmergencyIocEntry {
  kind: EmergencyIocKind;
  value: string;
  scope: EmergencyIocScope;
  /** How many times the value occurred across all stored output. */
  hits: number;
  /** Titles of the checks whose output contained it. */
  sources: string[];
  /** A well-known distro/package name — kept, but marked. */
  common: boolean;
}

export interface EmergencyIocReport {
  entries: EmergencyIocEntry[];
  truncated: boolean;
}

export const emergencyHistoryLocationStatuses = ["found", "missing", "not-recorded", "not-in-catalog"] as const;
export type EmergencyHistoryLocationStatus = typeof emergencyHistoryLocationStatuses[number];

/** Where a history record's check sits in the current catalogue, if anywhere. */
export interface EmergencyHistoryLocation {
  status: EmergencyHistoryLocationStatus;
  commandHandle: string | null;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const categorySet = new Set<string>(emergencyCommandCategories);
const resultKindSet = new Set<string>(emergencyCommandResultKinds);
const placeSet = new Set<string>(emergencyCommandPlaces);
const pathActionSet = new Set<string>(emergencyPathActions);
const pathKindSet = new Set<string>(["file", "directory", "symlink", "other"]);
const planStateSet = new Set<string>(["planned", "confirmed", "spent"]);

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

function signedI32OrNull(value: unknown): value is number | null {
  return value === null || typeof value === "number" && Number.isInteger(value) &&
    value >= -2_147_483_648 && value <= 2_147_483_647;
}

function serializedWithin(value: unknown, maximumBytes: number): boolean {
  try {
    const encoded = JSON.stringify(value);
    return typeof encoded === "string" && encoder.encode(encoded).byteLength <= maximumBytes;
  } catch {
    return false;
  }
}

export function isEmergencyCommandOpaqueHandle(value: unknown): value is string {
  return text(value, 128, false) && /^[A-Za-z0-9-]+$/u.test(value);
}

function catalogText(value: unknown, maximumBytes: number): value is string {
  return text(value, maximumBytes, false) && !/[\u0000-\u001f\u007f]/u.test(value);
}

/**
 * The command and raw-output views arrive with control characters already
 * escaped into printable text, so a raw control character on the wire — any
 * except the newline and tab the fields legitimately contain — is a violation.
 */
function escapedText(value: unknown, maximumBytes: number): value is string {
  return text(value, maximumBytes, true) &&
    !/[ --]/u.test(value);
}

function catalogItem(value: unknown): value is EmergencyCommandCatalogItem {
  return record(value) && exact(value, [
    "commandHandle", "category", "title", "description", "timeoutSeconds", "optIn",
  ]) && isEmergencyCommandOpaqueHandle(value.commandHandle) && typeof value.category === "string" &&
    categorySet.has(value.category) && catalogText(value.title, 128) && catalogText(value.description, 512) &&
    unsigned(value.timeoutSeconds, 60) && value.timeoutSeconds > 0 && typeof value.optIn === "boolean";
}

export function isEmergencyCommandCatalog(value: unknown): value is EmergencyCommandCatalog {
  if (!record(value) || !exact(value, ["snapshotHandle", "expiresInSeconds", "commandSet", "commands", "containers"]) ||
    !isEmergencyCommandOpaqueHandle(value.snapshotHandle) || value.expiresInSeconds !== 300 ||
    (value.commandSet !== "detected" && value.commandSet !== "portable") ||
    !Array.isArray(value.commands) || value.commands.length > 256 || !value.commands.every(catalogItem) ||
    !Array.isArray(value.containers) || value.containers.length > 64 ||
    !value.containers.every(catalogContainer) ||
    !serializedWithin(value, 256 * 1_024)) return false;
  const commands = value.commands as EmergencyCommandCatalogItem[];
  const containers = value.containers as EmergencyCommandContainer[];
  return new Set(commands.map((command) => command.commandHandle)).size === commands.length &&
    new Set(containers.map((container) => container.containerHandle)).size === containers.length;
}

function catalogContainer(value: unknown): value is EmergencyCommandContainer {
  return record(value) && exact(value, ["containerHandle", "kind", "name", "image"]) &&
    isEmergencyCommandOpaqueHandle(value.containerHandle) &&
    typeof value.kind === "string" && placeSet.has(value.kind) &&
    catalogText(value.name, 128) && catalogText(value.image, 128);
}

/**
 * Output is shown as the target printed it. Only control characters and the
 * per-line byte ceiling are enforced, because those break rendering; nothing is
 * filtered on how the text looks.
 */
function outputLine(value: string): boolean {
  return encoder.encode(value).byteLength <= 4 * 1_024 &&
    !/[\r\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value);
}

function outputLines(value: string): string[] {
  return value.length === 0 ? [] : value.split("\n");
}

/**
 * A path the sidecar read out of its own output. It is displayed, never sent
 * back, so the check is only that it is drawable and could name a real file.
 */
function offeredPath(value: unknown): value is string {
  return text(value, 1_024, false) && value.startsWith("/") && !/[\u0000-\u001f\u007f]/u.test(value);
}

function pathOffer(value: unknown): value is EmergencyCommandPathOffer {
  return record(value) && exact(value, ["pathHandle", "line", "path", "lineEditable", "xinetdService"]) &&
    isEmergencyCommandOpaqueHandle(value.pathHandle) && unsigned(value.line, 1_999) &&
    offeredPath(value.path) && typeof value.lineEditable === "boolean" &&
    typeof value.xinetdService === "boolean";
}

export function isEmergencyCommandResult(value: unknown): value is EmergencyCommandResult {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "commandHandle", "resultKind", "exitCode", "output", "observedLineCount",
    "displayedLineCount", "findingLines", "findingReason", "truncated",
    "command", "commandTruncated", "rawOutput", "rawOutputTruncated", "paths",
  ]) || !isEmergencyCommandOpaqueHandle(value.snapshotHandle) ||
    !isEmergencyCommandOpaqueHandle(value.commandHandle) || typeof value.resultKind !== "string" ||
    !resultKindSet.has(value.resultKind) || !signedI32OrNull(value.exitCode) || !text(value.output, 256 * 1_024) ||
    !unsigned(value.observedLineCount, 2 * 1_024 * 1_024) || !unsigned(value.displayedLineCount, 2_000) ||
    typeof value.truncated !== "boolean" ||
    !Array.isArray(value.findingLines) || value.findingLines.length > 2_000 ||
    !(value.findingReason === null || catalogText(value.findingReason, 512)) ||
    !escapedText(value.command, 128 * 1_024) || typeof value.commandTruncated !== "boolean" ||
    !escapedText(value.rawOutput, 1_024 * 1_024) || typeof value.rawOutputTruncated !== "boolean" ||
    !Array.isArray(value.paths) || value.paths.length > 500 || !value.paths.every(pathOffer) ||
    !serializedWithin(value, 1_536 * 1_024)) return false;
  const lines = outputLines(value.output);
  if (lines.length !== value.displayedLineCount || value.displayedLineCount > value.observedLineCount ||
    !lines.every(outputLine) || value.observedLineCount > value.displayedLineCount && !value.truncated) return false;
  // A mark has to point at a line that is actually here.
  const marks = value.findingLines as unknown[];
  if (!marks.every((mark, index) => unsigned(mark, 1_999) && mark < lines.length &&
    (index === 0 || mark > (marks[index - 1] as number)))) return false;
  // An offer has to point at a line that is here, name what that line says,
  // and be the only offer for it.
  const offers = value.paths as EmergencyCommandPathOffer[];
  if (new Set(offers.map((offer) => offer.pathHandle)).size !== offers.length ||
    new Set(offers.map((offer) => offer.line)).size !== offers.length ||
    !offers.every((offer) => offer.line < lines.length &&
      (lines[offer.line] as string).includes(offer.path.slice(offer.path.lastIndexOf("/") + 1)))) return false;
  if (value.resultKind === "success") return value.exitCode === 0 && value.output.length > 0;
  if (value.resultKind === "empty") return value.exitCode === 0 && value.output.length === 0;
  if (value.resultKind === "non-zero") return value.exitCode !== null && value.exitCode !== 0;
  if (value.resultKind === "unknown-exit") return value.exitCode === null;
  return true;
}

export function isEmergencyPathDetail(value: unknown): value is EmergencyPathDetail {
  return record(value) && exact(value, [
    "pathHandle", "path", "kind", "size", "mode", "ownerId", "groupId", "modifiedAt", "executable",
  ]) && isEmergencyCommandOpaqueHandle(value.pathHandle) && offeredPath(value.path) &&
    typeof value.kind === "string" && pathKindSet.has(value.kind) &&
    typeof value.size === "string" && /^\d{1,20}$/u.test(value.size) &&
    (value.mode === null || typeof value.mode === "string" && /^[0-7]{4}$/u.test(value.mode)) &&
    (value.ownerId === null || unsigned(value.ownerId, 4_294_967_295)) &&
    (value.groupId === null || unsigned(value.groupId, 4_294_967_295)) &&
    (value.modifiedAt === null || catalogText(value.modifiedAt, 64)) &&
    typeof value.executable === "boolean";
}

const residueKindSet = new Set<string>(["backup", "variant"]);

function residueCandidate(value: unknown): value is EmergencyPathResidueCandidate {
  return record(value) && exact(value, ["path", "sha256", "size", "kind"]) &&
    offeredPath(value.path) &&
    typeof value.sha256 === "string" && /^[0-9a-f]{1,64}$/u.test(value.sha256) &&
    typeof value.size === "string" && /^\d{1,20}$/u.test(value.size) &&
    typeof value.kind === "string" && residueKindSet.has(value.kind);
}

function residuePlan(value: unknown): value is EmergencyPathResiduePlan {
  if (!record(value) || !exact(value, ["source", "package", "candidates"]) ||
    !residueCandidate(value.source) ||
    !(value.package === null || catalogText(value.package, 128)) ||
    !Array.isArray(value.candidates) || value.candidates.length > 9 ||
    !value.candidates.every(residueCandidate)) return false;
  // The chosen source has to be one of the candidates the probe saw.
  const source = value.source as EmergencyPathResidueCandidate;
  return (value.candidates as EmergencyPathResidueCandidate[]).some(
    (candidate) => candidate.path === source.path && candidate.sha256 === source.sha256,
  );
}

export function isEmergencyPathPlan(value: unknown): value is EmergencyPathPlan {
  return record(value) && exact(value, [
    "planHandle", "pathHandle", "path", "action", "summary", "dangerous", "restoreDescription",
    "state", "expiresInSeconds", "residue",
  ]) && isEmergencyCommandOpaqueHandle(value.planHandle) &&
    isEmergencyCommandOpaqueHandle(value.pathHandle) && offeredPath(value.path) &&
    typeof value.action === "string" && pathActionSet.has(value.action) &&
    catalogText(value.summary, 512) && typeof value.dangerous === "boolean" &&
    (value.restoreDescription === null || catalogText(value.restoreDescription, 512)) &&
    typeof value.state === "string" && planStateSet.has(value.state) &&
    unsigned(value.expiresInSeconds, 300) && value.expiresInSeconds > 0 &&
    (value.residue === null || residuePlan(value.residue));
}

const MAX_PREVIEW_LINES = 5_000;
const MAX_LINE_TEXT_BYTES = 512;

function previewLine(value: unknown): value is EmergencyPathLine {
  return record(value) && exact(value, ["number", "text", "clipped"]) &&
    unsigned(value.number, 4_294_967_295) && value.number > 0 &&
    // Empty display lines exist; blank file lines do. Controls still refuse.
    text(value.text, MAX_LINE_TEXT_BYTES) && !/[ -]/u.test(value.text) &&
    typeof value.clipped === "boolean";
}

export function isEmergencyPathLinesPreview(value: unknown): value is EmergencyPathLinesPreview {
  return record(value) && exact(value, [
    "previewHandle", "pathHandle", "path", "totalLines", "lines", "truncated",
  ]) && isEmergencyCommandOpaqueHandle(value.previewHandle) &&
    isEmergencyCommandOpaqueHandle(value.pathHandle) && offeredPath(value.path) &&
    unsigned(value.totalLines, 4_294_967_295) &&
    Array.isArray(value.lines) && value.lines.length <= MAX_PREVIEW_LINES &&
    (value.lines as unknown[]).every(previewLine) &&
    (value.lines as EmergencyPathLine[]).every((line, index) => line.number === index + 1) &&
    value.totalLines >= (value.lines as unknown[]).length &&
    typeof value.truncated === "boolean" &&
    // A truncated preview must actually be at the cap; an untruncated one names them all.
    (value.truncated ? (value.lines as unknown[]).length === MAX_PREVIEW_LINES
      : value.totalLines === (value.lines as unknown[]).length);
}

export function isEmergencyPathLinesPlan(value: unknown): value is EmergencyPathLinesPlan {
  if (!record(value) || !exact(value, [
    "planHandle", "pathHandle", "path", "action", "summary", "dangerous", "restoreDescription",
    "state", "expiresInSeconds", "residue", "removedLines",
  ]) || value.action !== "delete-lines") return false;
  const { removedLines: lines, ...plan } = value;
  return isEmergencyPathPlan(plan) && Array.isArray(lines) && lines.length >= 1 &&
    lines.length <= 200 && lines.every(previewLine) &&
    // The removal list must stay contiguous, exactly the range it names.
    ((removed) => {
      const head = removed[0];
      return head !== undefined && removed.every((line, index) => line.number === head.number + index);
    })(lines as EmergencyPathLine[]);
}

export function isEmergencyPathReceipt(value: unknown): value is EmergencyPathReceipt {
  return record(value) && exact(value, [
    "planHandle", "path", "action", "passed", "detail", "restored", "untouched", "undoable",
  ]) && isEmergencyCommandOpaqueHandle(value.planHandle) && offeredPath(value.path) &&
    typeof value.action === "string" && pathActionSet.has(value.action) &&
    typeof value.passed === "boolean" && catalogText(value.detail, 512) &&
    typeof value.restored === "boolean" && typeof value.untouched === "boolean" &&
    typeof value.undoable === "boolean" &&
    // Only a refusal can leave the file untouched, and then nothing was restored.
    (!value.untouched || (!value.passed && !value.restored)) &&
    // Only a verified action can be offered for undo.
    (!value.undoable || value.passed);
}

/** What an undo did: put back and read back, or refused with the reason. */
export interface EmergencyPathUndoResult {
  planHandle: string;
  path: string;
  undone: boolean;
  detail: string;
}

const historyLocationStatusSet = new Set<string>(emergencyHistoryLocationStatuses);

export function isEmergencyHistoryLocation(value: unknown): value is EmergencyHistoryLocation {
  return record(value) && exact(value, ["status", "commandHandle"]) &&
    typeof value.status === "string" && historyLocationStatusSet.has(value.status) &&
    // A handle exactly when it was found.
    (value.status === "found"
      ? isEmergencyCommandOpaqueHandle(value.commandHandle)
      : value.commandHandle === null);
}

export function isEmergencyPathUndoResult(value: unknown): value is EmergencyPathUndoResult {
  return record(value) && exact(value, ["planHandle", "path", "undone", "detail"]) &&
    isEmergencyCommandOpaqueHandle(value.planHandle) && offeredPath(value.path) &&
    typeof value.undone === "boolean" && catalogText(value.detail, 512);
}

const iocKindSet = new Set<string>(emergencyIocKinds);
const iocScopeSet = new Set<string>(emergencyIocScopes);
const MAX_IOC_ENTRIES = 500;
const MAX_IOC_SOURCES = 8;
const MAX_IOC_VALUE_BYTES = 512;
const MAX_IOC_SOURCE_BYTES = 128;

function iocEntry(value: unknown): value is EmergencyIocEntry {
  return record(value) && exact(value, ["kind", "value", "scope", "hits", "sources", "common"]) &&
    typeof value.kind === "string" && iocKindSet.has(value.kind) &&
    catalogText(value.value, MAX_IOC_VALUE_BYTES) &&
    typeof value.scope === "string" && iocScopeSet.has(value.scope) &&
    unsigned(value.hits, 0xffff_ffff) &&
    Array.isArray(value.sources) && value.sources.length <= MAX_IOC_SOURCES &&
    (value.sources as unknown[]).every((source) => catalogText(source, MAX_IOC_SOURCE_BYTES)) &&
    typeof value.common === "boolean";
}

export function isEmergencyIocReport(value: unknown): value is EmergencyIocReport {
  return record(value) && exact(value, ["entries", "truncated"]) &&
    Array.isArray(value.entries) && value.entries.length <= MAX_IOC_ENTRIES &&
    (value.entries as unknown[]).every(iocEntry) &&
    typeof value.truncated === "boolean";
}

const batchStateSet = new Set<string>(emergencyPathBatchStates);
// Restore and capability edits stay single-path decisions; a batch can only
// ever be one of the two containment actions.
const batchActionSet = new Set<string>(["disarm", "quarantine"]);
const MAX_BATCH_ITEMS = 50;
const MAX_BATCH_REFUSAL_BYTES = 64;

function batchItem(value: unknown): value is EmergencyPathBatchItem {
  if (!record(value) || !exact(value, [
    "pathHandle", "path", "kind", "size", "mode", "executable",
    "planHandle", "summary", "restoreDescription", "refusal",
  ]) || !isEmergencyCommandOpaqueHandle(value.pathHandle)) return false;
  const refused = value.refusal !== null;
  // A refused row carries only the refusal; a planned one carries the plan
  // facts. Neither may borrow the other's fields, and a stale row's empty
  // path stays empty.
  if (refused && (
    typeof value.refusal !== "string" || !catalogText(value.refusal, MAX_BATCH_REFUSAL_BYTES) ||
    value.planHandle !== null || value.summary !== null || value.restoreDescription !== null)) {
    return false;
  }
  if (!refused && (
    !isEmergencyCommandOpaqueHandle(value.planHandle) || !catalogText(value.summary, 512) ||
    !(value.restoreDescription === null || catalogText(value.restoreDescription, 512)))) {
    return false;
  }
  return (value.path === "" || offeredPath(value.path)) &&
    typeof value.kind === "string" && (pathKindSet.has(value.kind) || refused && value.kind === "") &&
    typeof value.size === "string" && (/^\d{1,20}$/u.test(value.size) || refused && value.size === "") &&
    (value.mode === null || typeof value.mode === "string" && /^[0-7]{4}$/u.test(value.mode)) &&
    typeof value.executable === "boolean";
}

export function isEmergencyPathBatchPlan(value: unknown): value is EmergencyPathBatchPlan {
  if (!record(value) || !exact(value, [
    "batchHandle", "action", "items", "planned", "refused", "state", "expiresInSeconds",
  ]) || !isEmergencyCommandOpaqueHandle(value.batchHandle) ||
    typeof value.action !== "string" || !batchActionSet.has(value.action) ||
    !Array.isArray(value.items) || value.items.length === 0 || value.items.length > MAX_BATCH_ITEMS ||
    !(value.items as unknown[]).every(batchItem) ||
    !unsigned(value.planned, MAX_BATCH_ITEMS) || !unsigned(value.refused, MAX_BATCH_ITEMS) ||
    typeof value.state !== "string" || !batchStateSet.has(value.state) ||
    !unsigned(value.expiresInSeconds, 300) || value.expiresInSeconds === 0) return false;
  // The counts have to add up to the rows that are actually here.
  const items = value.items as EmergencyPathBatchItem[];
  const planned = items.filter((item) => item.refusal === null).length;
  return value.planned === planned && value.refused === items.length - planned;
}

export function isEmergencyPathBatchStep(value: unknown): value is EmergencyPathBatchStep {
  return record(value) && exact(value, ["batchHandle", "receipt", "remaining", "refused", "finished"]) &&
    isEmergencyCommandOpaqueHandle(value.batchHandle) &&
    (value.receipt === null || isEmergencyPathReceipt(value.receipt)) &&
    unsigned(value.remaining, MAX_BATCH_ITEMS) && unsigned(value.refused, MAX_BATCH_ITEMS) &&
    typeof value.finished === "boolean" &&
    // A finished batch has nothing left to run; a step with nothing run is the end.
    (!value.finished || value.remaining === 0) && (value.finished || value.receipt !== null);
}

export function isEmergencyPathAction(value: unknown): value is EmergencyPathAction {
  return typeof value === "string" && pathActionSet.has(value);
}
