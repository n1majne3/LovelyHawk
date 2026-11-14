export type ProcessWatchGap =
  | "hidepid"
  | "container"
  | "coarse-interval"
  | "proc-unreadable"
  | "polling-misses-short-lived"
  | "already-running"
  | "tool-may-miss-short-lived"
  | "inotify-low"
  | "file-events-limited";

export const PROCESS_WATCH_GAPS: readonly ProcessWatchGap[] = [
  "hidepid",
  "container",
  "coarse-interval",
  "proc-unreadable",
  "polling-misses-short-lived",
  "already-running",
  "tool-may-miss-short-lived",
  "inotify-low",
  "file-events-limited",
];

export type ProcessWatchMethod = "proc-poll" | "pspy";
/** How removing an uploaded program ended; only `clean` was verified. */
export type ProcessWatchCleanup = "clean" | "residue" | "unverified";
export type ProcessWatchOrigin = "cron" | "ssh" | "service" | "other" | "unknown";

export type ProcessWatchState =
  | "running"
  | "finished"
  | "cancelled"
  | "truncated"
  | "failed"
  | "disconnected";

export interface ProcessWatchProbe {
  procReadable: boolean;
  gaps: ProcessWatchGap[];
  fractionalSleep: boolean;
  account: string;
  isRoot: boolean;
}

export interface ProcessWatchStartInput {
  durationSeconds: number;
  intervalMs: number;
}

export interface ProcessWatchStarted {
  watchHandle: string;
  method: ProcessWatchMethod;
  startedAtMs: number;
  deadlineAtMs: number;
  gaps: ProcessWatchGap[];
}

export interface ProcessWatchEvent {
  /** `file` rows are file-system events: no process, `command` is event + path. */
  kind: "process" | "file";
  seq: number;
  atMs: number;
  /** `-1` when the target could not name an owner. */
  uid: number;
  pid: number;
  ppid: number | null;
  startTicks: number | null;
  command: string;
  clipped: boolean;
  origin: "baseline" | "observed";
  own: boolean;
  raw: string;
}

export interface ProcessWatchUnparsed {
  seq: number;
  raw: string;
}

export interface ProcessWatchPoll {
  watchHandle: string;
  state: ProcessWatchState;
  elapsedSeconds: number;
  observedCount: number;
  baselineCount: number;
  ownCount: number;
  unparsedCount: number;
  truncated: boolean;
  gaps: ProcessWatchGap[];
  /** Null while running and when the stop check could not reach the target. */
  stopVerified: boolean | null;
  selfEndsAtMs: number;
  nextCursor: number;
  /** Set once an upload run ended; null for a run that wrote nothing. */
  cleanup: ProcessWatchCleanup | null;
  events: ProcessWatchEvent[];
  unparsed: ProcessWatchUnparsed[];
}

export interface ProcessWatchStopped {
  state: ProcessWatchState;
  stopVerified: boolean | null;
  cleanup: ProcessWatchCleanup | null;
}

export type ProcessWatchCadence = "periodic" | "repeated" | "single";

export interface ProcessWatchGroup {
  normalized: string;
  sample: string;
  count: number;
  uids: number[];
  firstAtMs: number;
  lastAtMs: number;
  intervalsMs: number[];
  cadence: ProcessWatchCadence;
  periodMs: number | null;
  origin: ProcessWatchOrigin;
  /** The ancestor command that decided the origin; empty when none did. */
  originVia: string;
  /** The cron file that schedules this command, when one was matched. */
  schedule: string | null;
}

export interface ProcessWatchInferred {
  entryId: string;
  /** The workbench entry's title, as the catalogue shows it. */
  title: string;
  count: number;
  sample: string;
}

export interface ProcessWatchIndicator {
  kind: "ipv4" | "ipv6" | "domain" | "url";
  value: string;
  scope: "public" | "private" | "loopback" | "reserved";
  hits: number;
}

export interface ProcessWatchSummary {
  state: ProcessWatchState;
  observed: number;
  baseline: number;
  own: number;
  unparsed: number;
  periodicGroups: number;
  repeatedGroups: number;
  distinctUids: number;
  fileEvents: number;
  gaps: ProcessWatchGap[];
  groups: ProcessWatchGroup[];
  /** False when the cron files could not be read: no match then means unchecked. */
  scheduleRead: boolean;
  scheduleUnreadable: string[];
  origins: { origin: ProcessWatchOrigin; count: number }[];
  inferred: ProcessWatchInferred[];
  unmatched: { command: string; count: number }[];
  unmatchedTruncated: boolean;
  indicators: ProcessWatchIndicator[];
}

export type ProcessWatchSourceKind = "accounting" | "audit-execve" | "execsnoop" | "bpftrace";
/**
 * `readable`: recording and this account can read it. `unreadable`: there
 * is a record this account cannot read. `present`: installed, not known to
 * be recording.
 */
export type ProcessWatchSourceState = "readable" | "unreadable" | "present" | "absent";

export interface ProcessWatchSource {
  source: ProcessWatchSourceKind;
  state: ProcessWatchSourceState;
}

/** What process accounting recorded; program names only, no arguments. */
export interface ProcessWatchAccounting {
  minutes: number;
  records: number;
  unparsed: number;
  truncated: boolean;
  groups: {
    command: string;
    count: number;
    uids: number[];
    firstAtMs: number;
    lastAtMs: number;
    cadence: ProcessWatchCadence;
    periodMs: number | null;
  }[];
}

/** The program the operator picked, as the host read it. No path. */
export interface ProcessWatchTool {
  toolHandle: string;
  fileName: string;
  size: number;
  sha256: string;
  /** Which upstream release asset this is, when its digest is a known one. */
  recognized: string | null;
  arch: "x86" | "x86_64" | "other";
}

export interface ProcessWatchUploadInput {
  toolHandle: string;
  durationSeconds: number;
  fileEvents: boolean;
}

/** One upload run, described before anything is written. */
export interface ProcessWatchUploadPlan {
  planHandle: string;
  directory: string;
  size: number;
  sha256: string;
  recognized: string | null;
  account: string;
  isRoot: boolean;
  machine: string;
  durationSeconds: number;
  fileEvents: boolean;
  fileEventDirs: string[];
  gaps: ProcessWatchGap[];
  expiresInSeconds: number;
}

/** What an earlier upload run left on the target. */
export interface ProcessWatchResidue {
  residueHandle: string;
  directory: string;
  size: number;
  sha256: string;
  recognized: string | null;
  running: boolean;
}

export interface ProcessWatchApi {
  probeProcessWatch(bindingHandle: string): Promise<ProcessWatchProbe>;
  startProcessWatch(
    bindingHandle: string,
    input: ProcessWatchStartInput,
  ): Promise<ProcessWatchStarted>;
  pollProcessWatch(
    bindingHandle: string,
    watchHandle: string,
    cursor: number,
    limit: number,
  ): Promise<ProcessWatchPoll>;
  stopProcessWatch(
    bindingHandle: string,
    watchHandle: string,
  ): Promise<ProcessWatchStopped>;
  processWatchSummary(
    bindingHandle: string,
    watchHandle: string,
  ): Promise<ProcessWatchSummary>;
  /** Opens the native file dialog; null when the operator cancelled it. */
  pickProcessWatchTool(): Promise<ProcessWatchTool | null>;
  planProcessWatchUpload(
    bindingHandle: string,
    input: ProcessWatchUploadInput,
  ): Promise<ProcessWatchUploadPlan>;
  startProcessWatchUpload(
    bindingHandle: string,
    planHandle: string,
  ): Promise<ProcessWatchStarted>;
  listProcessWatchResidues(bindingHandle: string): Promise<ProcessWatchResidue[]>;
  cleanProcessWatchResidue(
    bindingHandle: string,
    residueHandle: string,
  ): Promise<ProcessWatchCleanup>;
  listProcessWatchSources(bindingHandle: string): Promise<ProcessWatchSource[]>;
  readProcessWatchAccounting(
    bindingHandle: string,
    minutes: number,
  ): Promise<ProcessWatchAccounting>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const HANDLE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const MAX_UINT32 = 4_294_967_295;

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function unsigned(value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

/**
 * Bounded, control-character-free text. It does not judge the content: a
 * collected command line that mentions a credential is the evidence, and
 * refusing it here would reject the whole response rather than one line.
 */
function publicText(value: unknown, maximumBytes: number, allowEmpty = true): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes &&
    !/[\u0000-\u001f]/u.test(value);
}

function jsonBytesAtMost(value: unknown, maximum: number): boolean {
  try {
    return encoder.encode(JSON.stringify(value)).byteLength <= maximum;
  } catch {
    return false;
  }
}

export function isProcessWatchHandle(value: unknown): value is string {
  return typeof value === "string" && HANDLE.test(value);
}

function gapList(value: unknown): value is ProcessWatchGap[] {
  return Array.isArray(value) && value.length <= PROCESS_WATCH_GAPS.length &&
    value.every((gap) => PROCESS_WATCH_GAPS.includes(gap as ProcessWatchGap));
}

function cleanup(value: unknown): value is ProcessWatchCleanup {
  return value === "clean" || value === "residue" || value === "unverified";
}

const SHA256 = /^[0-9a-f]{64}$/u;
const LANDING = /^\/[A-Za-z0-9._/-]{0,200}\/\.lovelyhawk-watch-[0-9a-f]{16}$/u;
const FILE_EVENT_DIRS = ["/etc", "/tmp", "/var/tmp", "/dev/shm", "/var/spool/cron", "/var/www"];

function recognized(value: unknown): value is string | null {
  return value === null || publicText(value, 64, false);
}

export function isProcessWatchTool(value: unknown): value is ProcessWatchTool {
  return record(value) && exact(value, [
    "toolHandle", "fileName", "size", "sha256", "recognized", "arch",
  ]) && isProcessWatchHandle(value.toolHandle) && publicText(value.fileName, 512) &&
    unsigned(value.size, 16 * 1_024 * 1_024) && value.size > 0 &&
    typeof value.sha256 === "string" && SHA256.test(value.sha256) &&
    recognized(value.recognized) &&
    (value.arch === "x86" || value.arch === "x86_64" || value.arch === "other");
}

export function isProcessWatchUploadInput(value: unknown): value is ProcessWatchUploadInput {
  return record(value) && exact(value, ["toolHandle", "durationSeconds", "fileEvents"]) &&
    isProcessWatchHandle(value.toolHandle) &&
    unsigned(value.durationSeconds, 1_800) && value.durationSeconds >= 60 &&
    typeof value.fileEvents === "boolean";
}

export function isProcessWatchUploadPlan(value: unknown): value is ProcessWatchUploadPlan {
  return record(value) && exact(value, [
    "planHandle", "directory", "size", "sha256", "recognized", "account", "isRoot",
    "machine", "durationSeconds", "fileEvents", "fileEventDirs", "gaps", "expiresInSeconds",
  ]) && isProcessWatchHandle(value.planHandle) &&
    typeof value.directory === "string" && LANDING.test(value.directory) &&
    unsigned(value.size, 16 * 1_024 * 1_024) && value.size > 0 &&
    typeof value.sha256 === "string" && SHA256.test(value.sha256) &&
    recognized(value.recognized) && publicText(value.account, 512, false) &&
    typeof value.isRoot === "boolean" && publicText(value.machine, 64, false) &&
    unsigned(value.durationSeconds, 1_800) && value.durationSeconds >= 60 &&
    typeof value.fileEvents === "boolean" &&
    Array.isArray(value.fileEventDirs) && value.fileEventDirs.length <= FILE_EVENT_DIRS.length &&
    value.fileEventDirs.every((directory) => FILE_EVENT_DIRS.includes(directory as string)) &&
    (value.fileEvents || value.fileEventDirs.length === 0) &&
    gapList(value.gaps) && unsigned(value.expiresInSeconds, 3_600) && value.expiresInSeconds > 0;
}

function isProcessWatchResidue(value: unknown): value is ProcessWatchResidue {
  return record(value) && exact(value, [
    "residueHandle", "directory", "size", "sha256", "recognized", "running",
  ]) && isProcessWatchHandle(value.residueHandle) &&
    typeof value.directory === "string" && LANDING.test(value.directory) &&
    unsigned(value.size) && typeof value.sha256 === "string" &&
    (value.sha256 === "" || SHA256.test(value.sha256)) &&
    recognized(value.recognized) && typeof value.running === "boolean";
}

export function isProcessWatchResidueList(value: unknown): value is ProcessWatchResidue[] {
  return Array.isArray(value) && value.length <= 64 && value.every(isProcessWatchResidue);
}

export function isProcessWatchResidueCleaned(
  value: unknown,
): value is { cleanup: ProcessWatchCleanup } {
  return record(value) && exact(value, ["cleanup"]) && cleanup(value.cleanup);
}

export function isProcessWatchSourceList(value: unknown): value is ProcessWatchSource[] {
  return Array.isArray(value) && value.length <= 4 && value.every((entry) =>
    record(entry) && exact(entry, ["source", "state"]) &&
    (entry.source === "accounting" || entry.source === "audit-execve" ||
      entry.source === "execsnoop" || entry.source === "bpftrace") &&
    (entry.state === "readable" || entry.state === "unreadable" ||
      entry.state === "present" || entry.state === "absent"));
}

export function isProcessWatchAccounting(value: unknown): value is ProcessWatchAccounting {
  return record(value) && exact(value, ["minutes", "records", "unparsed", "truncated", "groups"]) &&
    unsigned(value.minutes, 120) && value.minutes >= 1 && unsigned(value.records, 20_000) &&
    unsigned(value.unparsed) && typeof value.truncated === "boolean" &&
    Array.isArray(value.groups) && value.groups.length <= 500 &&
    value.groups.every((group) => record(group) && exact(group, [
      "command", "count", "uids", "firstAtMs", "lastAtMs", "cadence", "periodMs",
    ]) && publicText(group.command, 1_024, false) && unsigned(group.count) && group.count > 0 &&
      Array.isArray(group.uids) && group.uids.length <= 64 &&
      group.uids.every((uid) => unsigned(uid, MAX_UINT32)) &&
      unsigned(group.firstAtMs) && unsigned(group.lastAtMs) && group.firstAtMs <= group.lastAtMs &&
      (group.cadence === "periodic" || group.cadence === "repeated" || group.cadence === "single") &&
      (group.periodMs === null || unsigned(group.periodMs)) &&
      (group.cadence !== "periodic" || group.periodMs !== null)) &&
    jsonBytesAtMost(value, 2 * 1_024 * 1_024);
}

function state(value: unknown): value is ProcessWatchState {
  return value === "running" || value === "finished" || value === "cancelled" ||
    value === "truncated" || value === "failed" || value === "disconnected";
}

export function isProcessWatchStartInput(value: unknown): value is ProcessWatchStartInput {
  return record(value) && exact(value, ["durationSeconds", "intervalMs"]) &&
    unsigned(value.durationSeconds, 1_800) && value.durationSeconds >= 60 &&
    (value.intervalMs === 200 || value.intervalMs === 500 || value.intervalMs === 1_000);
}

export function isProcessWatchProbe(value: unknown): value is ProcessWatchProbe {
  return record(value) && exact(value, [
    "procReadable", "gaps", "fractionalSleep", "account", "isRoot",
  ]) && typeof value.procReadable === "boolean" && gapList(value.gaps) &&
    typeof value.fractionalSleep === "boolean" && publicText(value.account, 512) &&
    typeof value.isRoot === "boolean" &&
    value.procReadable !== value.gaps.includes("proc-unreadable") &&
    jsonBytesAtMost(value, 16 * 1_024);
}

export function isProcessWatchStarted(value: unknown): value is ProcessWatchStarted {
  return record(value) && exact(value, [
    "watchHandle", "method", "startedAtMs", "deadlineAtMs", "gaps",
  ]) && isProcessWatchHandle(value.watchHandle) &&
    (value.method === "proc-poll" || value.method === "pspy") &&
    unsigned(value.startedAtMs) && unsigned(value.deadlineAtMs) &&
    (value.startedAtMs === 0 || value.startedAtMs <= value.deadlineAtMs) &&
    gapList(value.gaps);
}

export function isProcessWatchEvent(value: unknown): value is ProcessWatchEvent {
  return record(value) && exact(value, [
    "kind", "seq", "atMs", "uid", "pid", "ppid", "startTicks", "command", "clipped",
    "origin", "own", "raw",
  ]) && (value.kind === "process" || value.kind === "file") &&
    unsigned(value.seq) && value.seq > 0 && unsigned(value.atMs) &&
    (value.uid === -1 || unsigned(value.uid, MAX_UINT32)) &&
    unsigned(value.pid, MAX_UINT32) &&
    (value.ppid === null || unsigned(value.ppid, MAX_UINT32)) &&
    (value.startTicks === null || unsigned(value.startTicks)) &&
    publicText(value.command, 8 * 1_024, false) && typeof value.clipped === "boolean" &&
    (value.origin === "baseline" || value.origin === "observed") &&
    typeof value.own === "boolean" && publicText(value.raw, 16 * 1_024) &&
    jsonBytesAtMost(value, 64 * 1_024);
}

function isProcessWatchUnparsed(value: unknown): value is ProcessWatchUnparsed {
  return record(value) && exact(value, ["seq", "raw"]) &&
    unsigned(value.seq) && value.seq > 0 && publicText(value.raw, 16 * 1_024) &&
    jsonBytesAtMost(value, 64 * 1_024);
}

export function isProcessWatchPoll(value: unknown): value is ProcessWatchPoll {
  if (!record(value) || !exact(value, [
    "watchHandle", "state", "elapsedSeconds", "observedCount", "baselineCount",
    "ownCount", "unparsedCount", "truncated", "gaps", "stopVerified",
    "selfEndsAtMs", "nextCursor", "cleanup", "events", "unparsed",
  ]) || !isProcessWatchHandle(value.watchHandle) || !state(value.state) ||
    !(value.cleanup === null || (cleanup(value.cleanup) && value.state !== "running")) ||
    !unsigned(value.elapsedSeconds, 4_000) || !unsigned(value.observedCount) ||
    !unsigned(value.baselineCount) || !unsigned(value.ownCount) ||
    !unsigned(value.unparsedCount) || typeof value.truncated !== "boolean" ||
    !gapList(value.gaps) ||
    !(value.stopVerified === null || typeof value.stopVerified === "boolean") ||
    !unsigned(value.selfEndsAtMs) || !unsigned(value.nextCursor) ||
    !Array.isArray(value.events) || value.events.length > 500 ||
    !value.events.every(isProcessWatchEvent) ||
    !Array.isArray(value.unparsed) || value.unparsed.length > 500 ||
    !value.unparsed.every(isProcessWatchUnparsed)) return false;
  const nextCursor = value.nextCursor;
  const sequences = value.events.map((event) => event.seq);
  const ordered = sequences.every((sequence, index) =>
    sequence <= nextCursor && (index === 0 || sequence > (sequences[index - 1] ?? 0)));
  const running = value.state === "running";
  return ordered && (value.stopVerified === null || !running) &&
    jsonBytesAtMost(value, 4 * 1_024 * 1_024);
}

export function isProcessWatchStopped(value: unknown): value is ProcessWatchStopped {
  return record(value) && exact(value, ["state", "stopVerified", "cleanup"]) &&
    state(value.state) &&
    (value.stopVerified === null || typeof value.stopVerified === "boolean") &&
    (value.cleanup === null || cleanup(value.cleanup));
}

function origin(value: unknown): value is ProcessWatchOrigin {
  return value === "cron" || value === "ssh" || value === "service" ||
    value === "other" || value === "unknown";
}

function isInferred(value: unknown): value is ProcessWatchInferred {
  return record(value) && exact(value, ["entryId", "title", "count", "sample"]) &&
    typeof value.entryId === "string" && /^[a-z][a-z0-9-]{1,63}$/u.test(value.entryId) &&
    publicText(value.title, 256, false) && unsigned(value.count) && value.count > 0 &&
    publicText(value.sample, 2 * 1_024, false);
}

function isIndicator(value: unknown): value is ProcessWatchIndicator {
  return record(value) && exact(value, ["kind", "value", "scope", "hits"]) &&
    (value.kind === "ipv4" || value.kind === "ipv6" || value.kind === "domain" || value.kind === "url") &&
    publicText(value.value, 2 * 1_024, false) &&
    (value.scope === "public" || value.scope === "private" || value.scope === "loopback" ||
      value.scope === "reserved") &&
    unsigned(value.hits, MAX_UINT32) && value.hits > 0;
}

function isProcessWatchGroup(value: unknown): value is ProcessWatchGroup {
  return record(value) && exact(value, [
    "normalized", "sample", "count", "uids", "firstAtMs", "lastAtMs",
    "intervalsMs", "cadence", "periodMs", "origin", "originVia", "schedule",
  ]) && origin(value.origin) && publicText(value.originVia, 1_024) &&
    (value.schedule === null || publicText(value.schedule, 1_024, false)) &&
    publicText(value.normalized, 8 * 1_024, false) &&
    publicText(value.sample, 8 * 1_024, false) &&
    unsigned(value.count) && value.count > 0 &&
    Array.isArray(value.uids) && value.uids.length <= 64 &&
    value.uids.every((uid) => unsigned(uid, MAX_UINT32)) &&
    unsigned(value.firstAtMs) && unsigned(value.lastAtMs) &&
    value.firstAtMs <= value.lastAtMs &&
    Array.isArray(value.intervalsMs) && value.intervalsMs.length <= 50 &&
    value.intervalsMs.every((interval) => unsigned(interval)) &&
    (value.cadence === "periodic" || value.cadence === "repeated" || value.cadence === "single") &&
    (value.periodMs === null || unsigned(value.periodMs)) &&
    (value.cadence !== "periodic" || value.periodMs !== null);
}

export function isProcessWatchSummary(value: unknown): value is ProcessWatchSummary {
  return record(value) && exact(value, [
    "state", "observed", "baseline", "own", "unparsed", "periodicGroups",
    "repeatedGroups", "distinctUids", "fileEvents", "gaps", "groups", "scheduleRead",
    "scheduleUnreadable", "origins", "inferred", "unmatched", "unmatchedTruncated",
    "indicators",
  ]) && unsigned(value.fileEvents) && typeof value.scheduleRead === "boolean" &&
    Array.isArray(value.scheduleUnreadable) && value.scheduleUnreadable.length <= 16 &&
    value.scheduleUnreadable.every((source) => publicText(source, 1_024, false)) &&
    Array.isArray(value.origins) && value.origins.length <= 5 &&
    value.origins.every((entry) => record(entry) && exact(entry, ["origin", "count"]) &&
      origin(entry.origin) && unsigned(entry.count)) &&
    Array.isArray(value.inferred) && value.inferred.length <= 32 &&
    value.inferred.every(isInferred) &&
    Array.isArray(value.unmatched) && value.unmatched.length <= 50 &&
    value.unmatched.every((entry) => record(entry) && exact(entry, ["command", "count"]) &&
      publicText(entry.command, 2 * 1_024, false) && unsigned(entry.count) && entry.count > 0) &&
    typeof value.unmatchedTruncated === "boolean" &&
    Array.isArray(value.indicators) && value.indicators.length <= 50 &&
    value.indicators.every(isIndicator) &&
    state(value.state) && unsigned(value.observed) &&
    unsigned(value.baseline) && unsigned(value.own) && unsigned(value.unparsed) &&
    unsigned(value.periodicGroups) && unsigned(value.repeatedGroups) &&
    unsigned(value.distinctUids, 1_024) && gapList(value.gaps) &&
    Array.isArray(value.groups) && value.groups.length <= 500 &&
    value.groups.every(isProcessWatchGroup) &&
    jsonBytesAtMost(value, 8 * 1_024 * 1_024);
}
