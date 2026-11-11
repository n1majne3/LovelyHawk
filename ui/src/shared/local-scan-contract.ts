export type LocalScanRequest =
  | { action: "engines" }
  | { action: "configure"; name: string; kind: "gui" | "cli"; arguments: string[] }
  | { action: "remove-engine"; engineId: string }
  | { action: "fetch"; bindingHandle: string; pathHandle: string; scope: "file" | "directory" }
  | { action: "inspect" | "reveal" | "discard"; bindingHandle: string; fetchId: string }
  | { action: "run"; bindingHandle: string; fetchId: string; engineId: string };

export interface LocalScanEngineDto {
  id: string;
  name: string;
  kind: "gui" | "cli";
  programName: string;
}
export interface LocalScanFetchDto {
  fetchId: string;
  path: string;
  sourceKind: "file" | "directory" | "other";
  scope: "file" | "directory";
  files: number;
  directories: number;
  bytes: number;
  skipped: number;
  skippedReasons: string[];
  truncated: boolean;
  archiveSha256: string;
  archiveBytes: number;
  transport: string;
  stagingDirectory: string;
  entries: string[];
  fetchedAt: string;
  expiresInSeconds: number;
}
export type LocalScanResult =
  | { kind: "engines"; engines: LocalScanEngineDto[] }
  | { kind: "fetch"; fetch: LocalScanFetchDto }
  | { kind: "run"; state: "launched" | "finished"; engineName: string; exitCode: number | null; output: string | null; detail: string }
  | { kind: "done"; detail: string };
export interface LocalScanApi {
  localScan(request: LocalScanRequest): Promise<LocalScanResult | null>;
}
const encoder = new TextEncoder();
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function text(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.trim().length > 0 && encoder.encode(value).length <= maximum &&
    ![...value].some((char) => { const code = char.codePointAt(0)!; return code < 0x20 || code >= 0x7f && code <= 0x9f; });
}
function bounded(value: unknown, maximum: number): value is string {
  return typeof value === "string" && encoder.encode(value).length <= maximum;
}
export function isLocalScanRequest(value: unknown): value is LocalScanRequest {
  if (!record(value) || typeof value.action !== "string") return false;
  const keys = Object.keys(value);
  switch (value.action) {
    case "engines": return keys.length === 1;
    case "configure":
      return keys.length === 4 && text(value.name, 64) && (value.kind === "gui" || value.kind === "cli") &&
        Array.isArray(value.arguments) && value.arguments.length <= 16 && value.arguments.every((arg) => bounded(arg, 512));
    case "remove-engine": return keys.length === 2 && text(value.engineId, 64);
    case "fetch":
      return keys.length === 4 && text(value.bindingHandle, 128) && text(value.pathHandle, 128) &&
        (value.scope === "file" || value.scope === "directory");
    case "inspect": case "reveal": case "discard":
      return keys.length === 3 && text(value.bindingHandle, 128) && text(value.fetchId, 128);
    case "run":
      return keys.length === 4 && text(value.bindingHandle, 128) && text(value.fetchId, 128) && text(value.engineId, 64);
    default: return false;
  }
}
function count(value: unknown, max: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max;
}
function isEngine(value: unknown): value is LocalScanEngineDto {
  return record(value) && Object.keys(value).length === 4 && text(value.id, 64) && text(value.name, 64) &&
    (value.kind === "gui" || value.kind === "cli") && text(value.programName, 1024);
}
function isFetch(value: unknown): value is LocalScanFetchDto {
  return record(value) && Object.keys(value).length === 17 &&
    text(value.fetchId, 128) && text(value.path, 4096) && value.path.startsWith("/") &&
    (value.sourceKind === "file" || value.sourceKind === "directory" || value.sourceKind === "other") &&
    (value.scope === "file" || value.scope === "directory") &&
    count(value.files, 1_000_000) && count(value.directories, 1_000_000) && count(value.bytes, 4 * 1024 * 1024 * 1024) &&
    count(value.skipped, 1_000_000) && typeof value.truncated === "boolean" &&
    typeof value.archiveSha256 === "string" && /^[a-f0-9]{64}$/u.test(value.archiveSha256) &&
    count(value.archiveBytes, 4 * 1024 * 1024 * 1024) && text(value.transport, 32) &&
    text(value.stagingDirectory, 32768) && bounded(value.fetchedAt, 64) && count(value.expiresInSeconds, 86_400) &&
    Array.isArray(value.skippedReasons) && value.skippedReasons.length <= 32 && value.skippedReasons.every((r) => bounded(r, 512)) &&
    Array.isArray(value.entries) && value.entries.length <= 512 && value.entries.every((e) => bounded(e, 1024));
}
export function isLocalScanResult(value: unknown): value is LocalScanResult {
  if (!record(value) || typeof value.kind !== "string") return false;
  switch (value.kind) {
    case "engines":
      return Object.keys(value).length === 2 && Array.isArray(value.engines) && value.engines.length <= 8 && value.engines.every(isEngine);
    case "fetch":
      return Object.keys(value).length === 2 && isFetch(value.fetch);
    case "run":
      return Object.keys(value).length === 6 && (value.state === "launched" || value.state === "finished") &&
        text(value.engineName, 64) && bounded(value.detail, 2048) &&
        (value.exitCode === null || count(value.exitCode, 2 ** 31)) &&
        (value.output === null || bounded(value.output, 64 * 1024));
    case "done":
      return Object.keys(value).length === 2 && bounded(value.detail, 2048);
    default: return false;
  }
}
export function matchesLocalScanResult(request: LocalScanRequest, result: unknown): result is LocalScanResult | null {
  if (result === null) return request.action === "configure";
  if (!isLocalScanResult(result)) return false;
  switch (request.action) {
    case "engines": case "configure": case "remove-engine":
      return result.kind === "engines";
    case "fetch": case "inspect":
      return result.kind === "fetch" && (request.action === "inspect" ? result.fetch.fetchId === request.fetchId : true);
    case "run":
      return result.kind === "run";
    case "reveal": case "discard":
      return result.kind === "done";
  }
}
