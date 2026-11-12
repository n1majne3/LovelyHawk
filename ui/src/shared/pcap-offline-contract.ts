/**
 * Offline pcap analysis contract. Mirrors crates/lovelyhawk-backend's
 * pcap_offline_api: status DTO plus the analysis result. No local paths and no
 * object bytes ever cross this boundary — import/export are host commands.
 */

export type PcapOfflineSource = "import" | "evidence" | "";
export type PcapOfflineState = "idle" | "reading" | "analyzing" | "done" | "failed" | "cancelled";

export interface PcapSummary {
  format: string;
  linkTypes: number[];
  packetCount: number;
  parsedCount: number;
  malformedCount: number;
  fragmentCount: number;
  flowCapHit: boolean;
  streamCapHit: boolean;
  packetCapHit: boolean;
  warnings: string[];
}

export interface PcapFlow {
  id: number;
  proto: string;
  endpointA: string;
  endpointB: string;
  packets: number;
  bytes: number;
  firstMs: number;
  lastMs: number;
  tcpGaps: number;
  streamTruncated: boolean;
}

export interface PcapHttpTx {
  id: number;
  flowId: number;
  method: string;
  uri: string;
  host: string;
  status: number;
  reqContentType: string;
  respContentType: string;
  reqBodySize: number;
  respBodySize: number;
  reqObjectId: string | null;
  respObjectId: string | null;
  reqHeaders: string[];
  respHeaders: string[];
  incomplete: boolean;
}

export interface PcapObjectInfo {
  id: string;
  sha256: string;
  size: number;
  contentType: string;
  uri: string;
  kind: string;
  stored: boolean;
}

export interface PcapAlert {
  rule: string;
  level: "lead" | "strong" | "weak";
  message: string;
  flowId: number | null;
  txId: number | null;
}

export interface PcapEcho {
  txId: number | null;
  flowId: number;
  marker: "x@y" | "arrow";
  text: string;
}

export interface PcapAnalysisResult {
  summary: PcapSummary;
  flows: PcapFlow[];
  http: PcapHttpTx[];
  objects: PcapObjectInfo[];
  alerts: PcapAlert[];
  echoes: PcapEcho[];
}

export interface PcapOfflineStatus {
  state: PcapOfflineState;
  source: PcapOfflineSource;
  bytesRead: number;
  totalBytes: number;
  detail: string;
  result: PcapAnalysisResult | null;
}

const MAX = 2_000;
const text = (v: unknown, max = 64 * 1024): v is string => typeof v === "string" && v.length <= max;
const short = (v: unknown): v is string => typeof v === "string" && v.length <= 4096;
const uint = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const bool = (v: unknown): v is boolean => typeof v === "boolean";
const strList = (v: unknown, cap = MAX): v is string[] => Array.isArray(v) && v.length <= cap && v.every((s) => text(s, 8192));
const nullableShort = (v: unknown): v is string | null => v === null || short(v);
const nullableUint = (v: unknown): v is number | null => v === null || uint(v);

function exact(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return (
    typeof value === "object" && value !== null && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((k) => k in value)
  );
}
const listOf = (cap: number, check: (v: unknown) => boolean) => (v: unknown) =>
  Array.isArray(v) && v.length <= cap && v.every(check);

const isSummary = (v: unknown): v is PcapSummary =>
  exact(v, ["format", "linkTypes", "packetCount", "parsedCount", "malformedCount", "fragmentCount", "flowCapHit", "streamCapHit", "packetCapHit", "warnings"]) &&
  short(v.format) && Array.isArray(v.linkTypes) && v.linkTypes.every(uint) &&
  [v.packetCount, v.parsedCount, v.malformedCount, v.fragmentCount].every(uint) &&
  [v.flowCapHit, v.streamCapHit, v.packetCapHit].every(bool) && strList(v.warnings, 64);

const isFlow = (v: unknown): v is PcapFlow =>
  exact(v, ["id", "proto", "endpointA", "endpointB", "packets", "bytes", "firstMs", "lastMs", "tcpGaps", "streamTruncated"]) &&
  uint(v.id) && short(v.proto) && short(v.endpointA) && short(v.endpointB) &&
  [v.packets, v.bytes, v.tcpGaps].every(uint) &&
  typeof v.firstMs === "number" && typeof v.lastMs === "number" && bool(v.streamTruncated);

const isTx = (v: unknown): v is PcapHttpTx =>
  exact(v, ["id", "flowId", "method", "uri", "host", "status", "reqContentType", "respContentType", "reqBodySize", "respBodySize", "reqObjectId", "respObjectId", "reqHeaders", "respHeaders", "incomplete"]) &&
  uint(v.id) && uint(v.flowId) && short(v.method) && text(v.uri, 8192) && short(v.host) && uint(v.status) &&
  short(v.reqContentType) && short(v.respContentType) && uint(v.reqBodySize) && uint(v.respBodySize) &&
  nullableShort(v.reqObjectId) && nullableShort(v.respObjectId) &&
  strList(v.reqHeaders, 64) && strList(v.respHeaders, 64) && bool(v.incomplete);

const isObject = (v: unknown): v is PcapObjectInfo =>
  exact(v, ["id", "sha256", "size", "contentType", "uri", "kind", "stored"]) &&
  typeof v.id === "string" && /^obj-\d{1,12}$/u.test(v.id) &&
  typeof v.sha256 === "string" && /^[0-9a-f]{64}$/u.test(v.sha256) &&
  uint(v.size) && short(v.contentType) && text(v.uri, 8192) && short(v.kind) && bool(v.stored);

const isAlert = (v: unknown): v is PcapAlert =>
  exact(v, ["rule", "level", "message", "flowId", "txId"]) &&
  short(v.rule) && ["lead", "strong", "weak"].includes(v.level as string) && text(v.message) &&
  nullableUint(v.flowId) && nullableUint(v.txId);

const isEcho = (v: unknown): v is PcapEcho =>
  exact(v, ["txId", "flowId", "marker", "text"]) &&
  nullableUint(v.txId) && uint(v.flowId) && ["x@y", "arrow"].includes(v.marker as string) && text(v.text, 8192);

export const isPcapAnalysisResult = (v: unknown): v is PcapAnalysisResult =>
  exact(v, ["summary", "flows", "http", "objects", "alerts", "echoes"]) &&
  isSummary(v.summary) &&
  listOf(MAX, isFlow)(v.flows) && listOf(MAX, isTx)(v.http) &&
  listOf(500, isObject)(v.objects) && listOf(500, isAlert)(v.alerts) &&
  listOf(100, isEcho)(v.echoes);

export const isPcapOfflineStatus = (v: unknown): v is PcapOfflineStatus =>
  exact(v, ["state", "source", "bytesRead", "totalBytes", "detail", "result"]) &&
  ["idle", "reading", "analyzing", "done", "failed", "cancelled"].includes(v.state as string) &&
  ["import", "evidence", ""].includes(v.source as string) &&
  uint(v.bytesRead) && uint(v.totalBytes) && text(v.detail) &&
  (v.result === null || isPcapAnalysisResult(v.result));

export type PcapOfflineRequest =
  | { action: "import" }
  | { action: "begin-evidence"; jobHandle: string }
  | { action: "status" }
  | { action: "cancel" }
  | { action: "export-object"; objectId: string; fileName?: string };

export type PcapOfflineResult =
  | { kind: "started"; started: boolean }
  | { kind: "status"; status: PcapOfflineStatus }
  | { kind: "cancelled" }
  | { kind: "exported"; exported: boolean; bytes: number };

export const isPcapOfflineRequest = (v: unknown): v is PcapOfflineRequest => {
  if (exact(v, ["action"])) return v.action === "import" || v.action === "status" || v.action === "cancel";
  if (exact(v, ["action", "jobHandle"]))
    return v.action === "begin-evidence" && typeof v.jobHandle === "string" && /^[A-Za-z0-9_-]{8,64}$/u.test(v.jobHandle);
  if (exact(v, ["action", "objectId"]) || exact(v, ["action", "objectId", "fileName"]))
    return (
      v.action === "export-object" &&
      typeof v.objectId === "string" && /^obj-\d{1,12}$/u.test(v.objectId) &&
      (v.fileName === undefined || short(v.fileName))
    );
  return false;
};

export const matchesPcapOfflineResult = (request: PcapOfflineRequest, result: unknown): result is PcapOfflineResult => {
  if (request.action === "import" || request.action === "begin-evidence")
    return exact(result, ["kind", "started"]) && result.kind === "started" && bool(result.started);
  if (request.action === "status")
    return exact(result, ["kind", "status"]) && result.kind === "status" && isPcapOfflineStatus(result.status);
  if (request.action === "cancel") return exact(result, ["kind"]) && result.kind === "cancelled";
  return exact(result, ["kind", "exported", "bytes"]) && result.kind === "exported" && bool(result.exported) && uint(result.bytes);
};

export const isPcapStarted = (v: unknown): v is { started: boolean } =>
  exact(v, ["started"]) && bool(v.started);
export const isPcapExported = (v: unknown): v is { exported: boolean; bytes?: number } =>
  (exact(v, ["exported"]) || exact(v, ["exported", "bytes"])) &&
  bool(v.exported) && (v.bytes === undefined || uint(v.bytes));
