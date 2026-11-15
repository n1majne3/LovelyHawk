/**
 * SQLite read-only viewing and bounded row deletion.
 *
 * The page never names a path. From the file browser it hands over the entry
 * handle an open browser offered; from an emergency path menu it hands over
 * the offer's path handle. The host fills in which target the calling window
 * belongs to; the backend resolves the handles back to a path under the
 * current binding only.
 *
 * All cell text is untrusted: render it as plain text, never as markup.
 */

const encoder = new TextEncoder();

export type SqliteSource =
  | { kind: "sftp"; browserHandle: string; entryHandle: string }
  | { kind: "offer"; pathHandle: string };

export interface SqliteInspectRequest {
  bindingHandle: string;
  source: SqliteSource;
}

export interface SqliteRowsRequest {
  bindingHandle: string;
  source: SqliteSource;
  table: string;
  offset: number;
}

export interface SqliteDeletePlanRequest {
  bindingHandle: string;
  source: SqliteSource;
  table: string;
  rowids: number[];
}

export interface SqliteDeleteRefRequest {
  bindingHandle: string;
  planHandle: string;
}

export type SqliteCell =
  | { kind: "null" }
  | { kind: "integer" | "real" | "text" | "truncated"; text: string }
  | { kind: "blob"; bytes: number; hexPrefix: string };

export interface SqliteFileInfo {
  size: number;
  mtimeEpoch: number;
  owner: string;
  mode: string;
  wal: boolean;
  shm: boolean;
}

export interface SqliteTableRow {
  name: string;
  kind: string;
  sql: string;
  /** Null means the count was skipped, not that the table is empty. */
  rows: number | null;
}

export interface SqliteInspectResponse {
  engine: string;
  sqliteVersion: string;
  immutable: boolean;
  path: string;
  file: SqliteFileInfo;
  tables: SqliteTableRow[];
  tablesTruncated: boolean;
  notes: string[];
}

export interface SqliteColumn {
  name: string;
  declaredType: string;
  rowid: boolean;
}

export interface SqliteRowsResponse {
  engine: string;
  sqliteVersion: string;
  immutable: boolean;
  columns: SqliteColumn[];
  rows: SqliteCell[][];
  truncated: boolean;
  notes: string[];
}

export interface SqliteDeletePlanRow {
  rowid: number;
  display: SqliteCell[];
}

export interface SqliteDeletePlanResponse {
  planHandle: string;
  path: string;
  table: string;
  rows: SqliteDeletePlanRow[];
  missingRowids: number[];
  summary: string;
  dangerous: boolean;
  expiresInSeconds: number;
}

export interface SqliteDeleteReceipt {
  planHandle: string;
  state: "deleted" | "restored" | "refused";
  detail: string;
  deleted: number;
  backupPath: string | null;
  undoable: boolean;
}

export const SQLITE_DELETE_MAX_ROWS = 50;

/** The main-window surface: full requests, binding included. */
export interface SqliteHostApi {
  sqliteInspect(request: SqliteInspectRequest): Promise<SqliteInspectResponse>;
  sqliteRows(request: SqliteRowsRequest): Promise<SqliteRowsResponse>;
  sqliteDeletePlan(request: SqliteDeletePlanRequest): Promise<SqliteDeletePlanResponse>;
  sqliteDeleteExecute(request: SqliteDeleteRefRequest): Promise<SqliteDeleteReceipt>;
  sqliteDeleteUndo(request: SqliteDeleteRefRequest): Promise<SqliteDeleteReceipt>;
}

/** The five calls the viewer page makes, whichever window hosts it. */
export interface SqliteViewerApi {
  sqliteInspect(source: SqliteSource): Promise<SqliteInspectResponse>;
  sqliteRows(source: SqliteSource, table: string, offset: number): Promise<SqliteRowsResponse>;
  sqliteDeletePlan(source: SqliteSource, table: string, rowids: number[]): Promise<SqliteDeletePlanResponse>;
  sqliteDeleteExecute(planHandle: string): Promise<SqliteDeleteReceipt>;
  sqliteDeleteUndo(planHandle: string): Promise<SqliteDeleteReceipt>;
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function keys(value: Record<string, unknown>, expected: string[]): boolean {
  return Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function text(value: unknown, maximum: number, empty = false): value is string {
  return typeof value === "string" && (empty || value.trim().length > 0) &&
    encoder.encode(value).length <= maximum &&
    !/[\uD800-\uDFFF]/u.test(value) && ![...value].some((char) => char.charCodeAt(0) < 0x20);
}

function handle(value: unknown): value is string {
  return text(value, 256);
}

function integer(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

export function isSqliteSource(value: unknown): value is SqliteSource {
  if (!record(value)) return false;
  if (value.kind === "sftp") {
    return keys(value, ["kind", "browserHandle", "entryHandle"]) &&
      handle(value.browserHandle) && handle(value.entryHandle);
  }
  if (value.kind === "offer") {
    return keys(value, ["kind", "pathHandle"]) && handle(value.pathHandle);
  }
  return false;
}

export function isSqliteInspectRequest(value: unknown): value is SqliteInspectRequest {
  return record(value) && keys(value, ["bindingHandle", "source"]) &&
    handle(value.bindingHandle) && isSqliteSource(value.source);
}

export function isSqliteRowsRequest(value: unknown): value is SqliteRowsRequest {
  return record(value) && keys(value, ["bindingHandle", "source", "table", "offset"]) &&
    handle(value.bindingHandle) && isSqliteSource(value.source) &&
    text(value.table, 512) && integer(value.offset, 0, 1_000_000);
}

export function isSqliteDeletePlanRequest(value: unknown): value is SqliteDeletePlanRequest {
  return record(value) && keys(value, ["bindingHandle", "source", "table", "rowids"]) &&
    handle(value.bindingHandle) && isSqliteSource(value.source) &&
    text(value.table, 512) && Array.isArray(value.rowids) &&
    value.rowids.length >= 1 && value.rowids.length <= SQLITE_DELETE_MAX_ROWS &&
    value.rowids.every((rowid) => integer(rowid, 0, Number.MAX_SAFE_INTEGER));
}

export function isSqliteDeleteRefRequest(value: unknown): value is SqliteDeleteRefRequest {
  return record(value) && keys(value, ["bindingHandle", "planHandle"]) &&
    handle(value.bindingHandle) && handle(value.planHandle);
}

function isCell(value: unknown): value is SqliteCell {
  if (!record(value) || typeof value.kind !== "string") return false;
  switch (value.kind) {
    case "null":
      return keys(value, ["kind"]);
    case "integer":
    case "real":
    case "text":
    case "truncated":
      return keys(value, ["kind", "text"]) && text(value.text, 1200, true);
    case "blob":
      return keys(value, ["kind", "bytes", "hexPrefix"]) &&
        integer(value.bytes, 0, Number.MAX_SAFE_INTEGER) &&
        text(value.hexPrefix, 128, true);
    default:
      return false;
  }
}

export function isSqliteInspectResponse(value: unknown): value is SqliteInspectResponse {
  return record(value) &&
    keys(value, ["engine", "sqliteVersion", "immutable", "path", "file", "tables", "tablesTruncated", "notes"]) &&
    text(value.engine, 32) && text(value.sqliteVersion, 64, true) &&
    typeof value.immutable === "boolean" && text(value.path, 2048) &&
    record(value.file) &&
    keys(value.file, ["size", "mtimeEpoch", "owner", "mode", "wal", "shm"]) &&
    integer(value.file.size, 0, Number.MAX_SAFE_INTEGER) &&
    integer(value.file.mtimeEpoch, 0, Number.MAX_SAFE_INTEGER) &&
    text(value.file.owner, 128, true) && text(value.file.mode, 32, true) &&
    typeof value.file.wal === "boolean" && typeof value.file.shm === "boolean" &&
    Array.isArray(value.tables) && value.tables.length <= 500 &&
    value.tables.every((table) => record(table) &&
      keys(table, ["name", "kind", "sql", "rows"]) &&
      text(table.name, 512) && text(table.kind, 16) && text(table.sql, 8192, true) &&
      (table.rows === null || integer(table.rows, 0, Number.MAX_SAFE_INTEGER))) &&
    typeof value.tablesTruncated === "boolean" &&
    Array.isArray(value.notes) && value.notes.every((note) => text(note, 512));
}

export function isSqliteRowsResponse(value: unknown): value is SqliteRowsResponse {
  return record(value) &&
    keys(value, ["engine", "sqliteVersion", "immutable", "columns", "rows", "truncated", "notes"]) &&
    text(value.engine, 32) && text(value.sqliteVersion, 64, true) &&
    typeof value.immutable === "boolean" &&
    Array.isArray(value.columns) && value.columns.length <= 200 &&
    value.columns.every((column) => record(column) &&
      keys(column, ["name", "declaredType", "rowid"]) &&
      text(column.name, 512) && text(column.declaredType, 128, true) &&
      typeof column.rowid === "boolean") &&
    Array.isArray(value.rows) && value.rows.length <= 100 &&
    value.rows.every((row) => Array.isArray(row) && row.length <= 200 && row.every(isCell)) &&
    typeof value.truncated === "boolean" &&
    Array.isArray(value.notes) && value.notes.every((note) => text(note, 512));
}

export function isSqliteDeletePlanResponse(value: unknown): value is SqliteDeletePlanResponse {
  return record(value) &&
    keys(value, ["planHandle", "path", "table", "rows", "missingRowids", "summary", "dangerous", "expiresInSeconds"]) &&
    handle(value.planHandle) && text(value.path, 2048) && text(value.table, 512) &&
    Array.isArray(value.rows) && value.rows.length <= SQLITE_DELETE_MAX_ROWS &&
    value.rows.every((row) => record(row) &&
      keys(row, ["rowid", "display"]) &&
      integer(row.rowid, 0, Number.MAX_SAFE_INTEGER) &&
      Array.isArray(row.display) && row.display.length <= 200 && row.display.every(isCell)) &&
    Array.isArray(value.missingRowids) &&
    value.missingRowids.every((rowid) => integer(rowid, 0, Number.MAX_SAFE_INTEGER)) &&
    text(value.summary, 2048) && typeof value.dangerous === "boolean" &&
    integer(value.expiresInSeconds, 0, 3600);
}

export function isSqliteDeleteReceipt(value: unknown): value is SqliteDeleteReceipt {
  return record(value) &&
    keys(value, ["planHandle", "state", "detail", "deleted", "backupPath", "undoable"]) &&
    handle(value.planHandle) &&
    (value.state === "deleted" || value.state === "restored" || value.state === "refused") &&
    text(value.detail, 1024) && integer(value.deleted, 0, SQLITE_DELETE_MAX_ROWS) &&
    (value.backupPath === null || text(value.backupPath, 2048)) &&
    typeof value.undoable === "boolean";
}

/** The display text for a cell, for copy cell/row and the grid. */
export function sqliteCellText(cell: SqliteCell): string {
  switch (cell.kind) {
    case "null":
      return "NULL";
    case "blob":
      return `<BLOB ${cell.bytes} 字节> ${cell.hexPrefix}`;
    case "truncated":
      return `${cell.text}…`;
    default:
      return cell.text;
  }
}
