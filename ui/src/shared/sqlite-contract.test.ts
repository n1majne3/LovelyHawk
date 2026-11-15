import { describe, expect, it } from "vitest";

import {
  SQLITE_DELETE_MAX_ROWS,
  isSqliteDeletePlanRequest,
  isSqliteDeletePlanResponse,
  isSqliteDeleteReceipt,
  isSqliteDeleteRefRequest,
  isSqliteInspectRequest,
  isSqliteInspectResponse,
  isSqliteRowsRequest,
  isSqliteRowsResponse,
  isSqliteSource,
  sqliteCellText,
  type SqliteInspectResponse,
  type SqliteRowsResponse,
} from "./sqlite-contract";

function inspect(): SqliteInspectResponse {
  return {
    engine: "python3",
    sqliteVersion: "3.40.1",
    immutable: false,
    path: "/var/lib/app/cam.db",
    file: { size: 8192, mtimeEpoch: 1_700_000_000, owner: "root", mode: "0644", wal: true, shm: false },
    tables: [
      { name: "sessions", kind: "table", sql: "CREATE TABLE sessions(...)", rows: 12 },
      { name: "audit_v", kind: "view", sql: "CREATE VIEW audit_v AS ...", rows: null },
    ],
    tablesTruncated: false,
    notes: ["行数统计有上限"],
  };
}

function rows(): SqliteRowsResponse {
  return {
    engine: "python3",
    sqliteVersion: "3.40.1",
    immutable: false,
    columns: [
      { name: "rowid", declaredType: "", rowid: true },
      { name: "username", declaredType: "TEXT", rowid: false },
    ],
    rows: [
      [{ kind: "integer", text: "7" }, { kind: "text", text: "admin" }],
      [{ kind: "integer", text: "8" }, { kind: "null" }],
    ],
    truncated: false,
    notes: [],
  };
}

describe("sqlite source and request validation", () => {
  it("accepts the two bound source kinds only", () => {
    expect(isSqliteSource({ kind: "sftp", browserHandle: "w", entryHandle: "e" })).toBe(true);
    expect(isSqliteSource({ kind: "offer", pathHandle: "p" })).toBe(true);
    // A page-sent path never becomes a source.
    expect(isSqliteSource({ kind: "path", path: "/etc/cam.db" })).toBe(false);
    expect(isSqliteSource({ kind: "sftp", browserHandle: "w", entryHandle: "e", path: "/x" })).toBe(false);
    expect(isSqliteSource({ kind: "offer" })).toBe(false);
    expect(isSqliteSource({ kind: "sftp", browserHandle: "w\n", entryHandle: "e" })).toBe(false);
  });

  it("accepts exact request shapes", () => {
    const source = { kind: "offer", pathHandle: "p" };
    expect(isSqliteInspectRequest({ bindingHandle: "b", source })).toBe(true);
    expect(isSqliteRowsRequest({ bindingHandle: "b", source, table: "sessions", offset: 100 })).toBe(true);
    expect(isSqliteDeletePlanRequest({ bindingHandle: "b", source, table: "sessions", rowids: [1, 2] })).toBe(true);
    expect(isSqliteDeleteRefRequest({ bindingHandle: "b", planHandle: "p" })).toBe(true);
  });

  it("rejects unbound fields and out-of-range selections", () => {
    const source = { kind: "offer", pathHandle: "p" };
    expect(isSqliteRowsRequest({ bindingHandle: "b", source, table: "t", offset: -1 })).toBe(false);
    expect(isSqliteRowsRequest({ bindingHandle: "b", source, table: "t", offset: 0, path: "/x" })).toBe(false);
    expect(isSqliteDeletePlanRequest({ bindingHandle: "b", source, table: "t", rowids: [] })).toBe(false);
    expect(isSqliteDeletePlanRequest({
      bindingHandle: "b", source, table: "t",
      rowids: Array.from({ length: SQLITE_DELETE_MAX_ROWS + 1 }, (_, i) => i + 1),
    })).toBe(false);
    expect(isSqliteDeletePlanRequest({ bindingHandle: "b", source, table: "t", rowids: [-3] })).toBe(false);
    expect(isSqliteDeletePlanRequest({ bindingHandle: "b", source, table: "t", rowids: [1.5] })).toBe(false);
    expect(isSqliteDeleteRefRequest({ bindingHandle: "b" })).toBe(false);
  });
});

describe("sqlite response validation", () => {
  it("accepts well-formed inspect and rows answers", () => {
    expect(isSqliteInspectResponse(inspect())).toBe(true);
    expect(isSqliteRowsResponse(rows())).toBe(true);
  });

  it("rejects tables over the cap, non-integer counts, and invented keys", () => {
    const crowded = inspect();
    crowded.tables = Array.from({ length: 501 }, (_, i) => ({
      name: `t${i}`, kind: "table", sql: "", rows: null,
    }));
    expect(isSqliteInspectResponse(crowded)).toBe(false);
    const wrongCount = inspect();
    wrongCount.tables[0]!.rows = 1.5;
    expect(isSqliteInspectResponse(wrongCount)).toBe(false);
    const extra = { ...inspect(), raw: "x" };
    expect(isSqliteInspectResponse(extra)).toBe(false);
    const manyRows = rows();
    manyRows.rows = Array.from({ length: 101 }, () => []);
    expect(isSqliteRowsResponse(manyRows)).toBe(false);
    const unknownCell = rows();
    unknownCell.rows = [[{ kind: "future", text: "x" } as never]];
    expect(isSqliteRowsResponse(unknownCell)).toBe(false);
  });

  it("accepts every delete receipt state and refuses anything else", () => {
    for (const state of ["deleted", "restored", "refused"] as const) {
      expect(isSqliteDeleteReceipt({
        planHandle: "p", state, detail: "说明", deleted: 0, backupPath: null, undoable: false,
      })).toBe(true);
    }
    expect(isSqliteDeleteReceipt({
      planHandle: "p", state: "planned", detail: "x", deleted: 0, backupPath: null, undoable: false,
    })).toBe(false);
    expect(isSqliteDeletePlanResponse({
      planHandle: "p", path: "/x.db", table: "t",
      rows: [{ rowid: 1, display: [{ kind: "integer", text: "1" }] }],
      missingRowids: [2], summary: "计划", dangerous: true, expiresInSeconds: 600,
    })).toBe(true);
    expect(isSqliteDeletePlanResponse({
      planHandle: "p", path: "/x.db", table: "t", rows: [], missingRowids: [],
      summary: "计划", dangerous: true, expiresInSeconds: 600, statement: "DELETE",
    })).toBe(false);
  });
});

describe("cell display text", () => {
  it("renders every cell kind as plain text", () => {
    expect(sqliteCellText({ kind: "null" })).toBe("NULL");
    expect(sqliteCellText({ kind: "integer", text: "42" })).toBe("42");
    expect(sqliteCellText({ kind: "text", text: "a" })).toBe("a");
    expect(sqliteCellText({ kind: "truncated", text: "abc" })).toBe("abc…");
    expect(sqliteCellText({ kind: "blob", bytes: 40, hexPrefix: "aabb" })).toBe("<BLOB 40 字节> aabb");
  });
});
