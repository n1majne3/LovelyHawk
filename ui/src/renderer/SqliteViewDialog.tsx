import { useCallback, useEffect, useRef, useState } from "react";

import { useModalScrim } from "./modal-scrim";
import {
  SQLITE_DELETE_MAX_ROWS,
  sqliteCellText,
  type SqliteCell,
  type SqliteDeletePlanResponse,
  type SqliteDeleteReceipt,
  type SqliteInspectResponse,
  type SqliteRowsResponse,
  type SqliteSource,
  type SqliteViewerApi,
} from "../shared/sqlite-contract";
import "./sqlite-view.css";

export interface SqliteViewDialogProps {
  /** The bound viewer calls; which window hosts them decides how the source resolves. */
  api: SqliteViewerApi;
  source: SqliteSource;
  /** A label for the header: the entry name or the offered path. */
  subject: string;
  copyText: (text: string) => void;
  onClose: () => void;
}

const PAGE_SIZE = 100;

type GridState = {
  table: string;
  offset: number;
  result: SqliteRowsResponse;
};

type MutationState =
  | { kind: "plan"; plan: SqliteDeletePlanResponse }
  | { kind: "receipt"; receipt: SqliteDeleteReceipt };

/**
 * "SQLite 只读查看". The page only ever names handles; every command is built
 * and run by the backend under the binding that owns the source. Cell text is
 * untrusted and rendered as plain text only.
 */
export function SqliteViewDialog({ api, source, subject, copyText, onClose }: SqliteViewDialogProps) {
  useModalScrim();
  const [inspect, setInspect] = useState<SqliteInspectResponse | null>(null);
  const [grid, setGrid] = useState<GridState | null>(null);
  const [schema, setSchema] = useState<string | null>(null);
  const [selected, setSelected] = useState<ReadonlySet<number>>(new Set());
  const [mutation, setMutation] = useState<MutationState | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  // Bumps when a newer call should win; a late answer is dropped rather than
  // overwriting a table the operator already moved on from.
  const generation = useRef(0);
  const alive = useRef(true);
  useEffect(() => {
    const current = alive;
    return () => {
      current.current = false;
    };
  }, []);

  useEffect(() => {
    const run = ++generation.current;
    setBusy(true);
    setError(null);
    void api
      .sqliteInspect(source)
      .then((value) => {
        if (!alive.current || run !== generation.current) return;
        setInspect(value);
      })
      .catch((failure: unknown) => {
        if (!alive.current || run !== generation.current) return;
        setError(failure instanceof Error ? failure.message : "打开数据库失败。");
      })
      .finally(() => {
        if (alive.current && run === generation.current) setBusy(false);
      });
  }, [api, source]);

  const openTable = useCallback((table: string, offset: number) => {
    const run = ++generation.current;
    setBusy(true);
    setError(null);
    setSelected(new Set());
    setSchema(null);
    void api
      .sqliteRows(source, table, offset)
      .then((value) => {
        if (!alive.current || run !== generation.current) return;
        setGrid({ table, offset, result: value });
      })
      .catch((failure: unknown) => {
        if (!alive.current || run !== generation.current) return;
        setGrid(null);
        setError(failure instanceof Error ? failure.message : "读取表数据失败。");
      })
      .finally(() => {
        if (alive.current && run === generation.current) setBusy(false);
      });
  }, [api, source]);

  function toggleRow(rowid: number, checked: boolean): void {
    setSelected((current) => {
      const next = new Set(current);
      if (checked) next.add(rowid);
      else next.delete(rowid);
      return next;
    });
  }

  async function planDelete(): Promise<void> {
    if (grid === null || selected.size === 0 || selected.size > SQLITE_DELETE_MAX_ROWS) return;
    setBusy(true);
    setError(null);
    try {
      const plan = await api.sqliteDeletePlan(source, grid.table, [...selected].sort((a, b) => a - b));
      if (!alive.current) return;
      setMutation({ kind: "plan", plan });
    } catch (failure) {
      if (alive.current) {
        setError(failure instanceof Error ? failure.message : "无法生成删除计划。");
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }

  async function executeDelete(plan: SqliteDeletePlanResponse): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      const receipt = await api.sqliteDeleteExecute(plan.planHandle);
      if (!alive.current) return;
      setMutation({ kind: "receipt", receipt });
      setSelected(new Set());
      if (receipt.state === "deleted") openTable(grid!.table, 0);
    } catch (failure) {
      if (alive.current) {
        setMutation(null);
        setError(failure instanceof Error ? failure.message : "删除执行失败。");
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }

  async function undoDelete(planHandle: string): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      const receipt = await api.sqliteDeleteUndo(planHandle);
      if (!alive.current) return;
      setMutation({ kind: "receipt", receipt });
      if (receipt.state === "restored" && grid !== null) openTable(grid.table, grid.offset);
    } catch (failure) {
      if (alive.current) {
        setMutation(null);
        setError(failure instanceof Error ? failure.message : "恢复失败。");
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }

  function copyRow(cells: SqliteCell[]): void {
    copyText(cells.map(sqliteCellText).join("\t"));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  }

  const canDelete =
    grid !== null && grid.result.engine === "python3" &&
    grid.result.columns.some((column) => column.rowid) && grid.result.immutable === false;
  const rowidIndex = grid?.result.columns.findIndex((column) => column.rowid) ?? -1;

  return (
    <div className="sqlite-view-backdrop" role="presentation">
      <section
        className="sqlite-view-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="SQLite 只读查看"
        data-testid="sqlite-view-dialog"
      >
        <header className="sqlite-view-header">
          <div>
            <h2>SQLite 只读查看</h2>
            <p className="sqlite-view-subject" title={inspect?.path ?? subject}>{subject}</p>
          </div>
          <button type="button" className="sqlite-view-close" onClick={onClose} aria-label="关闭">
            ×
          </button>
        </header>

        <p className="sqlite-view-note">
          查看会更新文件的访问时间；只读查看不等于取证镜像，需要保留证据请先下载留证。
        </p>
        {inspect?.immutable === true || grid?.result.immutable === true ? (
          <p className="sqlite-view-note is-warning" data-testid="sqlite-immutable-note">
            以不可变方式读取，可能看不到尚未合并到主文件的写入。
          </p>
        ) : null}

        {error !== null ? <p className="sqlite-view-error" role="alert">{error}</p> : null}
        {busy ? <p className="sqlite-view-busy">处理中…</p> : null}

        {inspect === null ? null : (
          <div className="sqlite-view-body">
            <aside className="sqlite-view-tables">
              <p className="sqlite-view-file">
                {inspect.file.size} 字节 · 属主 {inspect.file.owner === "" ? "未知" : inspect.file.owner} · 权限{" "}
                {inspect.file.mode === "" ? "未知" : inspect.file.mode}
                {inspect.file.wal ? " · 存在 WAL" : ""}
                {inspect.file.shm ? " · 存在 SHM" : ""}
              </p>
              <p className="sqlite-view-file">
                SQLite {inspect.sqliteVersion === "" ? "版本未知" : inspect.sqliteVersion} · 读取方式{" "}
                {inspect.engine}
              </p>
              <ul className="sqlite-view-table-list">
                {inspect.tables.map((table) => (
                  <li key={`${table.kind}:${table.name}`}>
                    <div className="sqlite-view-table-row">
                      <button
                        type="button"
                        className={grid?.table === table.name ? "is-active" : ""}
                        onClick={() => openTable(table.name, 0)}
                      >
                        {table.kind === "view" ? "视图 " : ""}
                        {table.name}
                        {table.rows === null ? "" : `（${table.rows} 行）`}
                      </button>
                      <button
                        type="button"
                        className="sqlite-view-schema-button"
                        title="查看建表语句"
                        onClick={() => setSchema(schema === table.sql ? null : table.sql)}
                      >
                        结构
                      </button>
                    </div>
                  </li>
                ))}
                {inspect.tables.length === 0 ? <li className="sqlite-view-empty">没有表或视图。</li> : null}
              </ul>
              {inspect.tablesTruncated ? (
                <p className="sqlite-view-note">对象较多，只列出了前面一部分。</p>
              ) : null}
              {inspect.notes.map((note, index) => (
                <p className="sqlite-view-note" key={index}>{note}</p>
              ))}
            </aside>

            <div className="sqlite-view-content">
              {schema !== null ? (
                <pre className="sqlite-view-schema" data-testid="sqlite-schema">{schema}</pre>
              ) : null}
              {grid === null ? (
                <p className="sqlite-view-empty">选择左侧的表查看前 {PAGE_SIZE} 行。</p>
              ) : (
                <>
                  <div className="sqlite-view-grid-toolbar">
                    <span>
                      {grid.table} · 第 {grid.offset + 1}–{grid.offset + grid.result.rows.length} 行
                      {grid.result.truncated ? "（输出已达上限，只显示前面部分）" : ""}
                    </span>
                    <span className="sqlite-view-grid-actions">
                      <button
                        type="button"
                        disabled={busy || grid.offset === 0}
                        onClick={() => openTable(grid.table, Math.max(0, grid.offset - PAGE_SIZE))}
                      >
                        上一页
                      </button>
                      <button
                        type="button"
                        disabled={busy || grid.result.rows.length < PAGE_SIZE}
                        onClick={() => openTable(grid.table, grid.offset + PAGE_SIZE)}
                      >
                        下一页
                      </button>
                      {canDelete ? (
                        <button
                          type="button"
                          className="is-dangerous"
                          disabled={busy || selected.size === 0}
                          onClick={() => void planDelete()}
                        >
                          删除所选行（{selected.size}）…
                        </button>
                      ) : null}
                    </span>
                  </div>
                  {grid !== null && grid.result.engine !== "python3" ? (
                    <p className="sqlite-view-note">删除行需要目标上有 python3；当前只读查看不受影响。</p>
                  ) : null}
                  {grid !== null && grid.result.immutable ? (
                    <p className="sqlite-view-note">不可变读取下不提供删除行。</p>
                  ) : null}
                  {grid !== null && grid.result.engine === "python3" && rowidIndex < 0 ? (
                    <p className="sqlite-view-note">这个表没有可用的 rowid，不支持按行删除。</p>
                  ) : null}
                  <div className="sqlite-view-grid-scroll">
                    <table className="sqlite-view-grid">
                      <thead>
                        <tr>
                          {canDelete && rowidIndex >= 0 ? <th className="sqlite-view-check" /> : null}
                          {grid.result.columns.map((column, index) => (
                            <th key={index} title={column.declaredType}>
                              {column.name}
                              {column.declaredType === "" ? "" : ` :${column.declaredType}`}
                            </th>
                          ))}
                          <th className="sqlite-view-rowcopy">复制</th>
                        </tr>
                      </thead>
                      <tbody>
                        {grid.result.rows.map((row, rowIndex) => {
                          const rowid = rowidIndex >= 0 ? row[rowidIndex] : undefined;
                          const rowidValue =
                            rowid !== undefined && rowid.kind === "integer"
                              ? Number.parseInt(rowid.text, 10)
                              : null;
                          return (
                            <tr key={rowIndex}>
                              {canDelete && rowidIndex >= 0 ? (
                                <td className="sqlite-view-check">
                                  {rowidValue === null ? null : (
                                    <input
                                      type="checkbox"
                                      aria-label={`选择行 ${rowidValue}`}
                                      checked={selected.has(rowidValue)}
                                      onChange={(event) => toggleRow(rowidValue, event.target.checked)}
                                    />
                                  )}
                                </td>
                              ) : null}
                              {row.map((cell, cellIndex) => (
                                <td
                                  key={cellIndex}
                                  className={cell.kind === "blob" ? "is-blob" : ""}
                                  title={sqliteCellText(cell)}
                                >
                                  {sqliteCellText(cell)}
                                </td>
                              ))}
                              <td className="sqlite-view-rowcopy">
                                <button type="button" onClick={() => copyRow(row)}>复制行</button>
                              </td>
                            </tr>
                          );
                        })}
                        {grid.result.rows.length === 0 ? (
                          <tr>
                            <td className="sqlite-view-empty" colSpan={grid.result.columns.length + 2}>
                              这一页没有行。
                            </td>
                          </tr>
                        ) : null}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        {copied ? <p className="sqlite-view-note">已复制。</p> : null}

        {mutation?.kind === "plan" ? (
          <div className="sqlite-view-mutation" data-testid="sqlite-delete-plan">
            <h3>删除行计划</h3>
            <p>{mutation.plan.summary}</p>
            {mutation.plan.missingRowids.length > 0 ? (
              <p className="sqlite-view-note is-warning">
                有 {mutation.plan.missingRowids.length} 行在选择后已经不存在，不在本次删除内。
              </p>
            ) : null}
            <ul className="sqlite-view-plan-rows">
              {mutation.plan.rows.map((row) => (
                <li key={row.rowid}>
                  rowid {row.rowid}：{row.display.map(sqliteCellText).join(" | ")}
                </li>
              ))}
            </ul>
            <div className="sqlite-view-mutation-actions">
              <button
                type="button"
                className="is-dangerous"
                disabled={busy}
                onClick={() => void executeDelete(mutation.kind === "plan" ? mutation.plan : (undefined as never))}
              >
                确认删除
              </button>
              <button type="button" disabled={busy} onClick={() => setMutation(null)}>
                取消
              </button>
            </div>
          </div>
        ) : null}

        {mutation?.kind === "receipt" ? (
          <div className="sqlite-view-mutation" data-testid="sqlite-delete-receipt">
            <h3>{mutation.receipt.state === "refused" ? "操作被拒绝" : mutation.receipt.state === "restored" ? "已恢复" : "已删除"}</h3>
            <p>{mutation.receipt.detail}</p>
            {mutation.receipt.backupPath !== null ? (
              <p className="sqlite-view-note">备份：{mutation.receipt.backupPath}</p>
            ) : null}
            <div className="sqlite-view-mutation-actions">
              {mutation.receipt.undoable ? (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void undoDelete(mutation.kind === "receipt" ? mutation.receipt.planHandle : "")}
                >
                  撤销删除（10 分钟内）
                </button>
              ) : null}
              <button type="button" disabled={busy} onClick={() => setMutation(null)}>
                关闭
              </button>
            </div>
          </div>
        ) : null}
      </section>
    </div>
  );
}
