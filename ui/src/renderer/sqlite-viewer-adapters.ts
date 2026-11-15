import type {
  SqliteDeletePlanResponse,
  SqliteDeleteReceipt,
  SqliteInspectResponse,
  SqliteRowsResponse,
  SqliteSource,
  SqliteViewerApi,
} from "../shared/sqlite-contract";
import type { SqliteHostApi } from "../shared/sqlite-contract";
import type { SftpBrowserApi } from "../shared/sftp-browser-contract";

/**
 * The file-browser lane: the terminal window's host commands resolve the
 * binding themselves, so the calls take only handles. Responses already
 * passed the bridge's contract check; the cast just narrows `unknown`.
 */
export function sftpSqliteViewer(api: SftpBrowserApi): SqliteViewerApi {
  return {
    sqliteInspect: (source) =>
      api.sqliteInspectSftp(sftpHandles(source).browserHandle, sftpHandles(source).entryHandle)
        .then((value) => value as SqliteInspectResponse),
    sqliteRows: (source, table, offset) =>
      api.sqliteRowsSftp(sftpHandles(source).browserHandle, sftpHandles(source).entryHandle, table, offset)
        .then((value) => value as SqliteRowsResponse),
    sqliteDeletePlan: (source, table, rowids) =>
      api.sqliteDeletePlanSftp(sftpHandles(source).browserHandle, sftpHandles(source).entryHandle, table, rowids)
        .then((value) => value as SqliteDeletePlanResponse),
    sqliteDeleteExecute: (planHandle) =>
      api.sqliteDeleteExecuteSftp(planHandle).then((value) => value as SqliteDeleteReceipt),
    sqliteDeleteUndo: (planHandle) =>
      api.sqliteDeleteUndoSftp(planHandle).then((value) => value as SqliteDeleteReceipt),
  };
}

/** The emergency path-offer lane on the main window: requests carry the binding. */
export function offerSqliteViewer(api: SqliteHostApi, bindingHandle: string): SqliteViewerApi {
  return {
    sqliteInspect: (source) => api.sqliteInspect({ bindingHandle, source }),
    sqliteRows: (source, table, offset) => api.sqliteRows({ bindingHandle, source, table, offset }),
    sqliteDeletePlan: (source, table, rowids) =>
      api.sqliteDeletePlan({ bindingHandle, source, table, rowids }),
    sqliteDeleteExecute: (planHandle) => api.sqliteDeleteExecute({ bindingHandle, planHandle }),
    sqliteDeleteUndo: (planHandle) => api.sqliteDeleteUndo({ bindingHandle, planHandle }),
  };
}

function sftpHandles(source: SqliteSource): { browserHandle: string; entryHandle: string } {
  if (source.kind !== "sftp") throw new Error("这个入口只支持文件浏览器里的文件。");
  return source;
}
