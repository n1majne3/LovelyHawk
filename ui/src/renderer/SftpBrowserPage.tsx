import { TransientNotice } from "./NotificationCenter";
import { DialogHost } from "./DialogHost";
import { useConfirmDialog } from "./use-confirm-dialog";
import { useEffect, useReducer, useRef, useState, type MouseEvent } from "react";

import { errorText } from "./error-text";
import { targetFailureMessage } from "./target-lost";
import { useListExpiry } from "./use-list-expiry";

import {
  isSftpDirectorySnapshot,
  isSftpOperationPlan,
  isSftpOperationReceipt,
  isSftpOperationUndoResult,
  isSftpStagedUpload,
  isSftpTextPreview,
  isSftpDirectoryDownloadResult,
  isSftpDirectoryUploadPrepare,
  isSftpDirectoryUploadResult,
  isSftpTransferResult,
  isSftpTransferCancelResult,
  isSftpQueueEnqueueResult,
  isSftpTransferQueue,
  type SftpTransferQueue,
  type SftpOperationInput,
  type SftpOperationPlan,
  type SftpOperationReceipt,
  type SftpOperationUndoResult,
  sftpBrowserEntryKinds,
  type SftpBrowserApi,
  type SftpBrowserEntry,
  type SftpDirectorySnapshot,
  type SftpTextPreview,
} from "../shared/sftp-browser-contract";
import type { LocalBrowserApi } from "../shared/local-browser-contract";
import type { LocalScanChildApi } from "../shared/local-scan-contract";
import { LocalScanDialog } from "./LocalScanDialog";
import { browserScanTransport } from "./local-scan-controller";
import { LocalFilePane } from "./LocalFilePane";
import { SftpContextMenu, type SftpMenuAction } from "./SftpContextMenu";
import { SftpOperationDialog, type SftpOperationDraft } from "./SftpOperationDialog";
import { SftpPropertiesDialog } from "./SftpPropertiesDialog";
import {
  ArchiveIcon,
  DownloadIcon,
  EntryKindIcon,
  HomeIcon,
  NewFolderIcon,
  RefreshIcon,
  TerminalHereIcon,
  TrashIcon,
  UpIcon,
  UploadIcon,
} from "./file-icons";
import {
  compactSftpBytes,
  displaySftpBytes,
  displaySftpModifiedAt,
  filterSftpBrowserEntries,
  sftpBrowserActionLabel,
  sftpBrowserKindLabel,
  sftpBrowserScope,
  type SftpBrowserKindFilter,
} from "./sftp-browser-helpers";
import {
  createSftpBrowserState,
  sftpBrowserReducer,
  sftpReturnStep,
  sftpTrailPath,
  type SftpBrowserLoadStatus,
  type SftpDirectoryRequest,
  type SftpPreviewRequest,
} from "./sftp-browser-state";
import "./sftp-browser.css";

/** The way back to a folder after reopening the browser. */
interface SftpReturn {
  scope: string;
  /** The folder names from the start directory down to where the operator was. */
  target: string[];
  /** The names still to enter. */
  remaining: string[];
  /** The browser that expired; its listing may still be on screen for a moment. */
  expiredBrowser: string;
  /** The folder whose listing the walk waits for; null for the reopened start directory. */
  awaiting: string | null;
}

export interface SftpBrowserConnection {
  scopeKey: string;
}

export interface SftpBrowserPageProps {
  connection: SftpBrowserConnection | null;
  api: SftpBrowserApi & LocalBrowserApi & Partial<LocalScanChildApi>;
  active?: boolean;
}

interface PendingDirectory {
  scope: string;
  request: SftpDirectoryRequest;
}

interface PendingPreview {
  scope: string;
  request: SftpPreviewRequest;
}

export function SftpBrowserPage({
  connection,
  api,
  active = true,
}: SftpBrowserPageProps) {
  const [state, dispatch] = useReducer(sftpBrowserReducer, undefined, createSftpBrowserState);
  const [reopenVersion, setReopenVersion] = useState(0);
  const [pendingDirectory, setPendingDirectory] = useState<PendingDirectory | null>(null);
  const [pendingPreview, setPendingPreview] = useState<PendingPreview | null>(null);
  const [transferNotice, setTransferNotice] = useState<string | null>(null);
  // The download running now, shown with a way to stop it.
  const [downloading, setDownloading] = useState<{ browserHandle: string; name: string; stage: string; cancelling: boolean } | null>(null);
  // Files checked for the batch transfer queue; cleared on navigation and
  // whenever the browser (target) changes.
  const [checkedHandles, setCheckedHandles] = useState<ReadonlySet<string>>(new Set());
  // The batch queue this window's transfers run in; null before the first
  // enqueue and after the target changed.
  const [queue, setQueue] = useState<SftpTransferQueue | null>(null);
  const [queueCancelling, setQueueCancelling] = useState(false);
  // Optional download rate limit in KiB/s; blank means unlimited.
  const [rateLimitInput, setRateLimitInput] = useState("");
  // The open 取回本机扫描 dialog: the browser entry it fetches, never a path this page typed.
  const [localScan, setLocalScan] = useState<{
    browserHandle: string;
    entryHandle: string;
    path: string;
    entryKind: "file" | "directory";
    returnFocus: HTMLElement | null;
  } | null>(null);
  const [cancellingUpload, setCancellingUpload] = useState(false);
  // The preview the operator must confirm before a directory upload writes.
  const directoryUploadConfirm = useConfirmDialog();
  // The plan handle of a finished directory upload while it is still undoable.
  const [directoryUndo, setDirectoryUndo] = useState<{ planHandle: string; name: string } | null>(null);
  const transferInFlight = useRef(false);
  // Opening a window is remote work too: a double click would ask twice.
  const fileWindowInFlight = useRef(false);
  const [menu, setMenu] = useState<
    { position: { x: number; y: number }; entry: SftpBrowserEntry | null } | null
  >(null);
  const [draft, setDraft] = useState<SftpOperationDraft | null>(null);
  const [plan, setPlan] = useState<SftpOperationPlan | null>(null);
  const [receipt, setReceipt] = useState<SftpOperationReceipt | null>(null);
  const [undoResult, setUndoResult] = useState<SftpOperationUndoResult | null>(null);
  const [undoSpent, setUndoSpent] = useState(false);
  const [operationError, setOperationError] = useState<string | null>(null);
  // Opening an editor or a terminal window happens outside any dialog, so its
  // failure needs a place of its own in the pane.
  const [windowError, setWindowError] = useState<string | null>(null);
  const [operationBusy, setOperationBusy] = useState(false);
  const [properties, setProperties] = useState<SftpBrowserEntry | null>(null);
  const operationInFlight = useRef(false);
  const requestRef = useRef(0);
  // The backend said this browser is gone (expired or closed): listing again
  // cannot help, only opening a new one can.
  const [browserGone, setBrowserGone] = useState(false);
  // Reopening walks back down to the folder that was on screen, one listing
  // of the new browser at a time.
  const [returning, setReturning] = useState<SftpReturn | null>(null);
  const [returnNotice, setReturnNotice] = useState<string | null>(null);
  const scope = connection === null ? null : sftpBrowserScope(connection);
  const enabled = active && connection !== null;
  const visibleState = state.scope === scope ? state : createSftpBrowserState(scope);
  // Every listing renews the browser on the backend, and each listing is a new
  // snapshot, so the deadline is counted from the one on screen.
  const listExpiry = useListExpiry(visibleState.directory, visibleState.directory?.expiresInSeconds ?? null);

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
  }, [scope]);

  useEffect(() => {
    if (enabled) return;
    setPendingDirectory(null);
    setPendingPreview(null);
    dispatch({ type: "deactivated", scope });
  }, [enabled, scope]);

  // A new listing means new entry handles: checks from the old listing can
  // never name the same file again.
  const currentDirectoryHandle = visibleState.directory?.directoryHandle ?? null;
  useEffect(() => {
    setCheckedHandles(new Set());
  }, [currentDirectoryHandle]);

  // A new browser — target switch or reopen — means the old queue's binding
  // is gone; the backend already dropped it, drop the local copy too.
  const currentBrowserHandle = visibleState.directory?.browserHandle ?? null;
  useEffect(() => {
    setQueue(null);
    setCheckedHandles(new Set());
  }, [currentBrowserHandle]);

  // While the queue has work, poll it; a finished queue keeps its last state
  // on screen until the operator closes the panel.
  useEffect(() => {
    if (queue === null || !queue.active || currentBrowserHandle === null) return;
    let stopped = false;
    const poll = async () => {
      try {
        const value = await api.pollSftpQueue(currentBrowserHandle);
        if (stopped) return;
        if (value === null) {
          setQueue(null);
        } else if (isSftpTransferQueue(value)) {
          setQueue(value);
        }
      } catch {
        // A poll hiccup keeps the last snapshot; the next tick retries.
      }
    };
    let timer = 0;
    const tick = async () => {
      await poll();
      if (!stopped) timer = window.setTimeout(() => void tick(), 800);
    };
    timer = window.setTimeout(() => void tick(), 400);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [api, queue?.active, queue === null, currentBrowserHandle]);

  // A running queue holds the window open in the close handshake: closing
  // cancels every item first, then lets the window go.
  const queueRef = useRef<{ active: boolean; browserHandle: string | null } | null>(null);
  queueRef.current = { active: queue?.active === true, browserHandle: currentBrowserHandle };
  useEffect(() => {
    void api.setUnsavedChanges(queue?.active === true).catch(() => undefined);
  }, [api, queue?.active]);
  useEffect(() => {
    return api.onBeforeClose(async () => {
      const current = queueRef.current;
      if (current !== null && current.active && current.browserHandle !== null) {
        try {
          await api.cancelSftpQueue(current.browserHandle);
        } catch {
          // The window is going away anyway; the backend drops the queue
          // with the browser regardless of what the cancel answered.
        }
      }
      return true;
    });
  }, [api]);

  useEffect(() => {
    if (!enabled || scope === null || state.scope !== scope) return;
    const request: SftpDirectoryRequest = {
      id: ++requestRef.current,
      mode: "open",
      browserHandle: null,
      directoryHandle: null,
    };
    let cancelled = false;
    dispatch({ type: "directory-started", scope, request });
    void api.openSftpBrowser().then((value) => {
      if (cancelled) return;
      if (!isSftpDirectorySnapshot(value) || value.parentDirectoryHandle !== null) throw new Error();
      setBrowserGone(false);
      dispatch({ type: "directory-loaded", scope, request, directory: value });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "directory-failed",
        scope,
        request,
        error: sftpOpenFailureMessage(reason),
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, enabled, reopenVersion, scope, state.scope]);

  useEffect(() => {
    if (!enabled || scope === null || pendingDirectory?.scope !== scope ||
      pendingDirectory.request.mode !== "list") return;
    const request = pendingDirectory.request;
    let cancelled = false;
    dispatch({ type: "directory-started", scope, request });
    void api.listSftpDirectory(
      request.browserHandle!,
      request.directoryHandle!,
    ).then((value) => {
      if (cancelled) return;
      if (!isSftpDirectorySnapshot(value) || value.browserHandle !== request.browserHandle ||
        value.directoryHandle !== request.directoryHandle) throw new Error();
      dispatch({ type: "directory-loaded", scope, request, directory: value });
    }).catch((reason: unknown) => {
      if (cancelled) return;
      const gone = sftpBrowserGone(reason);
      if (gone) setBrowserGone(true);
      dispatch({
        type: "directory-failed",
        scope,
        request,
        error: gone
          ? "目录列表已过期（超过 5 分钟没有读取目录），点“重新打开”重新读取并回到这个文件夹。"
          : targetFailureMessage(reason, "目录读取失败；目录入口可能已过期、目标已切换、权限不足或条目已变化。"),
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, enabled, pendingDirectory, scope]);

  useEffect(() => {
    if (!enabled || scope === null || pendingPreview?.scope !== scope) return;
    const request = pendingPreview.request;
    let cancelled = false;
    dispatch({ type: "preview-started", scope, request });
    void api.readSftpText(request.browserHandle, request.fileHandle).then((value) => {
      if (cancelled) return;
      if (!isSftpTextPreview(value) || value.browserHandle !== request.browserHandle ||
        value.fileHandle !== request.fileHandle) throw new Error();
      dispatch({ type: "preview-loaded", scope, request, preview: value });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "preview-failed",
        scope,
        request,
        error: "文本预览失败：文件可能不是 UTF-8 文本，或会话已过期。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, enabled, pendingPreview, scope]);

  // One step of the way back after reopening, each time the listing it
  // waits for arrives. Every step is an ordinary listing of a folder the new
  // browser just listed; where the name is gone or cannot be told apart, the
  // walk stops there and says so.
  useEffect(() => {
    if (returning === null) return;
    if (returning.scope !== scope || !enabled) {
      setReturning(null);
      return;
    }
    const current = visibleState.directory;
    const status = visibleState.directoryStatus;
    // Until the new browser's first listing arrives, the expired one may still be on screen.
    const fresh = current !== null && current.browserHandle !== returning.expiredBrowser;
    if (status === "error" && (current === null || fresh)) {
      setReturning(null);
      return;
    }
    if (status !== "ready" || current === null || !fresh) return;
    const arrived = returning.awaiting === null
      ? current.parentDirectoryHandle === null
      : current.directoryHandle === returning.awaiting;
    if (!arrived) return;
    const reached = returning.target.slice(0, returning.target.length - returning.remaining.length);
    const trail = visibleState.trail;
    if (trail === null || trail.length !== reached.length || trail.some((name, index) => name !== reached[index])) {
      setReturning(null);
      return;
    }
    const next = returning.remaining[0];
    if (next === undefined) {
      setReturning(null);
      setReturnNotice(`已回到重新打开前所在的 ${sftpTrailPath(returning.target)}。`);
      return;
    }
    const step = sftpReturnStep(current, next);
    if (step.kind !== "enter") {
      setReturning(null);
      setReturnNotice(step.kind === "missing"
        ? `没能回到 ${sftpTrailPath(returning.target)}：${sftpTrailPath(reached)} 里已经没有“${next}”这个文件夹（可能已被删除、改名或无权查看），停在这里。`
        : `没能回到 ${sftpTrailPath(returning.target)}：${sftpTrailPath(reached)} 里有不止一个显示为“${next}”的文件夹，分不清是哪个，停在这里。`);
      return;
    }
    setReturning({ ...returning, remaining: returning.remaining.slice(1), awaiting: step.entryHandle });
    setPendingDirectory({
      scope: returning.scope,
      request: {
        id: ++requestRef.current,
        mode: "list",
        browserHandle: current.browserHandle,
        directoryHandle: step.entryHandle,
      },
    });
  }, [enabled, returning, scope, visibleState.directory, visibleState.directoryStatus, visibleState.trail]);

  if (connection === null) {
    return (
      <main className="sftp-browser-page sftp-browser-disconnected">
        <h1>文件管理 (SFTP)</h1>
        <p>连接 SSH 目标后，可浏览服务器目录、预览 UTF-8 文本，并在确认计划后传输和管理文件。</p>
      </main>
    );
  }

  if (!active) {
    return (
      <main className="sftp-browser-page sftp-browser-disconnected">
        <h1>文件管理已暂停</h1>
      </main>
    );
  }

  const connectedScope = scope ?? "";
  const directory = visibleState.directory;
  const entries = filterSftpBrowserEntries(directory?.entries ?? [], visibleState.kind, visibleState.search);
  const selected = directory?.entries.find((entry) =>
    entry.entryHandle === visibleState.selectedEntryHandle) ?? null;
  const busy = visibleState.directoryStatus === "loading" || visibleState.previewStatus === "loading";
  // Past its deadline, everything bound to this listing would be refused; say
  // so before a click is sent, and offer the one thing that helps.
  const listStale = directory !== null && (listExpiry.expired || browserGone);
  const staleTitle = listStale ? "目录列表已过期，先点“重新打开”" : undefined;

  /**
   * A new browser from the start directory: the expired one cannot be
   * renewed. It then walks back down to the folder that was on screen.
   */
  function reopenBrowser() {
    if (busy || downloading !== null) return;
    setPendingDirectory(null);
    setPendingPreview(null);
    setWindowError(null);
    setBrowserGone(false);
    const trail = visibleState.trail;
    setReturnNotice(trail === null && directory !== null && directory.parentDirectoryHandle !== null
      ? "原来所在的文件夹没能完整记下（名字被截短或层级太深），重新打开后从起始目录开始。"
      : null);
    setReturning(trail !== null && trail.length > 0 && directory !== null
      ? { scope: connectedScope, target: trail, remaining: trail, expiredBrowser: directory.browserHandle, awaiting: null }
      : null);
    setReopenVersion((version) => version + 1);
  }

  function requestDirectory(directoryHandle: string) {
    if (directory === null || busy) return;
    if (listStale) return reopenBrowser();
    setReturning(null);
    setReturnNotice(null);
    setPendingPreview(null);
    setWindowError(null);
    setPendingDirectory({
      scope: connectedScope,
      request: {
        id: ++requestRef.current,
        mode: "list",
        browserHandle: directory.browserHandle,
        directoryHandle,
      },
    });
  }

  /**
   * Opens one file in a window of its own.
   *
   * The pane hands over the two opaque handles it already holds and nothing
   * else; the window asks main what it was opened for, and main answers with
   * what it recorded. `editable` is settled here and cannot be changed from
   * inside the window.
   */
  async function openFileWindow(entry: SftpBrowserEntry | null, editable: boolean) {
    const file = entry ?? selected;
    if (directory === null || file === null || file.action !== "preview") return;
    if (listStale) return void setWindowError("目录列表已过期，先点“重新打开”。");
    if (fileWindowInFlight.current) return;
    fileWindowInFlight.current = true;
    setWindowError(null);
    try {
      await api.openFileEditor(directory.browserHandle, file.entryHandle, file.name, editable);
    } catch (reason) {
      setWindowError(errorText(reason, "打不开这个文件的窗口，连接可能已经断了。"));
    } finally {
      fileWindowInFlight.current = false;
    }
  }

  /**
   * Opens a new terminal window that starts in a folder: the one asked about,
   * or the one on screen. The window opens the shell itself, at its own size,
   * and says there if the folder can no longer be entered.
   */
  async function openFolderTerminal(entry: SftpBrowserEntry | null) {
    if (directory === null || (entry !== null && entry.kind !== "directory")) return;
    if (fileWindowInFlight.current) return;
    fileWindowInFlight.current = true;
    setWindowError(null);
    try {
      await api.openDirectoryTerminal(
        directory.browserHandle,
        entry?.entryHandle ?? directory.directoryHandle,
        entry?.name ?? directory.directoryLabel,
      );
    } catch (reason) {
      setWindowError(errorText(reason, "打不开新的终端窗口，连接可能已经断了。"));
    } finally {
      fileWindowInFlight.current = false;
    }
  }

  function selectEntry(entryHandle: string) {
    setPendingPreview(null);
    dispatch({ type: "entry-selected", entryHandle });
  }

  function toggleChecked(entry: SftpBrowserEntry) {
    if (entry.kind !== "file") return;
    setCheckedHandles((previous) => {
      const next = new Set(previous);
      if (next.has(entry.entryHandle)) {
        next.delete(entry.entryHandle);
      } else {
        next.add(entry.entryHandle);
      }
      return next;
    });
  }

  /** Parses the rate-limit field: blank is unlimited, else a KiB/s count. */
  function parsedRateLimit(): number | null {
    const text = rateLimitInput.trim();
    if (text === "") return 0;
    const value = Number.parseInt(text, 10);
    if (!Number.isFinite(value) || value < 0) return null;
    return value;
  }

  async function enqueueQueueDownload() {
    if (transferInFlight.current) return;
    const browserHandle = visibleState.directory?.browserHandle ?? null;
    if (browserHandle === null || checkedHandles.size === 0) return;
    const rateLimit = parsedRateLimit();
    if (rateLimit === null) {
      setTransferNotice("限速请输入 KiB/s 数字，留空表示不限速。");
      return;
    }
    transferInFlight.current = true;
    setTransferNotice(null);
    try {
      const value = await api.queueSftpDownload(browserHandle, [...checkedHandles], rateLimit);
      if (!isSftpQueueEnqueueResult(value)) throw new Error();
      if (value.queued && value.queue !== null) {
        setQueue(value.queue);
        setCheckedHandles(new Set());
      }
    } catch (reason) {
      setTransferNotice(errorText(reason, "批量下载没有排上队。"));
    } finally {
      transferInFlight.current = false;
    }
  }

  async function enqueueQueueUpload() {
    if (transferInFlight.current || directory === null) return;
    const browserHandle = directory.browserHandle;
    transferInFlight.current = true;
    setTransferNotice(null);
    try {
      const value = await api.queueSftpUpload(browserHandle, directory.directoryHandle);
      if (!isSftpQueueEnqueueResult(value)) throw new Error();
      if (value.queued && value.queue !== null) {
        setQueue(value.queue);
      }
    } catch (reason) {
      setTransferNotice(errorText(reason, "批量上传没有排上队。"));
    } finally {
      transferInFlight.current = false;
    }
  }

  async function cancelQueue() {
    const browserHandle = visibleState.directory?.browserHandle ?? null;
    if (browserHandle === null || queueCancelling) return;
    setQueueCancelling(true);
    try {
      await api.cancelSftpQueue(browserHandle);
      const value = await api.pollSftpQueue(browserHandle);
      if (value !== null && isSftpTransferQueue(value)) setQueue(value);
    } catch (reason) {
      setTransferNotice(errorText(reason, "未能取消队列。"));
    } finally {
      setQueueCancelling(false);
    }
  }

  async function retryQueueItem(itemId: number) {
    const browserHandle = visibleState.directory?.browserHandle ?? null;
    if (browserHandle === null) return;
    try {
      const value = await api.retrySftpQueueItem(browserHandle, itemId);
      if (isSftpTransferQueue(value)) setQueue(value);
    } catch (reason) {
      setTransferNotice(errorText(reason, "重试没有排上队。"));
    }
  }

  /**
   * 取回本机扫描: the row's own entry handle, or the listed directory's handle
   * when the operator asked the folder itself (blank area / toolbar with no
   * selection). The path on the subject is only a label — the backend
   * resolves the real path from the handles.
   */
  function openLocalScan(entry: SftpBrowserEntry | null): void {
    if (api.localScan === undefined || directory === null) return;
    const returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (entry !== null) {
      const path = directory.directoryLabel === "/" ? `/${entry.name}` : `${directory.directoryLabel}/${entry.name}`;
      setLocalScan({
        browserHandle: directory.browserHandle, entryHandle: entry.entryHandle, path,
        entryKind: entry.kind === "directory" ? "directory" : "file",
        returnFocus,
      });
    } else {
      setLocalScan({
        browserHandle: directory.browserHandle, entryHandle: directory.directoryHandle,
        path: directory.directoryLabel, entryKind: "directory",
        returnFocus,
      });
    }
  }

  async function downloadSelected(): Promise<void> {
    // A second click while the dialog is open would open a second dialog.
    if (transferInFlight.current) return;
    const browserHandle = visibleState.directory?.browserHandle ?? null;
    const fileHandle = visibleState.selectedEntryHandle;
    if (browserHandle === null || fileHandle === null) return;
    transferInFlight.current = true;
    setTransferNotice(null);
    setDownloading({ browserHandle, name: selected?.name ?? "所选文件", stage: "正在下载", cancelling: false });
    try {
      const value = await api.downloadSftpEntry(browserHandle, fileHandle);
      if (!isSftpTransferResult(value)) throw new Error();
      setTransferNotice(value.saved
        ? `已保存为 ${value.fileName}（${displaySftpBytes(value.bytes ?? "0")}）。`
        : "已取消保存。");
    } catch (reason) {
      setTransferNotice(transferStopped(reason)
        ? "已取消下载，写到一半的文件已经删除。"
        : "下载失败；文件可能已变化，或所选位置不可写。");
    } finally {
      transferInFlight.current = false;
      setDownloading(null);
    }
  }

  /**
   * "下载目录…": the target packs the directory into a tar, the host save
   * dialog — or the folder dialog for the extract variant — picks where it
   * goes, and the backend removes the remote temp archive however it ends.
   * The page hands over the directory's opaque handle and a suggested file
   * name only; local paths are the dialog's business.
   */
  async function downloadDirectory(entry: SftpBrowserEntry | null, extract: boolean): Promise<void> {
    if (transferInFlight.current || entry === null || entry.kind !== "directory") return;
    const browserHandle = visibleState.directory?.browserHandle ?? null;
    if (browserHandle === null) return;
    if (visibleState.directory?.degradedSftp === true) {
      setTransferNotice("目标没有 SFTP 子系统：无法改名、调整权限、删除或做递归操作；列目录经命令回退完成，文件下载上传经 SCP 通道完成。");
      return;
    }
    transferInFlight.current = true;
    setTransferNotice(null);
    setDownloading({
      browserHandle,
      name: entry.name,
      stage: extract ? "正在打包、下载并解压" : "正在打包并下载",
      cancelling: false,
    });
    try {
      const value = await api.downloadSftpDirectory(
        browserHandle, entry.entryHandle, entry.name, extract,
      );
      if (!isSftpDirectoryDownloadResult(value)) throw new Error();
      if (!value.saved) {
        setTransferNotice("已取消保存。");
      } else if (value.state === "done") {
        setTransferNotice(value.detail ?? `已保存为 ${value.fileName ?? ""}。`);
      } else {
        // Refusals and extract failures carry their own numbers and reasons.
        setTransferNotice(value.detail ?? "目录下载未完成。");
      }
    } catch (reason) {
      setTransferNotice(transferStopped(reason)
        ? "已取消下载，写到一半的文件和远端的临时包都已经删除。"
        : errorText(reason, "目录下载失败；目录可能已变化，或所选位置不可写。"));
    } finally {
      transferInFlight.current = false;
      setDownloading(null);
    }
  }

  /**
   * "上传目录…": the host folder dialog picks a local folder, the host packs
   * it into a bounded tar that refuses links and reparse points, and the
   * preview's numbers come back before anything remote is written. On confirm
   * the archive uploads to a remote temp path and extracts under
   * `<dir>/<folder name>`; both temps go away on every outcome, and a
   * finished upload can be undone while its receipt offers it.
   */
  async function uploadDirectory(entry: SftpBrowserEntry | null): Promise<void> {
    if (transferInFlight.current) return;
    const browserHandle = visibleState.directory?.browserHandle ?? null;
    const directoryHandle = entry?.entryHandle ?? visibleState.directory?.directoryHandle ?? null;
    const directoryLabel = entry?.name ?? visibleState.directory?.directoryLabel ?? "当前目录";
    if (browserHandle === null || directoryHandle === null) return;
    if (visibleState.directory?.degradedSftp === true) {
      setTransferNotice("目标没有 SFTP 子系统：无法改名、调整权限、删除或做递归操作；列目录经命令回退完成，文件下载上传经 SCP 通道完成。");
      return;
    }
    transferInFlight.current = true;
    setTransferNotice(null);
    setDirectoryUndo(null);
    try {
      const prepared = await api.prepareSftpDirectoryUpload(browserHandle);
      if (!isSftpDirectoryUploadPrepare(prepared)) throw new Error();
      if (!prepared.prepared) return;
      const stagedHandle = prepared.stagedHandle ?? "";
      const folderName = prepared.folderName ?? "所选文件夹";
      const confirmed = await directoryUploadConfirm.ask(
        "上传整个目录",
        `将把本机文件夹“${folderName}”（${prepared.fileCount ?? "?"} 个文件，共 ` +
        `${displaySftpBytes(prepared.totalBytes ?? "0")}）上传到 ${directoryLabel}。` +
        `目标位置若已存在同名内容会被拒绝，不会覆盖。`,
        "上传",
      );
      if (!confirmed) {
        setTransferNotice("已取消上传。");
        try { await api.discardSftpDirectoryUpload(stagedHandle); } catch { /* staged copy expires */ }
        return;
      }
      setDownloading({
        browserHandle,
        name: folderName,
        stage: "正在上传并解包",
        cancelling: false,
      });
      const value = await api.runSftpDirectoryUpload(browserHandle, directoryHandle, stagedHandle);
      if (!isSftpDirectoryUploadResult(value)) throw new Error();
      setTransferNotice(value.detail ?? "目录上传未完成。");
      if (value.saved && value.undoable === true && value.planHandle !== null &&
        value.planHandle !== undefined) {
        setDirectoryUndo({ planHandle: value.planHandle, name: folderName });
      }
    } catch (reason) {
      setTransferNotice(transferStopped(reason)
        ? "已取消上传，本机和远端的临时包都已经删除。"
        : errorText(reason, "目录上传失败；目录可能已变化，或目标位置不可写。"));
    } finally {
      transferInFlight.current = false;
      setDownloading(null);
    }
  }

  /** Removes the freshly uploaded tree after the target re-verifies it is unchanged. */
  async function undoDirectoryUpload(): Promise<void> {
    const pending = directoryUndo;
    if (pending === null) return;
    setDirectoryUndo(null);
    try {
      const value = await api.undoSftpOperation(pending.planHandle);
      if (!isSftpOperationUndoResult(value)) throw new Error();
      setTransferNotice(value.detail);
    } catch (reason) {
      setTransferNotice(sftpUndoFailure(reason));
    }
  }

  /**
   * Stops this browser's running upload or download. The transfer removes
   * what it wrote and then answers its own request, which reports the result;
   * when nothing was running yet the button simply comes back.
   */
  async function cancelTransfer(browserHandle: string, onSettled: (reached: boolean) => void): Promise<void> {
    try {
      const value = await api.cancelSftpTransfer(browserHandle);
      onSettled(isSftpTransferCancelResult(value) && value.cancelled > 0);
    } catch {
      onSettled(false);
    }
  }

  function openMenu(event: MouseEvent, entry: SftpBrowserEntry | null): void {
    event.preventDefault();
    if (entry !== null) selectEntry(entry.entryHandle);
    setMenu({ position: { x: event.clientX, y: event.clientY }, entry });
  }

  function startOperation(action: SftpMenuAction, entry: SftpBrowserEntry | null): void {
    setMenu(null);
    // The context menu reaches here as well as the toolbar.
    if (listStale) return void setWindowError("目录列表已过期，先点“重新打开”。");
    if (action === "local-scan") return void openLocalScan(entry);
    // A new window beside this one: a plan or a receipt on screen stays.
    if (action === "terminal") return void openFolderTerminal(entry);
    setPlan(null);
    clearReceipt();
    setOperationError(null);
    if (action === "open" && entry !== null) return requestDirectory(entry.entryHandle);
    // Both open the same window; only the permission to write differs, and
    // that is settled by main when it creates the window.
    if (action === "preview" || action === "edit") {
      return void openFileWindow(entry, action === "edit");
    }
    if (action === "download") return void downloadSelected();
    if (action === "download-directory" || action === "download-directory-extract") {
      return void downloadDirectory(entry, action === "download-directory-extract");
    }
    if (action === "upload-directory") return void uploadDirectory(entry);
    if (action === "properties") {
      if (entry !== null) setProperties(entry);
      return;
    }
    if (action === "open") return;
    const subject = entry === null ? (directory?.directoryLabel ?? "当前目录") : entry.name;
    const next: SftpOperationDraft = { kind: action, subject };
    if (action === "rename" && entry !== null) next.name = entry.name;
    // Adjust the mode the server reported rather than typing one from memory.
    if (action === "chmod" && entry !== null && entry.mode !== null) next.mode = entry.mode;
    setProperties(null);
    setDraft(next);
  }

  async function buildPlan(next: SftpOperationDraft): Promise<void> {
    if (operationInFlight.current) return;
    const browserHandle = visibleState.directory?.browserHandle ?? null;
    const directoryHandle = visibleState.directory?.directoryHandle ?? null;
    const entryHandle = visibleState.selectedEntryHandle;
    if (browserHandle === null || directoryHandle === null) return;
    const handles = next.kind === "create-directory" || next.kind === "upload"
      ? [directoryHandle]
      : entryHandle === null ? [] : [entryHandle];
    if (handles.length === 0) {
      setOperationError("请先选择一个条目。");
      return;
    }
    operationInFlight.current = true;
    setOperationBusy(true);
    setOperationError(null);
    try {
      let stagedHandle: string | null = null;
      if (next.kind === "upload") {
        const staged = next.localFileHandle === undefined
          ? await api.stageSftpUpload()
          : await api.stageSftpUpload(next.localFileHandle);
        const upload = stagedUpload(staged);
        if (upload === null) {
          setDraft(null);
          return;
        }
        stagedHandle = upload.stagedHandle;
        if (next.name === undefined || next.name.length === 0) {
          next = { ...next, name: upload.name };
        }
      }
      const input: SftpOperationInput = { kind: next.kind, entryHandles: handles };
      if (next.name !== undefined && next.name.length > 0) input.name = next.name;
      if (next.mode !== undefined && next.mode.length > 0) {
        input.mode = Number.parseInt(next.mode, 8);
      }
      if (next.format !== undefined) input.format = next.format;
      if (stagedHandle !== null) input.stagedHandle = stagedHandle;
      const value = await api.planSftpOperation(browserHandle, input);
      if (!isSftpOperationPlan(value)) throw new Error();
      setDraft(next);
      setPlan(value);
    } catch {
      setOperationError("无法生成计划；条目可能已变化，或参数不被接受。");
    } finally {
      operationInFlight.current = false;
      setOperationBusy(false);
    }
  }

  async function runPlan(): Promise<void> {
    if (operationInFlight.current || plan === null) return;
    operationInFlight.current = true;
    setOperationBusy(true);
    setOperationError(null);
    try {
      const confirmed = await api.confirmSftpOperation(plan.planHandle);
      if (!isSftpOperationPlan(confirmed)) throw new Error();
      const value = await api.executeSftpOperation(plan.planHandle);
      if (!isSftpOperationReceipt(value)) throw new Error();
      setReceipt(value);
      if (value.passed && directory !== null) requestDirectory(directory.directoryHandle);
    } catch {
      setOperationError("执行失败；目标可能已变化，或计划已过期。");
    } finally {
      operationInFlight.current = false;
      setOperationBusy(false);
      setCancellingUpload(false);
    }
  }

  /**
   * Puts the operation on the receipt back, once. The core reads the target
   * again first and refuses when it changed after the operation, so a later
   * change is never overwritten; whatever comes back, it is not offered again.
   */
  async function undoOperation(): Promise<void> {
    if (operationInFlight.current || receipt === null || !receipt.undoable || undoSpent) return;
    const { planHandle } = receipt;
    operationInFlight.current = true;
    setUndoSpent(true);
    setOperationBusy(true);
    setOperationError(null);
    try {
      const value = await api.undoSftpOperation(planHandle);
      if (!isSftpOperationUndoResult(value) || value.planHandle !== planHandle) {
        throw new Error("无法核对撤销的结果，请刷新查看现在的状态，勿重复操作。");
      }
      setUndoResult(value);
      if (directory !== null) requestDirectory(directory.directoryHandle);
    } catch (error) {
      setOperationError(sftpUndoFailure(error));
    } finally {
      operationInFlight.current = false;
      setOperationBusy(false);
    }
  }

  function clearReceipt(): void {
    setReceipt(null);
    setUndoResult(null);
    setUndoSpent(false);
  }

  function closeOperation(): void {
    if (plan !== null && receipt === null) void api.cancelSftpOperation(plan.planHandle);
    setDraft(null);
    setPlan(null);
    clearReceipt();
    setOperationError(null);
  }

  function updateFilter(kind: SftpBrowserKindFilter) {
    setPendingPreview(null);
    dispatch({ type: "kind-selected", kind });
  }

  return (
    <main className="sftp-browser-page">
      <header className="sftp-browser-header">
        <h1>文件管理 (SFTP)</h1>
      </header>
      <div className="sftp-browser-actions" role="toolbar" aria-label="文件操作">
        {listStale ? (
          <button type="button" className="sftp-browser-action is-attention" data-testid="sftp-reopen"
            disabled={busy || downloading !== null}
            title={downloading !== null ? "等下载结束或取消后再重新打开" : "目录列表已过期，重新读取并回到这个文件夹"}
            onClick={reopenBrowser}>
            <RefreshIcon />重新打开
          </button>
        ) : (
          <button type="button" className="sftp-browser-action" disabled={busy || directory === null}
            onClick={() => directory !== null && requestDirectory(directory.directoryHandle)}>
            <RefreshIcon />{visibleState.directoryStatus === "loading" ? "读取中" : "刷新"}
          </button>
        )}
        <button type="button" className="sftp-browser-action is-upload"
          disabled={busy || directory === null || listStale} title={staleTitle}
          onClick={() => {
            setPlan(null);
            clearReceipt();
            setOperationError(null);
            setDraft({ kind: "upload", subject: directory?.directoryLabel ?? "当前目录" });
          }}>
          <UploadIcon />上传
        </button>
        <button type="button" className="sftp-browser-action is-download"
          disabled={busy || selected?.kind !== "file" || listStale} title={staleTitle}
          onClick={() => void downloadSelected()}>
          <DownloadIcon />下载
        </button>
        <button type="button" className="sftp-browser-action is-download" data-testid="sftp-queue-download"
          disabled={busy || checkedHandles.size === 0 || listStale}
          title={staleTitle ?? "把勾选的文件逐个下载到所选文件夹；同名本机文件不会被覆盖"}
          onClick={() => void enqueueQueueDownload()}>
          <DownloadIcon />下载所选{checkedHandles.size > 0 ? `（${checkedHandles.size}）` : ""}
        </button>
        <button type="button" className="sftp-browser-action is-upload" data-testid="sftp-queue-upload"
          disabled={busy || directory === null || listStale}
          title={staleTitle ?? "选择多个本机文件，逐个上传到当前目录"}
          onClick={() => void enqueueQueueUpload()}>
          <UploadIcon />批量上传
        </button>
        <label className="sftp-browser-rate" title="队列下载限速，留空不限速">
          限速
          <input type="text" inputMode="numeric" placeholder="不限" value={rateLimitInput}
            aria-label="下载限速（KiB/s）" data-testid="sftp-rate-limit"
            onChange={(event) => setRateLimitInput(event.target.value)} />
          <span>KiB/s</span>
        </label>
        {api.localScan === undefined ? null : (
          <button type="button" className="sftp-browser-action" data-testid="sftp-local-scan"
            disabled={busy || directory === null || listStale}
            title={staleTitle ?? "把所选文件或目录（未选择时为当前目录）取回本机隔离目录扫描"}
            onClick={() => {
              if (selected !== null && (selected.action === "browse" || selected.action === "preview")) {
                openLocalScan(selected);
              } else {
                openLocalScan(null);
              }
            }}>
            <DownloadIcon />取回扫描
          </button>
        )}
        <button type="button" className="sftp-browser-action is-danger"
          disabled={busy || selected === null || listStale} title={staleTitle}
          onClick={() => startOperation("remove", selected)}>
          <TrashIcon />删除
        </button>
        <button type="button" className="sftp-browser-action" disabled={busy || directory === null || listStale}
          title={staleTitle}
          onClick={() => startOperation("create-directory", null)}>
          <NewFolderIcon />新建文件夹
        </button>
        <button type="button" className="sftp-browser-action" disabled={busy || selected === null || listStale}
          title={staleTitle}
          onClick={() => startOperation("archive", selected)}>
          <ArchiveIcon />打包
        </button>
        <button type="button" className="sftp-browser-action" disabled={directory === null || listStale}
          data-testid="sftp-terminal-here" title={staleTitle ?? "在当前文件夹打开一个新的终端窗口"}
          onClick={() => startOperation("terminal", null)}>
          <TerminalHereIcon />在这里打开终端
        </button>
      </div>

      {visibleState.directoryStatus === "loading" && directory === null ? (
        <SftpBrowserStatus label="正在打开文件管理并读取根目录…" />
      ) : visibleState.directoryStatus === "error" && directory === null ? (
        <SftpBrowserError message={visibleState.directoryError ?? "文件管理不可用，请关闭后重新打开再试。"} />
      ) : directory === null ? (
        <SftpBrowserEmpty title="文件管理还没有打开" detail="关闭后重新打开文件管理再试。" />
      ) : (
        <>
          {visibleState.directoryStatus === "error" && <SftpBrowserError
            message={visibleState.directoryError ?? "目录读取失败。"} compact />}
          {returning !== null ? (
            <p className="sftp-browser-return" role="status" data-testid="sftp-return">
              正在回到重新打开前所在的 {sftpTrailPath(returning.target)}…
            </p>
          ) : returnNotice !== null ? (
            <TransientNotice source="文件传输" message={returnNotice ?? ""} severity="info"><p className="sftp-browser-return" role="status" data-testid="sftp-return">{returnNotice}</p></TransientNotice>
          ) : null}
          <div className="sftp-browser-panes">
            <LocalFilePane
              api={api}
              active={enabled}
              onUpload={(entryHandle, name) => {
                setMenu(null);
                setPlan(null);
                clearReceipt();
                setOperationError(null);
                setDraft({
                  kind: "upload",
                  subject: directory?.directoryLabel ?? "当前目录",
                  name,
                  localFileHandle: entryHandle,
                });
              }}
            />

            <section className="sftp-browser-pane" aria-label="远程文件">
              <header className="sftp-browser-pane-head">
                <strong>远程文件</strong>
                <label className="sftp-browser-filter">
                  <span className="terminal-sr-only">筛选名称</span>
                  <input value={visibleState.search} maxLength={256} placeholder="筛选名称"
                    onChange={(event) => {
                      setPendingPreview(null);
                      dispatch({ type: "search-changed", value: event.currentTarget.value });
                    }} />
                </label>
                <select aria-label="类型" value={visibleState.kind}
                  onChange={(event) => updateFilter(event.currentTarget.value as SftpBrowserKindFilter)}>
                  <option value="all">全部</option>
                  {sftpBrowserEntryKinds.map((kind) => <option key={kind} value={kind}>
                    {sftpBrowserKindLabel(kind)}
                  </option>)}
                </select>
              </header>
              <div className="sftp-browser-pathbar">
                <button type="button" title="上一级" aria-label="上一级"
                  disabled={busy || directory.parentDirectoryHandle === null}
                  onClick={() => directory.parentDirectoryHandle !== null &&
                    requestDirectory(directory.parentDirectoryHandle)}>
                  <UpIcon />
                </button>
                <button type="button" title="回到根目录" aria-label="回到根目录" disabled={busy ||
                  visibleState.rootDirectoryHandle === null ||
                  directory.directoryHandle === visibleState.rootDirectoryHandle}
                  onClick={() => visibleState.rootDirectoryHandle !== null &&
                    requestDirectory(visibleState.rootDirectoryHandle)}>
                  <HomeIcon />
                </button>
                <span className="sftp-browser-path-value">{directory.directoryLabel}</span>
              </div>
              <div className="sftp-browser-pane-body">
                <SftpBrowserTable entries={entries} selectedHandle={visibleState.selectedEntryHandle}
                  search={visibleState.search} busy={busy} onSelect={selectEntry}
                  checkedHandles={checkedHandles} onToggleCheck={toggleChecked}
                  onBrowse={(entryHandle) => requestDirectory(entryHandle)}
                  onContextMenu={openMenu} />
              </div>
              <footer className="sftp-browser-pane-foot">
                <span>
                  {directory.displayedEntryCount} 个项目（
                  {entries.filter((item) => item.kind === "directory").length} 个文件夹，
                  {entries.filter((item) => item.kind !== "directory").length} 个文件）
                </span>
                {listStale ? (
                  <span className="sftp-browser-expired" role="status" data-testid="sftp-list-expired">
                    目录列表已过期，点“重新打开”重新读取并回到这个文件夹
                  </span>
                ) : (
                  <span title="每次读取目录都会重新计时；超过这个时间再操作会被拒绝，刷新目录即可继续。">
                    目录列表约 {listExpiry.minutesLeft ?? Math.max(1, Math.ceil(directory.expiresInSeconds / 60))} 分钟内有效
                  </span>
                )}
              </footer>
            </section>
          </div>
          {directory.degradedSftp && <p className="sftp-browser-warning sftp-browser-degraded" role="status" data-testid="sftp-degraded-banner">
            目标没有 SFTP 子系统，文件管理为只读降级模式：可以浏览目录，并通过 SCP 通道下载或上传文件；改名、权限调整、删除与递归操作不可用。
          </p>}
          {directory.truncated && <p className="sftp-browser-warning" role="status">
            目录共有 {directory.observedEntryCount} 项，当前只显示前 {directory.displayedEntryCount} 项。
          </p>}

          {/* Only the transfer result stays inline. The panel that used to sit
              here held a text preview as well, and it cost a permanent third
              of the pane to show a few wrapped lines of a file — the file now
              opens in a window of its own, where it can be read and edited at
              a usable size. */}
          {queue === null ? null : (
            <section className="sftp-queue" aria-label="传输队列" data-testid="sftp-transfer-queue">
              <header className="sftp-queue-head">
                <strong>传输队列</strong>
                {queue.degraded ? (
                  <span className="sftp-queue-note">目标没有 SFTP：逐项经 SCP 传输，下载无法续传。</span>
                ) : null}
                {queue.active ? (
                  <button type="button" disabled={queueCancelling} data-testid="sftp-queue-cancel"
                    onClick={() => void cancelQueue()}>
                    {queueCancelling ? "正在取消…" : "全部取消"}
                  </button>
                ) : (
                  <button type="button" data-testid="sftp-queue-dismiss" onClick={() => setQueue(null)}>
                    关闭
                  </button>
                )}
              </header>
              <ul className="sftp-queue-items">
                {queue.items.map((item) => (
                  <li key={item.itemId} className={`sftp-queue-item is-${item.state}`}
                    data-testid={`sftp-queue-item-${item.state}`}>
                    <span className="sftp-queue-item-name" title={item.name}>{item.name}</span>
                    <span className="sftp-queue-item-state">
                      {item.state === "queued" ? "排队中"
                        : item.state === "running"
                          ? `传输中 ${compactSftpBytes(item.doneBytes)}/${compactSftpBytes(item.totalBytes)}`
                          : item.state === "done" ? "完成"
                            : item.state === "failed" ? "失败" : "已取消"}
                    </span>
                    {item.detail !== "" ? (
                      <span className="sftp-queue-item-detail" title={item.detail}>{item.detail}</span>
                    ) : null}
                    {item.state === "failed" || item.state === "cancelled" ? (
                      <button type="button" data-testid={`sftp-queue-retry-${item.itemId}`}
                        onClick={() => void retryQueueItem(item.itemId)}>
                        重试
                      </button>
                    ) : null}
                  </li>
                ))}
              </ul>
            </section>
          )}
          {downloading === null ? null : (
            <p className="sftp-browser-transfer is-running" role="status">
              <span>{downloading.stage} {downloading.name}…</span>
              <button type="button" disabled={downloading.cancelling} data-testid="sftp-cancel-download"
                onClick={() => {
                  const current = downloading;
                  setDownloading({ ...current, cancelling: true });
                  void cancelTransfer(current.browserHandle, (reached) => {
                    if (!reached) setDownloading((now) => now === null ? null : { ...now, cancelling: false });
                  });
                }}>
                {downloading.cancelling ? "正在取消…" : downloading.stage.includes("上传") ? "取消上传" : "取消下载"}
              </button>
            </p>
          )}
          {transferNotice === null || downloading !== null ? null : (
            <TransientNotice source="文件传输" message={transferNotice ?? ""} severity="info"><p className="sftp-browser-transfer" role="status">{transferNotice}</p></TransientNotice>
          )}
          {directoryUndo === null || downloading !== null ? null : (
            <button type="button" className="sftp-browser-action" data-testid="sftp-undo-directory-upload"
              title={`撤销刚才上传的 ${directoryUndo.name}，目标机会先核对内容未变再整个删除`}
              onClick={() => void undoDirectoryUpload()}>
              <TrashIcon />撤销这次目录上传
            </button>
          )}
          {windowError === null ? null : (
            <TransientNotice source="文件传输" message={windowError ?? ""} severity="error"><p className="sftp-browser-transfer is-error" role="alert" data-testid="sftp-window-error">{windowError}</p></TransientNotice>
          )}

          {menu === null ? null : (
            <SftpContextMenu
              position={menu.position}
              entry={menu.entry}
              busy={busy}
              localScan={api.localScan !== undefined}
              onAction={(action) => startOperation(action, menu.entry)}
              onDismiss={() => setMenu(null)}
            />
          )}
          {localScan === null || api.localScan === undefined ? null : (
        <LocalScanDialog
          key={`${localScan.browserHandle}:${localScan.entryHandle}`}
          transport={browserScanTransport(api as LocalScanChildApi, localScan.browserHandle, localScan.entryHandle)}
          subject={{ path: localScan.path, entryKind: localScan.entryKind }}
          returnFocus={localScan.returnFocus}
          onClose={() => setLocalScan(null)}
        />
      )}
      {properties === null ? null : (
        <SftpPropertiesDialog
          entry={properties}
          onChmod={() => startOperation("chmod", properties)}
          onClose={() => setProperties(null)}
        />
      )}
      {directoryUploadConfirm.dialog === null ? null : (
        <DialogHost dialog={directoryUploadConfirm.dialog} onResolve={directoryUploadConfirm.resolve} />
      )}
      {draft === null ? null : (
            <SftpOperationDialog
              draft={draft}
              plan={plan}
              receipt={receipt}
              undo={undoResult}
              undoSpent={undoSpent}
              busy={operationBusy}
              error={operationError}
              onPlan={(next) => void buildPlan(next)}
              onConfirm={() => void runPlan()}
              onUndo={() => void undoOperation()}
              cancellingTransfer={cancellingUpload}
              onCancelTransfer={plan?.kind === "upload" && receipt === null ? () => {
                setCancellingUpload(true);
                void cancelTransfer(plan.browserHandle, (reached) => {
                  if (!reached) setCancellingUpload(false);
                });
              } : undefined}
              onClose={closeOperation}
            />
          )}
        </>
      )}
    </main>
  );
}

/**
 * Says what a failed undo means for the target. An undo the backend no longer
 * holds was refused before anything was touched; one that ran out of time may
 * or may not have reached the target. The window is the backend's UNDO_TTL.
 */
export function sftpUndoFailure(reason: unknown): string {
  const text = reason instanceof Error ? reason.message : "";
  if (/\(sftp-browser-unavailable\)\s*$/u.test(text)) {
    return "撤销的时限已过（完成后 10 分钟内有效），没有改动任何东西。请刷新后再决定。";
  }
  if (/\(sftp-browser-timeout\)\s*$/u.test(text)) {
    return "撤销没有在时限内返回结果，不确定是否已经放回。请刷新查看现在的状态。";
  }
  return errorText(reason, "撤销没有完成；请刷新查看现在的状态。");
}

/** Whether a transfer failed because the operator stopped it. */
export function transferStopped(reason: unknown): boolean {
  return reason instanceof Error && /\(sftp-browser-cancelled\)\s*$/u.test(reason.message);
}

/** Main answers either a staged file or a dismissed dialog. */
function stagedUpload(value: unknown): { stagedHandle: string; name: string } | null {
  if (typeof value !== "object" || value === null) return null;
  const reply = value as { staged?: unknown; upload?: unknown };
  if (reply.staged !== true || !isSftpStagedUpload(reply.upload)) return null;
  return { stagedHandle: reply.upload.stagedHandle, name: reply.upload.name };
}

/** One row per entry: name, size, modified — the columns the design asks for. */
export function SftpBrowserTable({
  entries,
  selectedHandle,
  search,
  busy,
  onSelect,
  onBrowse,
  onContextMenu,
  checkedHandles,
  onToggleCheck,
}: {
  entries: SftpBrowserEntry[];
  selectedHandle: string | null;
  search: string;
  busy: boolean;
  onSelect: (entryHandle: string) => void;
  onBrowse: (entryHandle: string) => void;
  onContextMenu?: (event: MouseEvent, entry: SftpBrowserEntry | null) => void;
  checkedHandles?: ReadonlySet<string>;
  onToggleCheck?: (entry: SftpBrowserEntry) => void;
}) {
  return (
    <div className="sftp-browser-rows" role="list"
      onContextMenu={(event) => onContextMenu?.(event, null)}>
      <div className="sftp-browser-table-head" aria-hidden="true">
        <span>名称</span><span>大小</span><span>修改时间</span>
      </div>
      {entries.length === 0 ? (
        <SftpBrowserEmpty
          title={search.trim() === "" ? "目录为空" : "没有匹配条目"}
          detail={search.trim() === "" ? "当前目录没有条目。" : "调整筛选条件。"}
          compact
        />
      ) : entries.map((entry) => (
        <button
          type="button"
          role="listitem"
          key={entry.entryHandle}
          className={entry.entryHandle === selectedHandle
            ? "sftp-browser-row is-selected"
            : "sftp-browser-row"}
          disabled={busy}
          aria-pressed={entry.entryHandle === selectedHandle}
          onClick={() => onSelect(entry.entryHandle)}
          onDoubleClick={() => entry.action === "browse" && onBrowse(entry.entryHandle)}
          onContextMenu={(event) => {
            event.stopPropagation();
            onContextMenu?.(event, entry);
          }}
        >
          <span className="sftp-browser-row-name">
            {entry.kind === "file" && onToggleCheck !== undefined ? (
              <span
                role="checkbox"
                aria-checked={checkedHandles?.has(entry.entryHandle) === true}
                aria-label={`勾选 ${entry.name} 加入批量传输`}
                tabIndex={0}
                className="sftp-browser-row-check"
                data-testid={`sftp-check-${entry.name}`}
                onClick={(event) => {
                  event.stopPropagation();
                  onToggleCheck(entry);
                }}
                onKeyDown={(event) => {
                  if (event.key === " " || event.key === "Enter") {
                    event.preventDefault();
                    event.stopPropagation();
                    onToggleCheck(entry);
                  }
                }}
              >
                {checkedHandles?.has(entry.entryHandle) === true ? "☑" : "☐"}
              </span>
            ) : null}
            <span className={`sftp-browser-row-kind is-${entry.kind}`}>
              <EntryKindIcon kind={entry.kind} />
            </span>
            <span className="sftp-browser-row-label" title={entry.name}>{entry.name}</span>
            {entry.nameTruncated ? <em>名称已截断</em> : null}
          </span>
          <span className="sftp-browser-row-size" title={entry.kind === "directory" ? undefined : displaySftpBytes(entry.sizeBytes)}>
            {entry.kind === "directory" ? "—" : compactSftpBytes(entry.sizeBytes)}
          </span>
          <span className="sftp-browser-row-time">{displaySftpModifiedAt(entry.modifiedAt)}</span>
        </button>
      ))}
    </div>
  );
}

export function SftpTextPreviewView({ preview }: { preview: SftpTextPreview }) {
  return (
    <div className="sftp-browser-preview">
      <header>
        <strong>UTF-8 纯文本预览</strong>
        <span>{preview.displayedLineCount}/{preview.observedLineCount} 行</span>
      </header>
      {preview.truncated && <p className="sftp-browser-warning" role="status">
        文本已按行数或大小上限截断。
      </p>}
      {preview.text.length === 0 ? <SftpBrowserEmpty title="文件没有可显示文本"
        detail="常规 UTF-8 文件为空，或仅包含一个空行。" compact /> :
        <pre className="sftp-browser-preview-text">{preview.text}</pre>}
    </div>
  );
}

/**
 * Why the file browser would not open, in terms an operator can act on.
 *
 * The old text named three things that might be wrong — the binding, the
 * permissions, the fixed entry point — and the most common cause was none of
 * them: an `sshd` with no `Subsystem sftp` line takes the request, never
 * finishes the handshake, and the browser reads as broken. Guessing three
 * wrong causes is worse than naming the one the target reported.
 */
/**
 * Whether a refusal means this browser no longer exists on the backend —
 * expired or closed — so that listing again cannot help and only opening a
 * new one can. The code is the backend's, kept at the end of the message.
 */
export function sftpBrowserGone(reason: unknown): boolean {
  const text = reason instanceof Error ? reason.message : String(reason ?? "");
  return /\(sftp-browser-unavailable\)\s*$/u.test(text);
}

export function sftpOpenFailureMessage(reason: unknown): string {
  const text = reason instanceof Error ? reason.message : "";
  if (text.includes("sftp-browser-subsystem-unavailable")) {
    return "这台目标机没有完成 SFTP 握手，多半是它的 SSH 服务没有开启 sftp 子系统"
      + "（sshd_config 里缺少 Subsystem sftp 那一行）。终端命令仍然可用。";
  }
  if (text.includes("sftp-browser-timeout")) {
    return "打开文件管理超时：目标机没有在限定时间内回应。";
  }
  if (text.includes("sftp-browser-capacity")) {
    return "同时打开的文件管理太多了，关掉一个再试。";
  }
  return targetFailureMessage(
    reason,
    "无法打开文件管理：目标机没有接受这次请求，可能是当前账号没有使用 SFTP 的权限。",
  );
}

export function SftpBrowserStatus({ label, compact = false }: { label: string; compact?: boolean }) {
  return <div className={compact ? "sftp-browser-status is-compact" : "sftp-browser-status"}
    aria-live="polite"><span aria-hidden="true" />{label}</div>;
}

export function SftpBrowserError({ message, compact = false }: { message: string; compact?: boolean }) {
  return <div className={compact ? "sftp-browser-error is-compact" : "sftp-browser-error"}
    role="alert"><strong>读取失败</strong><p>{message}</p></div>;
}

export function SftpBrowserEmpty({ title, detail, compact = false }: {
  title: string;
  detail: string;
  compact?: boolean;
}) {
  return <div className={compact ? "sftp-browser-empty is-compact" : "sftp-browser-empty"}>
    <strong>{title}</strong><p>{detail}</p>
  </div>;
}
