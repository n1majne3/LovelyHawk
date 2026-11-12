import { listen } from "@tauri-apps/api/event";

import { isAiAssistRequest, matchesAiAssistResponse } from "../shared/ai-assist-contract.js";
import { isLocalBrowserOpaqueHandle, isLocalDirectorySnapshot } from "../shared/local-browser-contract.js";
import {
  isLocalScanChildRequest,
  matchesLocalScanResult,
  type LocalScanChildRequest,
} from "../shared/local-scan-contract.js";
import {
  isSftpBrowserOpaqueHandle,
  isSftpDirectoryDownloadResult,
  isSftpDirectorySnapshot,
  isSftpDirectoryUploadPrepare,
  isSftpDirectoryUploadResult,
  isSftpOperationInput,
  isSftpOperationPlan,
  isSftpOperationReceipt,
  isSftpOperationUndoResult,
  isSftpQueueEnqueueResult,
  isSftpRelay,
  isSftpRelayTargetList,
  isSftpTransferCancelResult,
  isSftpTransferQueue,
  isSftpStagedUpload,
  isSftpTextPreview,
} from "../shared/sftp-browser-contract.js";
import {
  isFileEditorTarget,
  isTerminalClosed,
  isTerminalInputAcknowledgement,
  isTerminalPoll,
  isTerminalPollBounds,
  isTerminalResized,
  isTerminalSearch,
  isTerminalSearchRequest,
  isTerminalSelectionCopyText,
  isTerminalSize,
  isTerminalTabName,
  isTerminalTabOpened,
  isTerminalWindowLaunchResult,
  terminalBase64DecodedLength,
  TERMINAL_LIMITS,
  type TerminalApi,
  type TerminalTabOpened,
} from "../shared/terminal-contract.js";
import { invokeHost } from "./transport.js";

const TERMINAL_TIMEOUT_MS = 15_000;
/** The same event the main window's close question uses. */
const BEFORE_CLOSE_EVENT = "lovelyhawk://before-close";
const SFTP_BROWSER_TIMEOUT_MS = 30_000;
/** Starting an answer may wait for the provider to accept the connection. */
const AI_ASSIST_TIMEOUT_MS = 60_000;
const SFTP_OPERATION_TIMEOUT_MS = 100_000;
/** A dialog stays open as long as the operator needs; the transfer bound follows it. */
const DIALOG_TIMEOUT_MS = 60 * 60 * 1_000;

function refuse(message: string): never {
  throw new Error(message);
}

function requireArity(values: unknown[], count: number, message: string): void {
  if (values.length !== count) refuse(message);
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function checked<T>(
  command: string,
  args: Record<string, unknown>,
  timeoutMs: number,
  accept: (value: unknown) => boolean,
  message: string,
): Promise<T> {
  const value = await invokeHost(command, args, timeoutMs);
  if (!accept(value)) refuse(message);
  return value as T;
}

/**
 * The API a terminal, container-terminal or file-editor window gets.
 *
 * None of these calls names a target: the host resolves the binding, the
 * container and the file from what it recorded when it created this window.
 */
export function createTerminalApi(): TerminalApi {
  const opening = (command: string) => async (...values: unknown[]) => {
    requireArity(values, 2, "Invalid terminal open request.");
    const [columns, rows] = values;
    if (!isTerminalSize(columns, rows)) refuse("Invalid terminal open request.");
    return checked<TerminalTabOpened>(command, { columns, rows }, 60_000,
      (value) => isTerminalTabOpened(value) && value.columns === columns && value.rows === rows,
      "The terminal open response is invalid.");
  };
  const api: TerminalApi = {
    open: opening("terminal_open"),
    openTab: opening("terminal_open_tab"),
    poll: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid terminal poll request.");
      const [tab, maximumEvents, maximumBytes] = values;
      if (!isTerminalTabName(tab) || !isTerminalPollBounds(maximumEvents, maximumBytes)) {
        refuse("Invalid terminal poll request.");
      }
      return checked("terminal_poll", { tab, maximumEvents, maximumBytes }, TERMINAL_TIMEOUT_MS, isTerminalPoll,
        "The terminal poll response is invalid.");
    },
    input: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid terminal input request.");
      const [tab, bytesBase64] = values;
      const decoded = terminalBase64DecodedLength(bytesBase64, TERMINAL_LIMITS.maximumInputBytes, false);
      if (!isTerminalTabName(tab) || decoded === null) refuse("Invalid terminal input request.");
      return checked("terminal_input", { tab, bytesBase64 }, TERMINAL_TIMEOUT_MS,
        (value) => isTerminalInputAcknowledgement(value) && value.acceptedBytes === decoded,
        "The terminal input response is invalid.");
    },
    resize: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid terminal resize request.");
      const [tab, columns, rows] = values;
      if (!isTerminalTabName(tab) || !isTerminalSize(columns, rows)) refuse("Invalid terminal resize request.");
      return checked("terminal_resize", { tab, columns, rows }, TERMINAL_TIMEOUT_MS,
        (value) => isTerminalResized(value) && value.columns === columns && value.rows === rows,
        "The terminal resize response is invalid.");
    },
    search: async (...values: unknown[]) => {
      requireArity(values, 5, "Invalid terminal search request.");
      const [tab, query, caseSensitive, regex, maximumResults] = values;
      if (!isTerminalTabName(tab) || !isTerminalSearchRequest(query, maximumResults) ||
        typeof caseSensitive !== "boolean" || typeof regex !== "boolean") {
        refuse("Invalid terminal search request.");
      }
      return checked("terminal_search", { tab, query, caseSensitive, regex, maximumResults }, TERMINAL_TIMEOUT_MS,
        isTerminalSearch, "The terminal search response is invalid.");
    },
    copySelection: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid terminal selection copy request.");
      if (!isTerminalSelectionCopyText(values[0])) refuse("Invalid terminal selection copy request.");
      await invokeHost("terminal_copy_selection", { text: values[0] }, TERMINAL_TIMEOUT_MS);
    },
    aiAssist: async (...values: unknown[]) => {
      requireArity(values, 1, "AI 解读请求无效。");
      const request = values[0];
      if (!isAiAssistRequest(request) || (request.action === "start" && request.task !== "explain-terminal")) {
        refuse("AI 解读请求无效。");
      }
      return checked("terminal_ai_assist", { request }, AI_ASSIST_TIMEOUT_MS,
        (value) => matchesAiAssistResponse(request, value), "AI 解读返回了无法核实的结果，请重试。");
    },
    closeTab: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid terminal close request.");
      if (!isTerminalTabName(values[0])) refuse("Invalid terminal close request.");
      return checked("terminal_close_tab", { tab: values[0] }, TERMINAL_TIMEOUT_MS, isTerminalClosed,
        "The terminal close response is invalid.");
    },
    close: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid terminal close request.");
      return checked("terminal_close", {}, TERMINAL_TIMEOUT_MS, isTerminalClosed, "The terminal close response is invalid.");
    },
    openSftpBrowser: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid SFTP browser request.");
      return checked("sftp_open", {}, SFTP_BROWSER_TIMEOUT_MS, isSftpDirectorySnapshot, "The SFTP directory is invalid.");
    },
    listSftpDirectory: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid SFTP directory request.");
      const [browserHandle, directoryHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(directoryHandle)) {
        refuse("Invalid SFTP directory request.");
      }
      return checked("sftp_list", { browserHandle, directoryHandle }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => isSftpDirectorySnapshot(value) && value.browserHandle === browserHandle &&
          value.directoryHandle === directoryHandle,
        "The SFTP directory is invalid.");
    },
    readSftpText: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid SFTP preview request.");
      const [browserHandle, fileHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(fileHandle)) {
        refuse("Invalid SFTP preview request.");
      }
      return checked("sftp_read_text", { browserHandle, fileHandle }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => isSftpTextPreview(value) && value.browserHandle === browserHandle && value.fileHandle === fileHandle,
        "The SFTP preview is invalid.");
    },
    downloadSftpEntry: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid SFTP download request.");
      const [browserHandle, fileHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(fileHandle)) {
        refuse("Invalid SFTP download request.");
      }
      return checked("sftp_download", { browserHandle, fileHandle }, DIALOG_TIMEOUT_MS,
        (value) => record(value) && Object.keys(value).length === 3 && typeof value.saved === "boolean" &&
          (value.saved
            ? typeof value.fileName === "string" && typeof value.bytes === "string"
            : value.fileName === null && value.bytes === null),
        "The SFTP transfer result is invalid.");
    },
    downloadSftpDirectory: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid SFTP directory download request.");
      const [browserHandle, directoryHandle, defaultName, extract] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(directoryHandle) ||
        typeof defaultName !== "string" || defaultName.length === 0 ||
        new TextEncoder().encode(defaultName).byteLength > 128 ||
        typeof extract !== "boolean") {
        refuse("Invalid SFTP directory download request.");
      }
      return checked("sftp_download_directory",
        { browserHandle, directoryHandle, defaultName, extract }, DIALOG_TIMEOUT_MS,
        isSftpDirectoryDownloadResult, "The SFTP transfer result is invalid.");
    },
    prepareSftpDirectoryUpload: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP directory upload request.");
      const [browserHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle)) {
        refuse("Invalid SFTP directory upload request.");
      }
      return checked("sftp_upload_directory_prepare", { browserHandle }, DIALOG_TIMEOUT_MS,
        isSftpDirectoryUploadPrepare, "The SFTP upload preview is invalid.");
    },
    runSftpDirectoryUpload: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid SFTP directory upload request.");
      const [browserHandle, directoryHandle, stagedHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(directoryHandle) ||
        !isSftpBrowserOpaqueHandle(stagedHandle)) {
        refuse("Invalid SFTP directory upload request.");
      }
      return checked("sftp_upload_directory_run",
        { browserHandle, directoryHandle, stagedHandle }, SFTP_BROWSER_TIMEOUT_MS,
        isSftpDirectoryUploadResult, "The SFTP upload result is invalid.");
    },
    discardSftpDirectoryUpload: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP directory upload request.");
      const [stagedHandle] = values;
      if (!isSftpBrowserOpaqueHandle(stagedHandle)) {
        refuse("Invalid SFTP directory upload request.");
      }
      return checked("sftp_upload_directory_discard", { stagedHandle }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => record(value) && Object.keys(value).length === 1 && value.discarded === true,
        "The SFTP upload discard result is invalid.");
    },
    queueSftpDownload: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid SFTP queue download request.");
      const [browserHandle, fileHandles, rateLimitKiB] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !Array.isArray(fileHandles) ||
        fileHandles.length === 0 || fileHandles.length > 64 ||
        !fileHandles.every(isSftpBrowserOpaqueHandle) ||
        typeof rateLimitKiB !== "number" || !Number.isInteger(rateLimitKiB) ||
        rateLimitKiB < 0 || rateLimitKiB > 4 * 1024 * 1024) {
        refuse("Invalid SFTP queue download request.");
      }
      return checked("sftp_queue_download", { browserHandle, fileHandles, rateLimitKiB },
        DIALOG_TIMEOUT_MS, isSftpQueueEnqueueResult, "The SFTP queue result is invalid.");
    },
    queueSftpUpload: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid SFTP queue upload request.");
      const [browserHandle, directoryHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(directoryHandle)) {
        refuse("Invalid SFTP queue upload request.");
      }
      return checked("sftp_queue_upload", { browserHandle, directoryHandle },
        DIALOG_TIMEOUT_MS, isSftpQueueEnqueueResult, "The SFTP queue result is invalid.");
    },
    pollSftpQueue: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP queue request.");
      const [browserHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle)) refuse("Invalid SFTP queue request.");
      return checked("sftp_queue_poll", { browserHandle }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => value === null || isSftpTransferQueue(value), "The SFTP queue state is invalid.");
    },
    cancelSftpQueue: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP queue cancellation.");
      const [browserHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle)) refuse("Invalid SFTP queue cancellation.");
      return checked("sftp_queue_cancel_all", { browserHandle }, SFTP_BROWSER_TIMEOUT_MS,
        isSftpTransferCancelResult, "The SFTP queue cancellation is invalid.");
    },
    retrySftpQueueItem: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid SFTP queue retry request.");
      const [browserHandle, itemId] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || typeof itemId !== "number" ||
        !Number.isInteger(itemId) || itemId < 0) {
        refuse("Invalid SFTP queue retry request.");
      }
      return checked("sftp_queue_retry", { browserHandle, itemId }, SFTP_BROWSER_TIMEOUT_MS,
        isSftpTransferQueue, "The SFTP queue result is invalid.");
    },
    listSftpRelayTargets: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP relay request.");
      const [browserHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle)) refuse("Invalid SFTP relay request.");
      return checked("sftp_relay_targets", { browserHandle }, SFTP_BROWSER_TIMEOUT_MS,
        isSftpRelayTargetList, "The SFTP relay target list is invalid.");
    },
    startSftpRelay: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid SFTP relay request.");
      const [browserHandle, fileHandle, connectionId, destDir] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(fileHandle) ||
        !isSftpBrowserOpaqueHandle(connectionId) || typeof destDir !== "string" ||
        !destDir.startsWith("/") || destDir.length > 4096) {
        refuse("Invalid SFTP relay request.");
      }
      return checked("sftp_relay_start", { browserHandle, fileHandle, connectionId, destDir },
        SFTP_BROWSER_TIMEOUT_MS, isSftpRelay, "The SFTP relay result is invalid.");
    },
    pollSftpRelay: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid SFTP relay request.");
      const [browserHandle, relayHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(relayHandle)) {
        refuse("Invalid SFTP relay request.");
      }
      return checked("sftp_relay_poll", { browserHandle, relayHandle }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => value === null || isSftpRelay(value), "The SFTP relay state is invalid.");
    },
    cancelSftpRelay: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid SFTP relay cancellation.");
      const [browserHandle, relayHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(relayHandle)) {
        refuse("Invalid SFTP relay cancellation.");
      }
      return checked("sftp_relay_cancel", { browserHandle, relayHandle }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => value === null || isSftpRelay(value), "The SFTP relay result is invalid.");
    },
    planSftpOperation: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid SFTP operation request.");
      const [browserHandle, input] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpOperationInput(input)) {
        refuse("Invalid SFTP operation request.");
      }
      return checked("sftp_plan", { browserHandle, input }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => isSftpOperationPlan(value) && value.browserHandle === browserHandle && value.kind === input.kind,
        "The SFTP operation plan is invalid.");
    },
    confirmSftpOperation: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP confirmation request.");
      const planHandle = values[0];
      if (!isSftpBrowserOpaqueHandle(planHandle)) refuse("Invalid SFTP confirmation request.");
      return checked("sftp_confirm", { planHandle }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => isSftpOperationPlan(value) && value.planHandle === planHandle && value.state === "confirmed",
        "The SFTP operation plan is invalid.");
    },
    executeSftpOperation: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP execution request.");
      const planHandle = values[0];
      if (!isSftpBrowserOpaqueHandle(planHandle)) refuse("Invalid SFTP execution request.");
      return checked("sftp_execute", { planHandle }, SFTP_OPERATION_TIMEOUT_MS,
        (value) => isSftpOperationReceipt(value) && value.planHandle === planHandle,
        "The SFTP operation receipt is invalid.");
    },
    cancelSftpOperation: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP cancellation request.");
      if (!isSftpBrowserOpaqueHandle(values[0])) refuse("Invalid SFTP cancellation request.");
      return checked("sftp_cancel", { planHandle: values[0] }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => record(value) && value.cancelled === true, "The SFTP cancellation is invalid.");
    },
    cancelSftpTransfer: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP transfer cancellation.");
      const browserHandle = values[0];
      if (!isSftpBrowserOpaqueHandle(browserHandle)) refuse("Invalid SFTP transfer cancellation.");
      return checked("sftp_cancel_transfer", { browserHandle }, SFTP_BROWSER_TIMEOUT_MS,
        isSftpTransferCancelResult, "The SFTP transfer cancellation is invalid.");
    },
    undoSftpOperation: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP undo request.");
      const planHandle = values[0];
      if (!isSftpBrowserOpaqueHandle(planHandle)) refuse("Invalid SFTP undo request.");
      return checked("sftp_undo", { planHandle }, SFTP_OPERATION_TIMEOUT_MS,
        (value) => isSftpOperationUndoResult(value) && value.planHandle === planHandle,
        "The SFTP undo result is invalid.");
    },
    stageSftpUpload: async (...values: unknown[]) => {
      if (values.length > 1) refuse("Invalid SFTP staging request.");
      const localFileHandle = values[0];
      if (localFileHandle !== undefined && !isLocalBrowserOpaqueHandle(localFileHandle)) {
        refuse("Invalid SFTP staging request.");
      }
      return checked("sftp_stage_upload", { localFileHandle: localFileHandle ?? null }, DIALOG_TIMEOUT_MS,
        (value) => record(value) && (value.staged === true
          ? isSftpStagedUpload(value.upload)
          : value.staged === false && value.upload === null),
        "The staged upload is invalid.");
    },
    openLocalBrowser: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid local browser request.");
      return checked("local_open", {}, TERMINAL_TIMEOUT_MS, isLocalDirectorySnapshot, "Invalid local directory listing.");
    },
    listLocalDirectory: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid local directory request.");
      if (!isLocalBrowserOpaqueHandle(values[0])) refuse("Invalid local directory request.");
      return checked("local_list", { directoryHandle: values[0] }, TERMINAL_TIMEOUT_MS, isLocalDirectorySnapshot,
        "Invalid local directory listing.");
    },
    localScan: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid local scan request.");
      if (!isLocalScanChildRequest(values[0])) refuse("Invalid local scan request.");
      const request = values[0] as LocalScanChildRequest;
      const command = request.action === "configure" ? "local_scan_child_configure" : "local_scan_child";
      const timeoutMs = request.action === "configure" ||
        request.action === "fetch-browser" ? DIALOG_TIMEOUT_MS : TERMINAL_TIMEOUT_MS;
      const value = await invokeHost(command, { request }, timeoutMs);
      // Null means the system program dialog was cancelled.
      if (!matchesLocalScanResult(request, value)) refuse("The local scan result is invalid.");
      return value;
    },
    openFileEditor: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid file editor launch request.");
      const [browserHandle, entryHandle, name, editable] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(entryHandle) ||
        typeof name !== "string" || name.length === 0 || name.length > 255 || typeof editable !== "boolean") {
        refuse("Invalid file editor launch request.");
      }
      return checked("file_editor_open", { browserHandle, entryHandle, name, editable }, TERMINAL_TIMEOUT_MS,
        isTerminalWindowLaunchResult, "The file editor launch result is invalid.");
    },
    openDirectoryTerminal: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid directory terminal request.");
      const [browserHandle, directoryHandle, name] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(directoryHandle) ||
        typeof name !== "string" || name.length === 0 || name.length > 255) {
        refuse("Invalid directory terminal request.");
      }
      return checked("directory_terminal_open", { browserHandle, directoryHandle, name }, TERMINAL_TIMEOUT_MS,
        isTerminalWindowLaunchResult, "The directory terminal launch result is invalid.");
    },
    fileEditorTarget: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid file editor target request.");
      return checked("file_editor_target", {}, TERMINAL_TIMEOUT_MS, isFileEditorTarget, "The file editor target is invalid.");
    },
    setUnsavedChanges: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid unsaved-changes report.");
      if (typeof values[0] !== "boolean") refuse("Invalid unsaved-changes report.");
      await invokeHost("file_editor_unsaved", { unsaved: values[0] }, TERMINAL_TIMEOUT_MS);
    },
    onBeforeClose: (handler: () => Promise<boolean>) => {
      if (typeof handler !== "function") refuse("Invalid close handler.");
      let disposed = false;
      let unlisten: (() => void) | null = null;
      void listen(BEFORE_CLOSE_EVENT, (event) => {
        // Numbered by the host, so a late answer cannot decide a newer close.
        const request = (event.payload as { request?: unknown } | null)?.request;
        if (typeof request !== "number" || !Number.isSafeInteger(request) || request < 1) return;
        void handler().then(
          (allowed) => invokeHost("child_close_decision", { request, allowed: allowed === true }, TERMINAL_TIMEOUT_MS),
          () => invokeHost("child_close_decision", { request, allowed: false }, TERMINAL_TIMEOUT_MS),
        ).catch(() => undefined);
      }).then((stop) => {
        if (disposed) stop();
        else unlisten = stop;
      }, () => undefined);
      return () => {
        disposed = true;
        unlisten?.();
      };
    },
  } as TerminalApi;
  return Object.freeze(api);
}
