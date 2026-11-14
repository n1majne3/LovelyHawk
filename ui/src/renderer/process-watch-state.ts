import type {
  ProcessWatchCleanup,
  ProcessWatchEvent,
  ProcessWatchGap,
  ProcessWatchMethod,
  ProcessWatchPoll,
  ProcessWatchProbe,
  ProcessWatchResidue,
  ProcessWatchSummary,
  ProcessWatchTool,
  ProcessWatchUnparsed,
  ProcessWatchUploadPlan,
} from "../shared/process-watch-contract";

/** The panel's own machine, deliberately one step per button press. */
export type ProcessWatchUiStatus =
  | "probing"
  | "ready"
  /** Reading the target to describe an upload run; nothing written yet. */
  | "planning"
  /** The upload plan is on screen, waiting for this run's confirmation. */
  | "confirming"
  | "starting"
  | "running"
  | "stopping"
  | "finished"
  | "cancelled"
  | "truncated"
  | "failed"
  | "disconnected";

export const PROCESS_WATCH_DURATIONS = [60, 120, 180, 300, 600, 1_800] as const;
export const PROCESS_WATCH_INTERVALS = [200, 500, 1_000] as const;
export const DEFAULT_PROCESS_WATCH_DURATION = 180;
export const DEFAULT_PROCESS_WATCH_INTERVAL = 500;
/** How many rows a page of the timeline renders; the backend keeps 20_000. */
export const PROCESS_WATCH_PAGE_ROWS = 200;

export interface ProcessWatchState {
  /** The target this state belongs to; anything older is dropped on sight. */
  scope: string;
  status: ProcessWatchUiStatus;
  probe: ProcessWatchProbe | null;
  probeError: string | null;
  durationSeconds: number;
  intervalMs: number;
  watchHandle: string | null;
  gaps: ProcessWatchGap[];
  cursor: number;
  elapsedSeconds: number;
  selfEndsAtMs: number;
  events: ProcessWatchEvent[];
  unparsed: ProcessWatchUnparsed[];
  observedCount: number;
  baselineCount: number;
  ownCount: number;
  unparsedCount: number;
  truncated: boolean;
  stopVerified: boolean | null;
  summary: ProcessWatchSummary | null;
  failure: string | null;
  showBaseline: boolean;
  showOwn: boolean;
  filter: string;
  filterUid: string;
  groupFilter: string | null;
  page: number;
  method: ProcessWatchMethod;
  tool: ProcessWatchTool | null;
  fileEvents: boolean;
  plan: ProcessWatchUploadPlan | null;
  /** The operator ticked "run it anyway" for a file no release digest matches. */
  unknownAccepted: boolean;
  /** How removing the uploaded program ended; null until an upload run ends. */
  cleanup: ProcessWatchCleanup | null;
  residues: ProcessWatchResidue[];
  showFiles: boolean;
}

export type ProcessWatchAction =
  | { type: "method-changed"; value: ProcessWatchMethod }
  | { type: "tool-picked"; tool: ProcessWatchTool }
  | { type: "file-events-toggled" }
  | { type: "unknown-accepted-toggled" }
  | { type: "plan-started" }
  | { type: "plan-loaded"; plan: ProcessWatchUploadPlan }
  | { type: "plan-failed"; error: string }
  | { type: "plan-dismissed" }
  | { type: "residues-loaded"; residues: ProcessWatchResidue[] }
  | { type: "cleanup-known"; cleanup: ProcessWatchCleanup | null }
  | { type: "resumed"; watchHandle: string }
  | { type: "resume-failed" }
  | { type: "restarted" }
  | { type: "files-toggled" }
  | { type: "probe-loaded"; probe: ProcessWatchProbe }
  | { type: "probe-failed"; error: string }
  | { type: "duration-changed"; value: number }
  | { type: "interval-changed"; value: number }
  | { type: "start-started" }
  | {
      type: "start-loaded";
      watchHandle: string;
      gaps: ProcessWatchGap[];
    }
  | { type: "start-failed"; error: string }
  | { type: "poll-loaded"; result: ProcessWatchPoll }
  | { type: "poll-failed"; error: string }
  | { type: "stop-started" }
  | { type: "summary-loaded"; summary: ProcessWatchSummary }
  | { type: "baseline-toggled" }
  | { type: "own-toggled" }
  | { type: "filter-changed"; value: string }
  | { type: "uid-filter-changed"; value: string }
  | { type: "group-filter-set"; value: string | null }
  | { type: "page-changed"; value: number };

export function createProcessWatchState(scope: string): ProcessWatchState {
  return {
    scope,
    status: "probing",
    probe: null,
    probeError: null,
    durationSeconds: DEFAULT_PROCESS_WATCH_DURATION,
    intervalMs: DEFAULT_PROCESS_WATCH_INTERVAL,
    watchHandle: null,
    gaps: [],
    cursor: 0,
    elapsedSeconds: 0,
    selfEndsAtMs: 0,
    events: [],
    unparsed: [],
    observedCount: 0,
    baselineCount: 0,
    ownCount: 0,
    unparsedCount: 0,
    truncated: false,
    stopVerified: null,
    summary: null,
    failure: null,
    showBaseline: false,
    showOwn: false,
    filter: "",
    filterUid: "",
    groupFilter: null,
    page: 0,
    method: "proc-poll",
    tool: null,
    fileEvents: false,
    plan: null,
    unknownAccepted: false,
    cleanup: null,
    residues: [],
    showFiles: true,
  };
}

/** Whether the confirm button of an upload plan may be pressed. */
export function canConfirmUpload(state: ProcessWatchState): boolean {
  return state.status === "confirming" && state.plan !== null &&
    (state.plan.recognized !== null || state.unknownAccepted);
}

export function processWatchReducer(
  state: ProcessWatchState,
  action: ProcessWatchAction,
): ProcessWatchState {
  switch (action.type) {
    case "probe-loaded":
      return { ...state, status: "ready", probe: action.probe, probeError: null };
    case "probe-failed":
      return { ...state, status: "ready", probe: null, probeError: action.error };
    case "duration-changed":
      if (!PROCESS_WATCH_DURATIONS.includes(action.value as 60)) return state;
      return { ...state, durationSeconds: action.value };
    case "interval-changed":
      if (!PROCESS_WATCH_INTERVALS.includes(action.value as 200)) return state;
      return { ...state, intervalMs: action.value };
    case "method-changed":
      if (state.status !== "ready") return state;
      return { ...state, method: action.value, failure: null };
    case "tool-picked":
      if (state.status !== "ready") return state;
      return { ...state, tool: action.tool, unknownAccepted: false, failure: null };
    case "file-events-toggled":
      if (state.status !== "ready") return state;
      return { ...state, fileEvents: !state.fileEvents };
    case "unknown-accepted-toggled":
      if (state.status !== "confirming") return state;
      return { ...state, unknownAccepted: !state.unknownAccepted };
    case "plan-started":
      if (state.status !== "ready" || state.method !== "pspy" || state.tool === null) return state;
      return { ...state, status: "planning", plan: null, unknownAccepted: false, failure: null };
    case "plan-loaded":
      if (state.status !== "planning") return state;
      return { ...state, status: "confirming", plan: action.plan };
    case "plan-failed":
      if (state.status !== "planning") return state;
      return { ...state, status: "ready", plan: null, failure: action.error };
    case "plan-dismissed":
      if (state.status !== "confirming" && state.status !== "planning") return state;
      return { ...state, status: "ready", plan: null, unknownAccepted: false };
    case "residues-loaded":
      return { ...state, residues: action.residues };
    case "cleanup-known":
      // A verified clean answer is final; anything else may still improve.
      if (state.cleanup === "clean" || action.cleanup === null) return state;
      return { ...state, cleanup: action.cleanup };
    case "resumed":
      if (state.status !== "ready" && state.status !== "probing") return state;
      return { ...state, status: "running", watchHandle: action.watchHandle, cursor: 0 };
    case "resume-failed":
      if (state.events.length > 0 || state.status !== "running") return state;
      return { ...state, status: "ready", watchHandle: null, failure: null };
    case "restarted":
      // Only a run that is over can be left behind for a new one.
      if (state.status !== "finished" && state.status !== "cancelled" &&
        state.status !== "truncated" && state.status !== "failed" &&
        state.status !== "disconnected") {
        return state;
      }
      return {
        ...createProcessWatchState(state.scope),
        status: "ready",
        probe: state.probe,
        durationSeconds: state.durationSeconds,
        intervalMs: state.intervalMs,
        method: state.method,
        tool: state.tool,
        fileEvents: state.fileEvents,
        residues: state.residues,
      };
    case "files-toggled":
      return { ...state, showFiles: !state.showFiles, page: 0 };
    case "start-started":
      if (state.status === "confirming") {
        // An upload run starts only from a plan that may be confirmed.
        return canConfirmUpload(state) ? { ...state, status: "starting", failure: null } : state;
      }
      if (state.status !== "ready" || state.method !== "proc-poll") return state;
      return { ...state, status: "starting", failure: null };
    case "start-loaded":
      if (state.status !== "starting") return state;
      return {
        ...state,
        status: "running",
        watchHandle: action.watchHandle,
        gaps: action.gaps,
        plan: null,
        cleanup: null,
        cursor: 0,
        events: [],
        unparsed: [],
        observedCount: 0,
        baselineCount: 0,
        ownCount: 0,
        unparsedCount: 0,
        truncated: false,
        stopVerified: null,
        summary: null,
        failure: null,
        showBaseline: false,
        showOwn: false,
        groupFilter: null,
        page: 0,
      };
    case "start-failed":
      if (state.status !== "starting") return state;
      // A plan is spent by its one start, whether or not the start worked.
      return { ...state, status: "ready", plan: null, unknownAccepted: false, failure: action.error };
    case "poll-loaded": {
      if (state.watchHandle === null || action.result.watchHandle !== state.watchHandle) {
        return state;
      }
      const next: ProcessWatchState = {
        ...state,
        cursor: action.result.nextCursor,
        elapsedSeconds: action.result.elapsedSeconds,
        selfEndsAtMs: action.result.selfEndsAtMs,
        observedCount: action.result.observedCount,
        baselineCount: action.result.baselineCount,
        ownCount: action.result.ownCount,
        unparsedCount: action.result.unparsedCount,
        truncated: action.result.truncated,
        stopVerified: action.result.stopVerified,
        cleanup: state.cleanup === "clean" ? state.cleanup : action.result.cleanup ?? state.cleanup,
        gaps: action.result.gaps,
        events: [...state.events, ...action.result.events],
        unparsed: [...state.unparsed, ...action.result.unparsed],
      };
      if (action.result.state !== "running") {
        next.status = action.result.state;
      }
      return next;
    }
    case "poll-failed":
      // A lost poll during a live watch leaves the watch running; the next
      // poll either recovers or the watch is reported gone.
      if (state.status !== "running" && state.status !== "stopping") return state;
      return { ...state, failure: action.error };
    case "stop-started":
      if (state.status !== "running") return state;
      return { ...state, status: "stopping" };
    case "summary-loaded":
      if (state.watchHandle === null) return state;
      return { ...state, summary: action.summary };
    case "baseline-toggled":
      return { ...state, showBaseline: !state.showBaseline, page: 0 };
    case "own-toggled":
      return { ...state, showOwn: !state.showOwn, page: 0 };
    case "filter-changed":
      return { ...state, filter: action.value, groupFilter: null, page: 0 };
    case "uid-filter-changed":
      return { ...state, filterUid: action.value, page: 0 };
    case "group-filter-set":
      return { ...state, groupFilter: action.value, filter: "", page: 0 };
    case "page-changed":
      return { ...state, page: Math.max(0, action.value) };
    default:
      return state;
  }
}

/** The timeline's default slice: only what newly started, tool noise aside. */
export function visibleWatchEvents(state: ProcessWatchState): ProcessWatchEvent[] {
  let rows = state.events;
  if (!state.showBaseline) rows = rows.filter((event) => event.origin !== "baseline");
  if (!state.showOwn) rows = rows.filter((event) => !event.own);
  if (!state.showFiles) rows = rows.filter((event) => event.kind !== "file");
  if (state.groupFilter !== null) {
    const needle = state.groupFilter;
    rows = rows.filter((event) => event.command === needle);
  } else {
    const needle = state.filter.trim().toLowerCase();
    if (needle !== "") {
      rows = rows.filter((event) => event.command.toLowerCase().includes(needle));
    }
  }
  const uid = state.filterUid.trim();
  if (uid !== "" && /^\d+$/u.test(uid)) {
    const want = Number.parseInt(uid, 10);
    rows = rows.filter((event) => event.uid === want);
  }
  return rows;
}

/**
 * The one-sentence verdict a new operator reads first. It never says "no
 * activity" when the run had gaps, truncation, unparsed rows, or a disconnect —
 * "未观察到" with the gap named is the honest version.
 */
export function processWatchConclusion(state: ProcessWatchState): string {
  const incomplete = state.gaps.length > 0 || state.truncated ||
    state.cleanup === "residue" || state.cleanup === "unverified" ||
    state.unparsedCount > 0 || state.status === "truncated" ||
    state.status === "failed" || state.status === "disconnected";
  const minutes = Math.max(1, Math.round(state.elapsedSeconds / 60)) ||
    Math.max(1, Math.round(state.durationSeconds / 60));
  if (state.status === "cancelled") {
    return `这次监视在 ${state.elapsedSeconds} 秒时被取消，结果不完整：已观察到 ${state.observedCount} 个新进程。`;
  }
  if (state.status === "failed") {
    return `监视没有完成：已观察到 ${state.observedCount} 个新进程，结论不完整，见上方缺口说明。`;
  }
  if (state.status === "disconnected") {
    return `监视中途与目标断开：已收到 ${state.observedCount} 个新进程，之后的情况未知。`;
  }
  const periodic = state.summary?.periodicGroups ?? 0;
  const repeated = (state.summary?.repeatedGroups ?? 0) + periodic;
  if (state.observedCount === 0) {
    return incomplete
      ? `这 ${minutes} 分钟未观察到新进程（采集有缺口，见下方说明），不能据此认为没有活动。`
      : `这 ${minutes} 分钟未观察到新进程。没观察到不代表没有，请结合其他检查。`;
  }
  const tail = repeated > 0
    ? `，其中 ${repeated} 条命令重复出现${periodic > 0 ? "（含间隔稳定的周期性命令）" : ""}`
    : "";
  const incompleteNote = incomplete ? "；采集有缺口，见下方说明" : "";
  return `这 ${minutes} 分钟里观察到 ${state.observedCount} 个新进程${tail}${incompleteNote}。可去“计划任务”项核对来源。`;
}
