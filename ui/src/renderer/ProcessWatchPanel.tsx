import { useEffect, useMemo, useReducer, useRef, useState } from "react";

import type {
  ProcessWatchAccounting,
  ProcessWatchApi,
  ProcessWatchCleanup,
  ProcessWatchSource,
  ProcessWatchSourceKind,
  ProcessWatchEvent,
  ProcessWatchGap,
  ProcessWatchOrigin,
  ProcessWatchResidue,
  ProcessWatchUploadPlan,
} from "../shared/process-watch-contract";
import {
  canConfirmUpload,
  createProcessWatchState,
  processWatchConclusion,
  processWatchReducer,
  PROCESS_WATCH_DURATIONS,
  PROCESS_WATCH_INTERVALS,
  PROCESS_WATCH_PAGE_ROWS,
  visibleWatchEvents,
  type ProcessWatchAction,
  type ProcessWatchState,
} from "./process-watch-state";
import { useModalScrim } from "./modal-scrim";
import "./emergency-path.css";
import "./process-watch.css";

export interface ProcessWatchPanelProps {
  api: ProcessWatchApi;
  bindingHandle: string;
  writeClipboard?: ((text: string) => Promise<void>) | undefined;
  returnFocus?: HTMLElement | null;
  /** A watch this binding started earlier and whose result is still kept. */
  resumeHandle?: string | null;
  /** Told whenever the panel has a watch worth coming back to, or loses it. */
  onWatchHandle?: ((watchHandle: string | null) => void) | undefined;
  /** Opens the workbench entry with this title; the panel closes first. */
  onOpenEntry?: ((title: string) => void) | undefined;
  onClose: () => void;
}

const GAP_TEXT: Record<ProcessWatchGap, string> = {
  "hidepid": "这台主机限制了进程信息，只能看到当前账号的进程。",
  "container": "当前环境是容器，只能看到容器里的进程，看不到宿主机和其他容器里的。",
  "coarse-interval": "这台主机不支持更短的间隔，只能每秒扫描一次，更容易漏掉短命进程。",
  "proc-unreadable": "这台主机上的进程列表读不了。",
  "polling-misses-short-lived": "两次扫描之间启动并退出的进程会漏掉，这是这种监视方式固有的限制。",
  "already-running": "这台主机上似乎已有一个相同的监视在运行（可能来自另一个窗口），请稍后再试。",
  "tool-may-miss-short-lived": "pspy 靠文件访问触发扫描，比定时扫描漏得少，但极短的进程仍可能看不到，有时只看到进程号而看不到命令。",
  "inotify-low": "这台主机的文件监视配额很小，pspy 能监视的目录有限，更容易漏掉进程。",
  "file-events-limited": "文件访问只记录 /etc、/tmp、/var/tmp、/dev/shm、计划任务目录和 /var/www；此时 pspy 也只靠这些目录触发扫描，别处启动的短命进程更容易漏掉。",
};

const STATE_LABEL: Record<string, string> = {
  finished: "已结束",
  cancelled: "已取消",
  truncated: "已达上限提前结束",
  failed: "失败",
  disconnected: "连接中断",
};

const ORIGIN_LABEL: Record<ProcessWatchOrigin, string> = {
  cron: "计划任务派生",
  ssh: "SSH 登录派生",
  service: "Web/数据库服务派生",
  other: "其他（由系统启动的进程派生）",
  unknown: "来源未知（父进程没有被看到）",
};

const CLEANUP_TEXT: Record<ProcessWatchCleanup, string> = {
  clean: "上传的程序已停止并删除，已回读确认目标上没有它的进程和文件。",
  residue: "清理后目标上仍有残留，没有清干净。请重新打开本面板，在“上次监视的残留”里再清理一次。",
  unverified: "没能连到目标确认清理结果，上传的程序可能还留在目标上。重新连接后打开本面板，会在“上次监视的残留”里列出。",
};

const SOURCE_LABEL: Record<ProcessWatchSourceKind, string> = {
  "accounting": "进程记账（记录已结束进程的程序名，不含参数）",
  "audit-execve": "审计规则（记录执行过的命令）",
  "execsnoop": "execsnoop",
  "bpftrace": "bpftrace",
};

/** What a detected source means here; reading is offered only for accounting. */
function sourceText(source: ProcessWatchSource): string {
  const name = SOURCE_LABEL[source.source];
  if (source.source === "accounting") {
    if (source.state === "readable") return `${name}：正在记录，可以直接读取，不需要运行任何东西。`;
    if (source.state === "unreadable") return `${name}：有记录，但当前账号没有权限读取。`;
    return `${name}：已安装，但没有发现正在记录的文件。本工具不会替你开启。`;
  }
  if (source.source === "audit-execve") {
    return source.state === "readable"
      ? `${name}：已启用。本工具暂不读取，可在终端用 ausearch 查看。`
      : `${name}：已安装审计工具，但没有发现记录命令执行的规则。`;
  }
  return `${name}：已安装。需要 root 手动运行，本工具暂不调用。`;
}

const ACCOUNTING_WINDOWS = [5, 15, 60] as const;

const POLL_EVERY_MS = 1_000;
const POLL_LIMIT = 500;

function formatClock(atMs: number): string {
  return new Date(atMs).toLocaleTimeString("zh-CN", { hour12: false });
}

function formatInterval(periodMs: number): string {
  const seconds = Math.round(periodMs / 1_000);
  if (seconds < 90) return `约每 ${seconds} 秒一次`;
  return `约每 ${Math.round(seconds / 60)} 分钟一次`;
}

function formatBytes(size: number): string {
  return size >= 1_048_576 ? `${(size / 1_048_576).toFixed(1)} MB` : `${Math.ceil(size / 1_024)} KB`;
}

function reasonText(reason: unknown): string {
  return String(reason instanceof Error ? reason.message : reason);
}

type View = "timeline" | "repeated" | "origins" | "checks";

/**
 * The watch stops before anything else happens — close, page leave and
 * window close all go through `requestClose` or the unmount stop, so nothing
 * keeps running on the target after this panel is gone.
 */
export function ProcessWatchPanel({
  api,
  bindingHandle,
  writeClipboard,
  returnFocus = null,
  resumeHandle = null,
  onWatchHandle,
  onOpenEntry,
  onClose,
}: ProcessWatchPanelProps) {
  useModalScrim();
  const [state, dispatch] = useReducer(
    processWatchReducer,
    bindingHandle,
    createProcessWatchState,
  );
  const [closing, setClosing] = useState(false);
  const [picking, setPicking] = useState(false);
  const [cleaning, setCleaning] = useState<string | null>(null);
  const [residueNote, setResidueNote] = useState<string | null>(null);
  const [view, setView] = useState<View>("timeline");
  const [sources, setSources] = useState<ProcessWatchSource[]>([]);
  const [accounting, setAccounting] = useState<ProcessWatchAccounting | null>(null);
  const [accountingBusy, setAccountingBusy] = useState(false);
  const [accountingError, setAccountingError] = useState<string | null>(null);
  const [accountingMinutes, setAccountingMinutes] = useState<number>(15);
  const stateRef = useRef(state);
  stateRef.current = state;
  const resumeRef = useRef(resumeHandle);
  const planHeading = useRef<HTMLHeadingElement>(null);

  // Probe once per binding. A probe answer for another scope is dropped.
  useEffect(() => {
    let cancelled = false;
    api.probeProcessWatch(bindingHandle).then(
      (probe) => {
        if (cancelled) return;
        dispatch({ type: "probe-loaded", probe });
        // A watch started before the panel was closed is picked up again;
        // its result is kept on the other side for a while.
        if (resumeRef.current !== null) dispatch({ type: "resumed", watchHandle: resumeRef.current });
      },
      (reason) => {
        if (!cancelled) dispatch({ type: "probe-failed", error: reasonText(reason) });
      },
    );
    api.listProcessWatchResidues(bindingHandle).then(
      (residues) => { if (!cancelled) dispatch({ type: "residues-loaded", residues }); },
      () => { /* a target that cannot be asked shows no residue list, not an empty one */ },
    );
    api.listProcessWatchSources(bindingHandle).then(
      (found) => { if (!cancelled) setSources(found.filter((source) => source.state !== "absent")); },
      () => undefined,
    );
    return () => { cancelled = true; };
  }, [api, bindingHandle]);

  // Poll while the watch is live. Late answers for a stale handle or cursor
  // are refused by the reducer's handle check before they can mix in.
  useEffect(() => {
    // "stopping" keeps polling: the final state and the stop check arrive
    // through the same poll, not through the stop call.
    if ((state.status !== "running" && state.status !== "stopping") || state.watchHandle === null) return;
    let cancelled = false;
    const tick = () => {
      const current = stateRef.current;
      if (current.watchHandle === null) return;
      api.pollProcessWatch(bindingHandle, current.watchHandle, current.cursor, POLL_LIMIT).then(
        (result) => { if (!cancelled) dispatch({ type: "poll-loaded", result }); },
        (reason) => {
          if (cancelled) return;
          // A resumed handle that is gone just means there is nothing to
          // come back to; the panel returns to its start screen.
          dispatch({ type: "resume-failed" });
          dispatch({ type: "poll-failed", error: reasonText(reason) });
        },
      );
    };
    tick();
    const timer = setInterval(tick, POLL_EVERY_MS);
    return () => { cancelled = true; clearInterval(timer); };
  }, [api, bindingHandle, state.status, state.watchHandle]);

  const terminal = state.status === "finished" || state.status === "cancelled" ||
    state.status === "truncated" || state.status === "failed" || state.status === "disconnected";

  // Once the run ends, ask for the analysis. One request, not a loop.
  useEffect(() => {
    if (state.watchHandle === null || !terminal) return;
    let cancelled = false;
    api.processWatchSummary(bindingHandle, state.watchHandle).then(
      (summary) => { if (!cancelled) dispatch({ type: "summary-loaded", summary }); },
      () => { /* the timeline still has the events; the verdict shows counts only */ },
    );
    return () => { cancelled = true; };
  }, [api, bindingHandle, state.watchHandle, terminal]);

  useEffect(() => {
    if (state.watchHandle !== null) onWatchHandle?.(state.watchHandle);
  }, [onWatchHandle, state.watchHandle]);

  const restart = () => {
    resumeRef.current = null;
    onWatchHandle?.(null);
    setView("timeline");
    dispatch({ type: "restarted" });
  };

  // The last-resort stop: unmount (page leave, window close) still ends the
  // remote run even though nothing here can wait for the answer.
  useEffect(() => {
    return () => {
      const current = stateRef.current;
      if (current.watchHandle !== null && current.status === "running") {
        void api.stopProcessWatch(bindingHandle, current.watchHandle).then(
          () => undefined,
          () => undefined,
        );
      }
    };
  }, [api, bindingHandle]);

  useEffect(() => {
    if (state.status === "confirming") planHeading.current?.focus();
  }, [state.status]);

  const requestClose = () => {
    const current = stateRef.current;
    if (current.status === "running" && current.watchHandle !== null) {
      setClosing(true);
      dispatch({ type: "stop-started" });
      void api.stopProcessWatch(bindingHandle, current.watchHandle).then(
        () => onClose(),
        () => onClose(),
      );
      return;
    }
    onClose();
  };

  useEffect(() => {
    if (returnFocus !== null) {
      return () => returnFocus.focus();
    }
  }, [returnFocus]);

  const started = (begin: Promise<{ watchHandle: string; gaps: ProcessWatchGap[] }>) => {
    begin.then(
      (result) => dispatch({ type: "start-loaded", watchHandle: result.watchHandle, gaps: result.gaps }),
      (reason) => dispatch({ type: "start-failed", error: reasonText(reason) }),
    );
  };

  const start = () => {
    dispatch({ type: "start-started" });
    started(api.startProcessWatch(bindingHandle, {
      durationSeconds: state.durationSeconds,
      intervalMs: state.intervalMs,
    }));
  };

  const pickTool = () => {
    if (picking) return;
    setPicking(true);
    api.pickProcessWatchTool().then(
      (tool) => {
        setPicking(false);
        if (tool !== null) dispatch({ type: "tool-picked", tool });
      },
      (reason) => {
        setPicking(false);
        dispatch({ type: "plan-started" });
        dispatch({ type: "plan-failed", error: reasonText(reason) });
      },
    );
  };

  const plan = () => {
    if (state.tool === null) return;
    dispatch({ type: "plan-started" });
    api.planProcessWatchUpload(bindingHandle, {
      toolHandle: state.tool.toolHandle,
      durationSeconds: state.durationSeconds,
      fileEvents: state.fileEvents,
    }).then(
      (loaded) => dispatch({ type: "plan-loaded", plan: loaded }),
      (reason) => dispatch({ type: "plan-failed", error: reasonText(reason) }),
    );
  };

  const confirmUpload = () => {
    if (!canConfirmUpload(state) || state.plan === null) return;
    const planHandle = state.plan.planHandle;
    dispatch({ type: "start-started" });
    started(api.startProcessWatchUpload(bindingHandle, planHandle));
  };

  const cancel = () => {
    if (state.watchHandle === null || state.status !== "running") return;
    dispatch({ type: "stop-started" });
    const handle = state.watchHandle;
    void api.stopProcessWatch(bindingHandle, handle).then(
      (stopped) => dispatch({ type: "cleanup-known", cleanup: stopped.cleanup }),
      (reason) => dispatch({ type: "poll-failed", error: reasonText(reason) }),
    );
  };

  const readAccounting = () => {
    if (accountingBusy) return;
    setAccountingBusy(true);
    setAccountingError(null);
    api.readProcessWatchAccounting(bindingHandle, accountingMinutes).then(
      (loaded) => { setAccountingBusy(false); setAccounting(loaded); },
      (reason) => { setAccountingBusy(false); setAccountingError(reasonText(reason)); },
    );
  };

  const cleanResidue = (residue: ProcessWatchResidue) => {
    if (cleaning !== null) return;
    setCleaning(residue.residueHandle);
    setResidueNote(null);
    const reload = () => api.listProcessWatchResidues(bindingHandle).then(
      (residues) => dispatch({ type: "residues-loaded", residues }),
      () => undefined,
    );
    api.cleanProcessWatchResidue(bindingHandle, residue.residueHandle).then(
      (outcome) => {
        setCleaning(null);
        setResidueNote(outcome === "clean"
          ? `已清理 ${residue.directory}，并回读确认目标上不再有它。`
          : `${residue.directory} 没有清干净：${CLEANUP_TEXT[outcome]}`);
        void reload();
      },
      (reason) => {
        setCleaning(null);
        setResidueNote(`没能清理 ${residue.directory}：${reasonText(reason)}`);
        void reload();
      },
    );
  };

  const rows = useMemo(() => visibleWatchEvents(state), [state]);
  const pageCount = Math.max(1, Math.ceil(rows.length / PROCESS_WATCH_PAGE_ROWS));
  const page = Math.min(state.page, pageCount - 1);
  const pageRows = rows.slice(page * PROCESS_WATCH_PAGE_ROWS, (page + 1) * PROCESS_WATCH_PAGE_ROWS);
  const fileEventCount = useMemo(
    () => state.events.filter((event) => event.kind === "file").length,
    [state.events],
  );

  const probeAgain = () => {
    dispatch({ type: "probe-failed", error: "正在重试…" });
    void api.probeProcessWatch(bindingHandle).then(
      (probe) => dispatch({ type: "probe-loaded", probe }),
      (reason) => dispatch({ type: "probe-failed", error: reasonText(reason) }),
    );
  };

  const setup = state.status === "ready" || state.status === "planning" || state.status === "starting";
  const blocked = state.probe !== null &&
    (state.probe.gaps.includes("already-running") || state.probe.gaps.includes("proc-unreadable"));

  return (
    <div className="emergency-path-backdrop" role="presentation">
      <section
        className="emergency-path-dialog process-watch-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="进程活动监视"
        data-testid="process-watch-dialog"
      >
        <header className="process-watch-header">
          <h2>进程活动监视</h2>
          <button type="button" className="process-watch-close" onClick={requestClose}
            disabled={closing} data-testid="process-watch-close">
            {closing ? "停止中…" : state.status === "running" ? "停止并关闭" : "关闭"}
          </button>
        </header>

        {state.status === "probing" ? (
          <p className="emergency-path-note" role="status">正在检查这台主机能否监视进程…</p>
        ) : state.probeError !== null ? (
          <div className="process-watch-ready">
            <p className="emergency-path-note" role="alert">
              没能检查这台主机的监视条件：{state.probeError}
            </p>
            <button type="button" onClick={probeAgain}>重试</button>
          </div>
        ) : null}

        {(setup || state.status === "confirming") && state.residues.length > 0 ? (
          <div className="process-watch-residues" data-testid="process-watch-residues">
            <h3>上次监视的残留</h3>
            <p className="emergency-path-note">
              目标上还留着以前上传的程序（通常是监视中途断开连接造成的）。确认不再需要后可以清理。
            </p>
            <ul>
              {state.residues.map((residue) => (
                <li key={residue.residueHandle}>
                  <code>{residue.directory}</code>
                  <span>
                    {residue.size > 0 ? `，${formatBytes(residue.size)}` : "，目录里没有程序文件"}
                    {residue.recognized !== null ? `，${residue.recognized}`
                      : residue.sha256 !== "" ? "，不是已知的 pspy 发布版本" : ""}
                    {residue.running ? "，仍在运行" : "，没有在运行"}
                  </span>
                  <button type="button" disabled={cleaning !== null}
                    onClick={() => cleanResidue(residue)} data-testid="process-watch-residue-clean">
                    {cleaning === residue.residueHandle ? "清理中…" : "停止并删除"}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {residueNote !== null ? (
          <p className="emergency-path-note" role="status" data-testid="process-watch-residue-note">{residueNote}</p>
        ) : null}

        {setup && sources.length > 0 ? (
          <div className="process-watch-sources" data-testid="process-watch-sources">
            <h3>这台主机已有的记录</h3>
            <ul>
              {sources.map((source) => (
                <li key={source.source} data-testid={`process-watch-source-${source.source}`}>{sourceText(source)}</li>
              ))}
            </ul>
            {sources.some((source) => source.source === "accounting" && source.state === "readable") ? (
              <div className="process-watch-options">
                <label>
                  读取最近
                  <select value={accountingMinutes} disabled={accountingBusy}
                    onChange={(event) => setAccountingMinutes(Number(event.target.value))}
                    data-testid="process-watch-accounting-window">
                    {ACCOUNTING_WINDOWS.map((minutes) => (
                      <option key={minutes} value={minutes}>{minutes} 分钟</option>
                    ))}
                  </select>
                </label>
                <button type="button" onClick={readAccounting} disabled={accountingBusy}
                  data-testid="process-watch-accounting-read">
                  {accountingBusy ? "读取中…" : "读取进程记账"}
                </button>
              </div>
            ) : null}
            {accountingError !== null ? (
              <p className="emergency-path-note" role="alert">{accountingError}</p>
            ) : null}
            {accounting !== null ? <AccountingView accounting={accounting} /> : null}
          </div>
        ) : null}

        {setup && state.probe !== null ? (
          <div className="process-watch-ready">
            <p className="emergency-path-note">
              看到这段时间内新出现的进程；现有检查只是某一时刻的快照，这里补的是两次检查之间发生的事。
            </p>
            <fieldset className="process-watch-methods" disabled={state.status !== "ready"}>
              <legend>监视方式</legend>
              <label>
                <input type="radio" name="process-watch-method" checked={state.method === "proc-poll"}
                  onChange={() => dispatch({ type: "method-changed", value: "proc-poll" })}
                  data-testid="process-watch-method-poll" />
                不上传，定时扫描进程列表
              </label>
              <label>
                <input type="radio" name="process-watch-method" checked={state.method === "pspy"}
                  onChange={() => dispatch({ type: "method-changed", value: "pspy" })}
                  data-testid="process-watch-method-pspy" />
                上传 pspy 运行（更容易抓到短命进程，会向目标写入一个文件）
              </label>
            </fieldset>
            {state.method === "proc-poll" ? (
              <p className="emergency-path-note">
                不向目标写入任何文件，按固定间隔扫描进程列表。两次扫描之间启动并退出的进程会漏掉。
              </p>
            ) : (
              <div className="process-watch-tool">
                <p className="emergency-path-note">
                  pspy 是开源的进程监视程序，本应用不自带。请先从它的发布页下载 pspy64（32 位主机用 pspy32），
                  再在这里选择。开始前会先说明要写到哪里、运行多久，由你确认；结束后自动删除。
                </p>
                <button type="button" onClick={pickTool} disabled={picking || state.status !== "ready"}
                  data-testid="process-watch-pick">
                  {picking ? "等待选择…" : state.tool === null ? "选择 pspy 程序文件…" : "换一个文件…"}
                </button>
                {state.tool !== null ? (
                  <p className="emergency-path-note" role="status" data-testid="process-watch-tool">
                    已选择 {state.tool.fileName}（{formatBytes(state.tool.size)}）：
                    {state.tool.recognized !== null
                      ? `与 ${state.tool.recognized} 的发布文件一致。`
                      : "不是已知的 pspy 发布文件，上传前需要你再确认一次。"}
                  </p>
                ) : null}
                <label className="process-watch-check">
                  <input type="checkbox" checked={state.fileEvents}
                    onChange={() => dispatch({ type: "file-events-toggled" })}
                    data-testid="process-watch-file-events" />
                  同时记录文件访问（仅 /etc、/tmp 等少数目录；会更容易漏掉别处的短命进程）
                </label>
              </div>
            )}
            {state.probe.gaps
              .filter((gap) => state.method === "proc-poll" ||
                (gap !== "polling-misses-short-lived" && gap !== "coarse-interval"))
              .map((gap) => (
                <p key={gap} className="emergency-path-note" role="note" data-testid={`process-watch-gap-${gap}`}>
                  {GAP_TEXT[gap]}
                </p>
              ))}
            <div className="process-watch-options">
              <label>
                监视时长
                <select value={state.durationSeconds} disabled={state.status !== "ready"}
                  onChange={(event) => dispatch({ type: "duration-changed", value: Number(event.target.value) })}
                  data-testid="process-watch-duration">
                  {PROCESS_WATCH_DURATIONS.map((seconds) => (
                    <option key={seconds} value={seconds}>{seconds / 60} 分钟</option>
                  ))}
                </select>
              </label>
              <p className="emergency-path-note">要看到每分钟执行一次的任务，至少需要 2 分钟以上。</p>
              {state.method === "proc-poll" ? (
                <label>
                  扫描间隔
                  <select value={state.intervalMs} disabled={state.status !== "ready"}
                    onChange={(event) => dispatch({ type: "interval-changed", value: Number(event.target.value) })}
                    data-testid="process-watch-interval">
                    {PROCESS_WATCH_INTERVALS.map((ms) => (
                      <option key={ms} value={ms}>{ms} 毫秒</option>
                    ))}
                  </select>
                </label>
              ) : null}
            </div>
            <p className="emergency-path-note" role="note">
              命令行里可能带有口令等敏感内容，请只在需要时复制。没观察到不代表没有。仅在已获授权的主机上使用。
            </p>
            {state.failure !== null ? (
              <p className="emergency-path-note" role="alert" data-testid="process-watch-failure">{state.failure}</p>
            ) : null}
            {blocked ? null : state.method === "proc-poll" ? (
              <button type="button" className="process-watch-start" disabled={state.status !== "ready"}
                onClick={start} data-testid="process-watch-start">
                {state.status === "starting" ? "正在启动…" : "开始监视"}
              </button>
            ) : (
              <button type="button" className="process-watch-start"
                disabled={state.status !== "ready" || state.tool === null}
                onClick={plan} data-testid="process-watch-plan">
                {state.status === "planning" ? "正在查看目标…"
                  : state.status === "starting" ? "正在上传并启动…" : "查看将要做什么…"}
              </button>
            )}
          </div>
        ) : null}

        {state.status === "confirming" && state.plan !== null ? (
          <UploadPlanView
            plan={state.plan}
            headingRef={planHeading}
            unknownAccepted={state.unknownAccepted}
            canConfirm={canConfirmUpload(state)}
            dispatch={dispatch}
            onConfirm={confirmUpload}
          />
        ) : null}

        {state.status === "running" || state.status === "stopping" ? (
          <div className="process-watch-live">
            <p className="emergency-path-note" role="status" data-testid="process-watch-progress">
              {state.status === "stopping" ? "正在停止…" :
                `监视中，已进行 ${state.elapsedSeconds} 秒，共 ${state.durationSeconds} 秒；` +
                `已收到 ${state.events.length} 条记录（新进程 ${state.observedCount}，` +
                `原有进程 ${state.baselineCount}，本工具产生 ${state.ownCount}` +
                `${fileEventCount > 0 ? `，文件访问 ${fileEventCount}` : ""}）。`}
            </p>
            {state.failure !== null ? (
              <p className="emergency-path-note" role="alert">{state.failure}</p>
            ) : null}
            {state.status === "running" ? (
              <button type="button" onClick={cancel} data-testid="process-watch-cancel">取消监视</button>
            ) : null}
          </div>
        ) : null}

        {terminal ? (
          <div className="process-watch-result">
            <p className="emergency-path-note" role="status" data-testid="process-watch-conclusion">
              {STATE_LABEL[state.status]}。{processWatchConclusion(state)}
            </p>
            {state.cleanup !== null ? (
              <p className="emergency-path-note" role={state.cleanup === "clean" ? "status" : "alert"}
                data-testid="process-watch-cleanup">
                {CLEANUP_TEXT[state.cleanup]}
              </p>
            ) : null}
            {state.truncated ? (
              <p className="emergency-path-note" role="note">记录达到上限，后面的进程没有采到，结果不完整。</p>
            ) : null}
            {state.unparsedCount > 0 ? (
              <p className="emergency-path-note" role="note">
                有 {state.unparsedCount} 行输出无法解析，已原样保留在记录里。
              </p>
            ) : null}
            {state.gaps.map((gap) => (
              <p key={gap} className="emergency-path-note" role="note">{GAP_TEXT[gap]}</p>
            ))}
            <button type="button" onClick={restart} data-testid="process-watch-restart">
              开始新的监视（这次的结果不再保留）
            </button>
          </div>
        ) : null}

        {state.events.length > 0 && (
          <>
            <div className="process-watch-tabs" role="tablist">
              <button type="button" role="tab" aria-selected={view === "timeline"}
                onClick={() => setView("timeline")} data-testid="process-watch-view-timeline">
                时间线
              </button>
              <button type="button" role="tab" aria-selected={view === "repeated"}
                onClick={() => setView("repeated")} data-testid="process-watch-view-repeated">
                重复出现的命令
              </button>
              <button type="button" role="tab" aria-selected={view === "origins"}
                onClick={() => setView("origins")} data-testid="process-watch-view-origins">
                会话与来源
              </button>
              <button type="button" role="tab" aria-selected={view === "checks"}
                onClick={() => setView("checks")} data-testid="process-watch-view-checks">
                检查动作推断
              </button>
            </div>

            {view === "timeline" ? (
              <ProcessWatchTimeline
                state={state}
                rows={rows}
                pageRows={pageRows}
                page={page}
                pageCount={pageCount}
                fileEventCount={fileEventCount}
                writeClipboard={writeClipboard}
                dispatch={dispatch}
              />
            ) : view === "repeated" ? (
              <ProcessWatchRepeated state={state} dispatch={dispatch} setView={setView} />
            ) : view === "origins" ? (
              <ProcessWatchOrigins state={state} dispatch={dispatch} setView={setView} />
            ) : (
              <ProcessWatchChecks state={state} onOpenEntry={onOpenEntry} />
            )}
          </>
        )}
      </section>
    </div>
  );
}

function AccountingView({ accounting }: { accounting: ProcessWatchAccounting }) {
  return (
    <div data-testid="process-watch-accounting">
      <p className="emergency-path-note" role="status">
        最近 {accounting.minutes} 分钟里，进程记账记下了 {accounting.records} 个已结束的进程。
        记账只有程序名，没有参数；还在运行的进程要等结束才会出现。
        本工具连接和检查时运行的命令也会被记在里面，记账无法把它们区分出来。
        {accounting.truncated ? "记录太多，只读取了最新的一部分。" : ""}
        {accounting.unparsed > 0 ? `另有 ${accounting.unparsed} 行无法解析。` : ""}
      </p>
      {accounting.groups.length > 0 ? (
        <table className="process-watch-table">
          <thead>
            <tr><th>程序名</th><th>次数</th><th>用户</th><th>首次</th><th>末次</th><th>间隔</th><th>类型</th></tr>
          </thead>
          <tbody>
            {accounting.groups.map((group) => (
              <tr key={`${group.command}:${group.firstAtMs}`} data-testid="process-watch-accounting-row">
                <td><code>{group.command}</code></td>
                <td>{group.count}</td>
                <td>{group.uids.join("、")}</td>
                <td>{formatClock(group.firstAtMs)}</td>
                <td>{formatClock(group.lastAtMs)}</td>
                <td>{group.periodMs !== null ? formatInterval(group.periodMs) : "—"}</td>
                <td>{cadenceTag(group.cadence)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </div>
  );
}

function UploadPlanView({
  plan,
  headingRef,
  unknownAccepted,
  canConfirm,
  dispatch,
  onConfirm,
}: {
  plan: ProcessWatchUploadPlan;
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  unknownAccepted: boolean;
  canConfirm: boolean;
  dispatch: (action: ProcessWatchAction) => void;
  onConfirm: () => void;
}) {
  return (
    <div className="process-watch-plan" data-testid="process-watch-plan-view">
      <h3 tabIndex={-1} ref={headingRef}>确认这一次上传运行</h3>
      <p className="emergency-path-note">确认只对这一次运行有效。下面是将要发生的事，确认前目标上没有写入任何东西。</p>
      <dl className="process-watch-plan-facts">
        <dt>写到哪里</dt>
        <dd>新建目录 <code>{plan.directory}</code>（仅当前账号可访问），其中放入一个 {formatBytes(plan.size)} 的程序文件。</dd>
        <dt>是什么文件</dt>
        <dd>
          {plan.recognized !== null ? `${plan.recognized} 的发布文件` : "不是已知的 pspy 发布文件"}，
          SHA-256 <code>{plan.sha256}</code>。上传后会在目标上重新计算并核对，不一致就删除、不运行。
        </dd>
        <dt>怎么运行</dt>
        <dd>
          以当前 SSH 账号 <code>{plan.account}</code>{plan.isRoot ? "（root）" : "（不提权）"} 运行
          {" "}{plan.durationSeconds / 60} 分钟，到时自动停止；取消或连接断开时也会停止。
          {plan.fileEvents
            ? `同时记录 ${plan.fileEventDirs.join("、")} 下的文件访问。`
            : "只记录进程，不记录文件访问。"}
        </dd>
        <dt>会留下什么痕迹</dt>
        <dd>磁盘上一次写入、一个新进程、若干文件监视；目录访问时间可能变化。主机上的其他人、安全软件和被观察的程序都可能看到它，安全软件可能把 pspy 当作黑客工具告警或删除。取证要求严格的现场请先完成磁盘和内存留证。</dd>
        <dt>结束后</dt>
        <dd>停止该程序，删除文件和目录，并回读确认。如果连接中断来不及删除，下次打开本面板会列出残留供清理。</dd>
      </dl>
      {plan.gaps.map((gap) => (
        <p key={gap} className="emergency-path-note" role="note">{GAP_TEXT[gap]}</p>
      ))}
      {plan.recognized === null ? (
        <label className="process-watch-check">
          <input type="checkbox" checked={unknownAccepted}
            onChange={() => dispatch({ type: "unknown-accepted-toggled" })}
            data-testid="process-watch-unknown-accept" />
          我确认要在这台主机上运行这个未识别的文件
        </label>
      ) : null}
      <div className="process-watch-plan-actions">
        <button type="button" onClick={() => dispatch({ type: "plan-dismissed" })}
          data-testid="process-watch-plan-back">返回，不上传</button>
        <button type="button" className="process-watch-confirm" disabled={!canConfirm} onClick={onConfirm}
          data-testid="process-watch-confirm">确认上传并开始监视</button>
      </div>
    </div>
  );
}

function ProcessWatchTimeline({
  state,
  rows,
  pageRows,
  page,
  pageCount,
  fileEventCount,
  writeClipboard,
  dispatch,
}: {
  state: ProcessWatchState;
  rows: ProcessWatchEvent[];
  pageRows: ProcessWatchEvent[];
  page: number;
  pageCount: number;
  fileEventCount: number;
  writeClipboard?: ((text: string) => Promise<void>) | undefined;
  dispatch: (action: ProcessWatchAction) => void;
}) {
  return (
    <div className="process-watch-timeline">
      <div className="process-watch-filters">
        <input type="search" placeholder="在命令或路径里查找…" value={state.filter}
          onChange={(event) => dispatch({ type: "filter-changed", value: event.target.value })}
          aria-label="在命令里查找" data-testid="process-watch-search" />
        <input type="text" placeholder="按用户编号筛选" value={state.filterUid}
          onChange={(event) => dispatch({ type: "uid-filter-changed", value: event.target.value })}
          aria-label="按用户编号筛选" size={6} />
        <button type="button" aria-pressed={state.showBaseline}
          onClick={() => dispatch({ type: "baseline-toggled" })}
          data-testid="process-watch-baseline-toggle">
          开始时已在运行的进程（{state.baselineCount}）
        </button>
        <button type="button" aria-pressed={state.showOwn}
          onClick={() => dispatch({ type: "own-toggled" })}
          data-testid="process-watch-own-toggle">
          本工具产生（{state.ownCount}）
        </button>
        {fileEventCount > 0 ? (
          <button type="button" aria-pressed={state.showFiles}
            onClick={() => dispatch({ type: "files-toggled" })}
            data-testid="process-watch-files-toggle">
            文件访问（{fileEventCount}）
          </button>
        ) : null}
        {state.groupFilter !== null ? (
          <button type="button" onClick={() => dispatch({ type: "group-filter-set", value: null })}
            data-testid="process-watch-group-clear">
            清除命令筛选
          </button>
        ) : null}
      </div>
      <p className="emergency-path-note">
        时间为本机时区显示的目标时钟；{rows.length} 条记录符合当前筛选。
      </p>
      <table className="process-watch-table">
        <thead>
          <tr>
            <th>时间</th><th>类型</th><th>用户</th><th>PID</th><th>父进程</th><th>命令或路径</th>
            <th>来源</th><th>操作</th>
          </tr>
        </thead>
        <tbody>
          {pageRows.map((event) => (
            <tr key={event.seq} data-testid="process-watch-row">
              <td>{formatClock(event.atMs)}</td>
              <td>{event.kind === "file" ? "文件" : "进程"}</td>
              <td>{event.kind === "file" ? "—" : event.uid === -1 ? "未知" : event.uid}</td>
              <td>{event.kind === "file" ? "—" : event.pid}</td>
              <td>{event.ppid ?? ""}</td>
              <td className="process-watch-command"><code>{event.command}</code>
                {event.clipped ? <span title="内容过长已截断">（已截断）</span> : null}</td>
              <td>{event.origin === "baseline" ? "原有" : "新出现"}{event.own ? "，本工具" : ""}</td>
              <td>
                {writeClipboard !== undefined ? (
                  <>
                    <button type="button" onClick={() => void writeClipboard(event.command)}
                      aria-label={`复制命令 ${event.seq}`}>复制命令</button>
                    <button type="button" onClick={() => void writeClipboard(event.raw)}
                      aria-label={`复制原始行 ${event.seq}`}>复制原始行</button>
                  </>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {pageCount > 1 ? (
        <div className="process-watch-pager">
          <button type="button" disabled={page <= 0}
            onClick={() => dispatch({ type: "page-changed", value: page - 1 })}>上一页</button>
          <span>第 {page + 1} / {pageCount} 页</span>
          <button type="button" disabled={page >= pageCount - 1}
            onClick={() => dispatch({ type: "page-changed", value: page + 1 })}>下一页</button>
        </div>
      ) : null}
    </div>
  );
}

function cadenceTag(cadence: string): string {
  return cadence === "periodic" ? "周期性" : cadence === "repeated" ? "重复" : "单次";
}

/** Where a repeating command is scheduled, said without overclaiming. */
function scheduleText(state: ProcessWatchState, schedule: string | null, cadence: string): string {
  if (schedule !== null) return `对应计划任务：${schedule}`;
  if (state.summary !== null && !state.summary.scheduleRead) return "计划任务读取不到，未核对";
  if (cadence === "periodic") return "来源未知的周期任务（计划任务文件里没有对应项）";
  return "计划任务文件里没有对应项";
}

function ProcessWatchRepeated({
  state,
  dispatch,
  setView,
}: {
  state: ProcessWatchState;
  dispatch: (action: ProcessWatchAction) => void;
  setView: (view: View) => void;
}) {
  const groups = useMemo(
    () => [...(state.summary?.groups ?? [])].sort((a, b) => b.count - a.count),
    [state.summary],
  );
  if (state.summary === null) {
    return <p className="emergency-path-note" role="status">正在汇总重复命令…</p>;
  }
  if (groups.length === 0) {
    return <p className="emergency-path-note">没有重复出现的命令。</p>;
  }
  return (
    <div className="process-watch-repeated">
      {state.summary.scheduleUnreadable.length > 0 ? (
        <p className="emergency-path-note" role="note">
          这些计划任务位置当前账号读不到，对应关系可能不全：{state.summary.scheduleUnreadable.join("、")}
        </p>
      ) : null}
      <table className="process-watch-table" data-testid="process-watch-groups">
        <thead>
          <tr>
            <th>命令（归一化）</th><th>示例</th><th>次数</th><th>用户</th>
            <th>首次</th><th>末次</th><th>间隔</th><th>类型</th><th>计划任务</th>
          </tr>
        </thead>
        <tbody>
          {groups.map((group) => (
            <tr key={`${group.normalized}:${group.firstAtMs}`}>
              <td>
                <button type="button" className="process-watch-group-link"
                  onClick={() => {
                    dispatch({ type: "group-filter-set", value: group.sample });
                    setView("timeline");
                  }}
                  data-testid="process-watch-group">
                  <code>{group.normalized}</code>
                </button>
              </td>
              <td><code>{group.sample}</code></td>
              <td>{group.count}</td>
              <td>{group.uids.length === 0 ? "未知" : group.uids.join("、")}</td>
              <td>{formatClock(group.firstAtMs)}</td>
              <td>{formatClock(group.lastAtMs)}</td>
              <td>{group.periodMs !== null ? formatInterval(group.periodMs) : "—"}</td>
              <td>{cadenceTag(group.cadence)}</td>
              <td>{scheduleText(state, group.schedule, group.cadence)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ProcessWatchOrigins({
  state,
  dispatch,
  setView,
}: {
  state: ProcessWatchState;
  dispatch: (action: ProcessWatchAction) => void;
  setView: (view: View) => void;
}) {
  const summary = state.summary;
  if (summary === null) {
    return <p className="emergency-path-note" role="status">正在按来源归类…</p>;
  }
  const order: ProcessWatchOrigin[] = ["cron", "ssh", "service", "other", "unknown"];
  const counts = new Map(summary.origins.map((entry) => [entry.origin, entry.count]));
  return (
    <div className="process-watch-origins" data-testid="process-watch-origins">
      <p className="emergency-path-note">
        按父进程一路向上找到的来源归类。这是根据观察到的进程关系推断的；父进程没被看到时归为“来源未知”，不代表它没有来源。
      </p>
      {order.filter((origin) => (counts.get(origin) ?? 0) > 0).map((origin) => (
        <section key={origin} data-testid={`process-watch-origin-${origin}`}>
          <h3>{ORIGIN_LABEL[origin]}（{counts.get(origin)} 个进程）</h3>
          <ul>
            {summary.groups.filter((group) => group.origin === origin).slice(0, 40).map((group) => (
              <li key={`${group.normalized}:${group.firstAtMs}`}>
                <button type="button" className="process-watch-group-link"
                  onClick={() => {
                    dispatch({ type: "group-filter-set", value: group.sample });
                    setView("timeline");
                  }}>
                  <code>{group.sample}</code>
                </button>
                <span> × {group.count}</span>
                {group.originVia !== "" ? <span>，经由 <code>{group.originVia}</code></span> : null}
              </li>
            ))}
          </ul>
        </section>
      ))}
      {summary.indicators.length > 0 ? (
        <section data-testid="process-watch-indicators">
          <h3>命令行里出现的地址</h3>
          <p className="emergency-path-note">供人工核查的线索，不是确认的入侵指标。</p>
          <ul>
            {summary.indicators.map((indicator) => (
              <li key={`${indicator.kind}:${indicator.value}`}>
                <code>{indicator.value}</code>
                <span>
                  （{indicator.scope === "public" ? "公网" : indicator.scope === "private" ? "内网"
                    : indicator.scope === "loopback" ? "本机" : "保留地址"}，出现 {indicator.hits} 次）
                </span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}

function ProcessWatchChecks({
  state,
  onOpenEntry,
}: {
  state: ProcessWatchState;
  onOpenEntry?: ((title: string) => void) | undefined;
}) {
  const summary = state.summary;
  if (summary === null) {
    return <p className="emergency-path-note" role="status">正在对照工作台的检查项…</p>;
  }
  return (
    <div className="process-watch-checks" data-testid="process-watch-checks">
      <p className="emergency-path-note">
        把观察到的命令对到工作台里查看同一处的检查项。这是根据命令行推断的：不代表对方只检查了这些，
        也不代表对应的检查项已经没有问题。请到对应检查项里重新运行后再判断。
      </p>
      {summary.inferred.length === 0 ? (
        <p className="emergency-path-note">观察到的命令里没有能对到工作台检查项的。</p>
      ) : (
        <table className="process-watch-table" data-testid="process-watch-inferred">
          <thead>
            <tr><th>工作台检查项</th><th>观察到的命令</th><th>次数</th><th>操作</th></tr>
          </thead>
          <tbody>
            {summary.inferred.map((check) => (
              <tr key={check.entryId} data-testid="process-watch-inferred-row">
                <td>{check.title}</td>
                <td className="process-watch-command"><code>{check.sample}</code></td>
                <td>{check.count}</td>
                <td>
                  {onOpenEntry !== undefined ? (
                    <button type="button" onClick={() => onOpenEntry(check.title)}
                      data-testid="process-watch-open-entry">
                      前往该检查项
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h3>没有对应检查项的命令</h3>
      {summary.unmatched.length === 0 ? (
        <p className="emergency-path-note">没有。</p>
      ) : (
        <ul data-testid="process-watch-unmatched">
          {summary.unmatched.map((entry) => (
            <li key={entry.command}><code>{entry.command}</code> × {entry.count}</li>
          ))}
        </ul>
      )}
      {summary.unmatchedTruncated ? (
        <p className="emergency-path-note" role="note">未对应的命令较多，这里只列出最常出现的 50 条。</p>
      ) : null}
    </div>
  );
}
