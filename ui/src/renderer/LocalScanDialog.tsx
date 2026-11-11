import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from "react";

import type { LocalScanFetchDto } from "../shared/local-scan-contract";
import {
  LocalScanController, type LocalScanRun, type LocalScanState, type LocalScanTransport,
} from "./local-scan-controller";
import { useModalScrim } from "./modal-scrim";
// The frame is the same one the file-action dialogs use; this dialog brings
// that sheet itself so the page it opens from does not have to.
import "./emergency-path.css";
import "./local-scan.css";

const ENTRY_PREVIEW = 20;
const encoder = new TextEncoder();

function byteLabel(bytes: number): string {
  if (bytes < 1024) return `${bytes} 字节`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}（${bytes} 字节）`;
}

function sourceKindLabel(kind: LocalScanFetchDto["sourceKind"]): string {
  return kind === "file" ? "普通文件" : kind === "directory" ? "目录" : "其他类型";
}

function transportLabel(transport: string): string {
  return transport === "scp" ? "scp（目标缺少 SFTP 子系统，已改用 scp 取回）" : transport;
}

/**
 * 取回本机扫描: fetch the offered file — or the directory holding it — into a
 * local isolation folder, then hand that folder to a scanning program the
 * operator configured on this machine.
 */
/** What the dialog scans: a path plus where it came from, for the header and scope labels. */
export interface LocalScanSubject {
  path: string;
  originLabel?: string;
  entryKind: "file" | "directory";
}

export function LocalScanDialog({ transport, subject, returnFocus, onClose }: {
  transport: LocalScanTransport; subject: LocalScanSubject;
  returnFocus: HTMLElement | null; onClose(): void;
}) {
  const [controller] = useState(() => new LocalScanController(transport));
  const view = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const root = useRef<HTMLElement>(null), close = useRef<HTMLButtonElement>(null);
  const closeRef = useRef(onClose); closeRef.current = onClose;
  useModalScrim();
  useEffect(() => {
    controller.attach();
    close.current?.focus();
    function keydown(event: KeyboardEvent) {
      if (event.key === "Escape") { event.preventDefault(); closeRef.current(); return; }
      if (event.key !== "Tab" || !root.current) return;
      const items = [...root.current.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex="0"]')];
      const index = items.indexOf(document.activeElement as HTMLElement);
      if (index < 0 || (event.shiftKey ? index === 0 : index === items.length - 1)) {
        event.preventDefault(); (event.shiftKey ? items.at(-1) : items[0])?.focus();
      }
    }
    function focusin(event: FocusEvent) {
      if (event.target instanceof Node && root.current && !root.current.contains(event.target)) close.current?.focus();
    }
    document.addEventListener("keydown", keydown);
    document.addEventListener("focusin", focusin);
    return () => {
      document.removeEventListener("keydown", keydown); controller.dispose();
      document.removeEventListener("focusin", focusin);
      if (returnFocus?.isConnected) returnFocus.focus({ preventScroll: true });
    };
  }, [controller, returnFocus]);
  return <div className="emergency-path-backdrop">
    <section ref={root} className="emergency-path-dialog local-scan-dialog" role="dialog" aria-modal="true"
      aria-labelledby="local-scan-title" data-testid="local-scan-dialog">
      <header>
        <h2 id="local-scan-title">取回本机扫描</h2>
        <p>{subject.path}</p>
        {subject.originLabel ? <p className="emergency-path-note" data-testid="local-scan-origin">{subject.originLabel}</p> : null}
      </header>
      <LocalScanBody controller={controller} view={view} subject={subject} onClose={onClose} />
      <footer><button ref={close} type="button" onClick={onClose}>关闭</button></footer>
    </section>
  </div>;
}

/** The dialog's working area; kept apart so each phase can be rendered on its own. */
export function LocalScanBody({ controller, view, subject, onClose }: {
  controller: LocalScanController; view: LocalScanState; subject: LocalScanSubject; onClose(): void;
}) {
  const [scope, setScope] = useState<"file" | "directory">("file");
  const [configuring, setConfiguring] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"gui" | "cli">("gui");
  const [argumentsText, setArgumentsText] = useState("");
  const [configureNote, setConfigureNote] = useState<string | null>(null);
  const busy = view.busy !== null;
  const engines = view.engines ?? [];
  const selected = engines.find((engine) => engine.id === view.selectedEngineId) ?? null;

  async function submitConfigure(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const trimmed = name.trim();
    if (trimmed === "") { setConfigureNote("先给引擎起个名字。"); return; }
    if (encoder.encode(trimmed).length > 64) { setConfigureNote("名称最长 64 字节。"); return; }
    const args = argumentsText.split(/\s+/u).filter((piece) => piece !== "").slice(0, 16);
    if (args.some((piece) => encoder.encode(piece).length > 512)) {
      setConfigureNote("单个参数最长 512 字节。");
      return;
    }
    setConfigureNote(null);
    const outcome = await controller.configure(trimmed, kind, args);
    if (outcome === "configured") {
      setConfiguring(false);
      setName("");
      setArgumentsText("");
    } else if (outcome === "cancelled") {
      setConfigureNote("已取消选择，没有添加引擎。");
    }
    // A failed add says why in the dialog's error area already.
  }

  return <>
    <p>把目标机上这个文件按只读方式取回到本机的隔离目录，再交给本机安装的扫描工具检查。取回不会改动目标机上的文件。</p>
    {view.fetch === null ? (
      <>
        <fieldset className="local-scan-scope">
          <legend>取回范围</legend>
          <label>
            <input type="radio" name="local-scan-scope" checked={scope === "file"} disabled={busy}
              onChange={() => setScope("file")} />
            {subject.entryKind === "directory" ? "该目录" : "该文件"}
          </label>
          <label>
            <input type="radio" name="local-scan-scope" checked={scope === "directory"} disabled={busy}
              onChange={() => setScope("directory")} />
            {subject.entryKind === "directory" ? "上一级目录" : "所在目录"}（取回整层，有大小上限）
          </label>
        </fieldset>
        <div className="local-scan-actions">
          <button type="button" className="is-primary" disabled={busy} data-testid="local-scan-fetch"
            onClick={() => void controller.fetch(scope)}>
            {view.busy === "fetch" ? "正在取回…" : "开始取回"}
          </button>
          {view.busy === "fetch" ? <p role="status" data-testid="local-scan-fetching">正在取回（大目录可能需要几分钟）</p> : null}
        </div>
      </>
    ) : (
      <LocalScanFetchSummary fetch={view.fetch} />
    )}
    <p className="emergency-path-note">
      取回内容按不可信来源隔离存放，已去除执行权限并标记为来自网络；取回不代表文件安全，扫描结果仍需人工核对。
    </p>
    <section className="local-scan-engines" aria-label="本机扫描引擎">
      <h3>本机引擎</h3>
      {view.engines === null ? (
        view.enginesFailed
          ? <p>没能读取本机引擎列表。<button type="button" disabled={busy}
            onClick={() => void controller.reloadEngines()}>重新读取</button></p>
          : <p role="status">正在读取已配置的本机引擎…</p>
      ) : engines.length === 0 ? (
        <p>还没有配置本机引擎。</p>
      ) : (
        <ul className="local-scan-engine-list">
          {engines.map((engine) => (
            <li key={engine.id}>
              <label>
                <input type="radio" name="local-scan-engine" checked={view.selectedEngineId === engine.id}
                  disabled={busy} onChange={() => controller.selectEngine(engine.id)} />
                <strong>{engine.name}</strong>
                <span className="local-scan-engine-kind">{engine.kind === "gui" ? "图形界面" : "命令行"}</span>
                <code title={engine.programName}>{engine.programName}</code>
              </label>
            </li>
          ))}
        </ul>
      )}
      <div className="local-scan-engine-actions">
        <button type="button" disabled={busy} onClick={() => { setConfiguring((open) => !open); setConfigureNote(null); }}>
          {configuring ? "收起配置" : "配置引擎"}
        </button>
        {selected !== null ? (
          <button type="button" disabled={busy} data-testid="local-scan-remove-engine"
            onClick={() => void controller.removeEngine(selected.id)}>
            {view.busy === "remove" ? "正在移除…" : "移除所选引擎"}
          </button>
        ) : null}
      </div>
      {configuring ? (
        <form className="local-scan-configure" onSubmit={(event) => void submitConfigure(event)} aria-label="配置引擎">
          <label>名称
            <input value={name} maxLength={64} required placeholder="例如 D盾" data-testid="local-scan-engine-name"
              onChange={(event) => setName(event.target.value)} />
          </label>
          <label>类型
            <select value={kind} data-testid="local-scan-engine-kind"
              onChange={(event) => setKind(event.target.value === "cli" ? "cli" : "gui")}>
              <option value="gui">图形界面引擎（如 D盾）</option>
              <option value="cli">命令行引擎</option>
            </select>
          </label>
          <label>参数（可选）
            <input value={argumentsText} spellCheck={false} placeholder="空格分隔，可含 {dir}"
              onChange={(event) => setArgumentsText(event.target.value)} />
          </label>
          <p className="emergency-path-note">
            {"参数按空格拆分后传给引擎；不写 {dir} 时，取回目录会作为最后一个参数传入。"}
          </p>
          {configureNote !== null ? <p role="status">{configureNote}</p> : null}
          <button type="submit" disabled={busy || name.trim() === ""} data-testid="local-scan-configure-submit">
            {view.busy === "configure" ? "正在选择程序…" : "选择程序并保存"}
          </button>
        </form>
      ) : null}
    </section>
    {view.fetch !== null ? (
      <section className="local-scan-run" aria-label="启动扫描">
        <button type="button" className="is-primary" data-testid="local-scan-run"
          disabled={view.fetch === null || selected === null || busy}
          title={selected === null ? "先选择或配置一个本机引擎" : undefined}
          onClick={() => { if (selected !== null) void controller.run(selected.id); }}>
          {view.busy === "run" ? "正在启动扫描…" : "启动扫描"}
        </button>
        {selected === null && view.engines !== null ? <p className="emergency-path-note">选择一个本机引擎后才能启动扫描。</p> : null}
        {view.run !== null ? <LocalScanRunResult run={view.run} /> : null}
        <div className="local-scan-secondary">
          <button type="button" disabled={busy} data-testid="local-scan-reveal"
            onClick={() => void controller.reveal()}>
            {view.busy === "reveal" ? "正在打开…" : "打开取回目录"}
          </button>
          <button type="button" disabled={busy} data-testid="local-scan-discard"
            onClick={() => { void controller.discard().then((done) => { if (done) onClose(); }); }}>
            {view.busy === "discard" ? "正在删除…" : "删除取回内容"}
          </button>
        </div>
      </section>
    ) : null}
    {view.notice !== null ? <p role="status">{view.notice}</p> : null}
    {view.error !== null ? <p className="emergency-path-error" role="alert" data-testid="local-scan-error">{view.error}</p> : null}
  </>;
}

/** What the completed fetch reported about the copy now sitting in isolation. */
function LocalScanFetchSummary({ fetch }: { fetch: LocalScanFetchDto }) {
  const preview = fetch.entries.slice(0, ENTRY_PREVIEW);
  return <div className="emergency-path-panel local-scan-summary" data-testid="local-scan-summary">
    <dl>
      <div><dt>来源类型</dt><dd>{sourceKindLabel(fetch.sourceKind)}</dd></div>
      <div><dt>取回范围</dt><dd>{fetch.scope === "file" ? "该路径本身" : "整层目录"}</dd></div>
      {fetch.originLabel !== "" ? <div><dt>来源</dt><dd data-testid="local-scan-summary-origin">{fetch.originLabel}</dd></div> : null}
      <div><dt>取回内容</dt><dd>{fetch.files} 个文件、{fetch.directories} 个目录，共 {byteLabel(fetch.bytes)}</dd></div>
      {fetch.skipped > 0 ? <div><dt>跳过</dt><dd>{fetch.skipped} 项</dd></div> : null}
      <div><dt>取回方式</dt><dd>{transportLabel(fetch.transport)}</dd></div>
      <div><dt>隔离目录</dt><dd>{fetch.stagingDirectory}</dd></div>
      <div><dt>归档 SHA-256</dt><dd className="file-evidence-hash">{fetch.archiveSha256}</dd></div>
      <div><dt>取回时间</dt><dd>{fetch.fetchedAt}</dd></div>
      <div><dt>本机保留</dt><dd>约 {Math.max(1, Math.round(fetch.expiresInSeconds / 60))} 分钟，之后自动删除</dd></div>
    </dl>
    {fetch.truncated ? <p className="local-scan-warning" role="status">内容过多，已按上限截断，取回的不是完整目录。</p> : null}
    {fetch.skippedReasons.length > 0 ? (
      <ul className="local-scan-skipped" aria-label="跳过原因">
        {fetch.skippedReasons.map((reason, index) => <li key={index}>{reason}</li>)}
      </ul>
    ) : null}
    {preview.length > 0 ? (
      <details className="local-scan-entries">
        <summary>取回内容预览（前 {preview.length} 项{fetch.entries.length > preview.length ? `，共 ${fetch.entries.length} 项` : ""}）</summary>
        <ul>{preview.map((entry, index) => <li key={index}>{entry}</li>)}</ul>
      </details>
    ) : null}
  </div>;
}

/** The launch answer: a window opened, or a command line run that already exited. */
function LocalScanRunResult({ run }: { run: LocalScanRun }) {
  return <div className="emergency-path-panel local-scan-run-result" data-testid="local-scan-run-result">
    <p role="status">{run.detail}</p>
    {run.state === "launched" ? (
      <p className="emergency-path-note">图形界面引擎在自己的窗口里继续，本页不跟踪它的进度。</p>
    ) : (
      <>
        <p>引擎「{run.engineName}」已结束，退出码 {run.exitCode ?? "未取得"}。</p>
        {run.output !== null && run.output !== "" ? (
          <pre className="local-scan-output" data-testid="local-scan-output">{run.output}</pre>
        ) : (
          <p className="emergency-path-note">引擎没有留下可显示的输出。</p>
        )}
      </>
    )}
  </div>;
}
