import { useCallback, useEffect, useRef, useState } from "react";
import { TransientNotice } from "./NotificationCenter";

import type {
  PcapAlert,
  PcapAnalysisResult,
  PcapEcho,
  PcapFlow,
  PcapHttpTx,
  PcapObjectInfo,
  PcapOfflineResult,
  PcapOfflineStatus,
  PcapSummary,
} from "../shared/pcap-offline-contract";
import "./traffic-analysis-page.css";

export interface PcapOfflineApi {
  pcapOffline(request: import("../shared/pcap-offline-contract").PcapOfflineRequest): Promise<PcapOfflineResult | null>;
}

interface TrafficAnalysisPageProps {
  api: PcapOfflineApi;
  /** Set by the capture page when the operator picks 离线分析 on saved evidence. */
  evidenceJobHandle?: string | null;
  onEvidenceConsumed?: () => void;
  active?: boolean;
  /** Tests and previews can seed a status; live use always polls the backend. */
  initialStatus?: PcapOfflineStatus | null;
  initialTab?: TabId;
}

type TabId = "summary" | "flows" | "http" | "objects" | "alerts" | "echoes";

const TABS: { id: TabId; label: string }[] = [
  { id: "summary", label: "概要" },
  { id: "flows", label: "会话" },
  { id: "http", label: "HTTP" },
  { id: "objects", label: "对象" },
  { id: "alerts", label: "告警" },
  { id: "echoes", label: "菜刀回显" },
];

const LINK_TYPE_NAMES: Record<number, string> = { 1: "以太网", 101: "裸 IP", 113: "Linux SLL", 276: "Linux SLL2" };
const FLOW_PAGE = 200;

export function formatBytes(n: number): string {
  if (n >= 1_073_741_824) return `${(n / 1_073_741_824).toFixed(1)} GiB`;
  if (n >= 1_048_576) return `${(n / 1_048_576).toFixed(1)} MiB`;
  if (n >= 1_024) return `${(n / 1_024).toFixed(1)} KiB`;
  return `${n} B`;
}

function fmtDuration(ms: number): string {
  if (ms >= 60_000) return `${(ms / 60_000).toFixed(1)} 分钟`;
  if (ms >= 1_000) return `${(ms / 1_000).toFixed(1)} 秒`;
  return `${Math.round(ms)} 毫秒`;
}

export function alertLevelLabel(level: PcapAlert["level"]): string {
  if (level === "strong") return "强线索";
  if (level === "weak") return "弱线索";
  return "线索";
}

export function TrafficAnalysisPage({ api, evidenceJobHandle = null, onEvidenceConsumed, active = true, initialStatus = null, initialTab = "summary" }: TrafficAnalysisPageProps) {
  const [status, setStatus] = useState<PcapOfflineStatus | null>(initialStatus);
  const [tab, setTab] = useState<TabId>(initialTab);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [flowVisible, setFlowVisible] = useState(FLOW_PAGE);
  const [focusFlow, setFocusFlow] = useState<number | null>(null);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (pollRef.current !== null) clearTimeout(pollRef.current);
    };
  }, []);

  const poll = useCallback(async () => {
    try {
      const result = await api.pcapOffline({ action: "status" });
      if (!mountedRef.current || result === null || result.kind !== "status") return;
      setStatus(result.status);
      if (result.status.state === "reading" || result.status.state === "analyzing") {
        pollRef.current = setTimeout(() => void poll(), 300);
      }
    } catch {
      if (mountedRef.current) pollRef.current = setTimeout(() => void poll(), 1_000);
    }
  }, [api]);

  // Starting an analysis (import dialog or saved evidence) flips the backend to
  // "reading"; polling picks the job up regardless of which entry began it.
  const startPolling = useCallback(() => {
    if (pollRef.current !== null) clearTimeout(pollRef.current);
    pollRef.current = setTimeout(() => void poll(), 100);
  }, [poll]);

  useEffect(() => {
    if (evidenceJobHandle === null || evidenceJobHandle === "") return;
    // Consuming clears the prop and re-renders the parent, which re-runs this
    // effect; the begun analysis must not be cancelled by that, so the work
    // below is not gated on a cleanup flag — unmount safety comes from
    // mountedRef inside poll.
    onEvidenceConsumed?.();
    void (async () => {
      try {
        await api.pcapOffline({ action: "begin-evidence", jobHandle: evidenceJobHandle });
        startPolling();
      } catch (error) {
        setNotice(error instanceof Error ? error.message : "无法分析这份抓包证据。");
      }
    })();
  }, [evidenceJobHandle, api, onEvidenceConsumed, startPolling]);

  const onImport = async () => {
    setBusy(true);
    try {
      const result = await api.pcapOffline({ action: "import" });
      if (result !== null && result.kind === "started" && result.started) {
        setFocusFlow(null);
        setFlowVisible(FLOW_PAGE);
        startPolling();
      }
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "无法开始分析。");
    } finally {
      setBusy(false);
    }
  };

  const onCancel = async () => {
    try {
      await api.pcapOffline({ action: "cancel" });
    } catch {
      /* cancelled-state arrives on the next poll */
    }
    startPolling();
  };

  const onExport = async (objectId: string) => {
    setBusy(true);
    try {
      const result = await api.pcapOffline({ action: "export-object", objectId });
      if (result !== null && result.kind === "exported" && result.exported) {
        setNotice(`已导出 ${formatBytes(result.bytes)}。对象内容未经核实，请勿直接运行。`);
      }
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "导出失败。");
    } finally {
      setBusy(false);
    }
  };

  const running = status !== null && (status.state === "reading" || status.state === "analyzing");
  const result = status?.result ?? null;

  const jumpToFlow = (flowId: number | null) => {
    if (flowId === null) return;
    setFocusFlow(flowId);
    setFlowVisible(FLOW_PAGE);
    setTab("flows");
  };
  const jumpToTx = (txId: number | null) => {
    if (txId === null || result === null) return;
    const tx = result.http.find((t) => t.id === txId);
    if (tx !== undefined) jumpToFlow(tx.flowId);
  };

  return (
    <div className="page traffic-analysis-page" data-testid="traffic-analysis-page">
      <header className="page-header">
        <h2>流量分析</h2>
        <p className="page-lead">离线解析本机抓包文件：会话、HTTP 事务、提取对象与可疑流量线索。分析在本机进行，路径不离开本机。</p>
        <div className="page-actions">
          <button type="button" onClick={() => void onImport()} disabled={busy || running} data-testid="pcap-import">
            导入抓包文件…
          </button>
          {running ? (
            <button type="button" onClick={() => void onCancel()} data-testid="pcap-cancel">取消分析</button>
          ) : null}
        </div>
      </header>

      {notice !== null ? (
        <TransientNotice source="流量分析" message={notice} severity="info">
          <p className="pcap-notice" role="status">{notice}<button type="button" className="link" onClick={() => setNotice(null)}>知道了</button></p>
        </TransientNotice>
      ) : null}

      {running && status !== null ? (
        <section className="pcap-progress" data-testid="pcap-progress" role="status">
          <p>
            {status.state === "reading" ? "正在读取文件" : "正在解析"}，已读 {formatBytes(status.bytesRead)}
            {status.totalBytes > 0 ? ` / ${formatBytes(status.totalBytes)}` : ""}
          </p>
          {status.totalBytes > 0 ? (
            <progress value={status.bytesRead} max={status.totalBytes} />
          ) : <progress />}
          {status.detail !== "" ? <p className="pcap-progress-detail">{status.detail}</p> : null}
        </section>
      ) : null}

      {status !== null && status.state === "failed" ? (
        <section className="pcap-failed" role="alert" data-testid="pcap-failed">
          <p><strong>分析失败。</strong>{status.detail}</p>
        </section>
      ) : null}
      {status !== null && status.state === "cancelled" ? (
        <section className="pcap-failed" data-testid="pcap-cancelled"><p>分析已取消。{status.detail}</p></section>
      ) : null}

      {result !== null ? (
        <>
          <nav className="tab-strip" role="tablist" aria-label="分析结果">
            {TABS.map((t) => (
              <button key={t.id} type="button" role="tab" aria-selected={tab === t.id}
                className={tab === t.id ? "tab active" : "tab"} onClick={() => setTab(t.id)}
                data-testid={`pcap-tab-${t.id}`}>
                {t.label}
                {t.id === "alerts" && result.alerts.length > 0 ? `（${result.alerts.length}）` : ""}
                {t.id === "echoes" && result.echoes.length > 0 ? `（${result.echoes.length}）` : ""}
              </button>
            ))}
          </nav>
          <section className="pcap-tab-body">
            {tab === "summary" ? <SummaryTab summary={result.summary} /> : null}
            {tab === "flows" ? (
              <FlowsTab flows={result.flows} focusFlow={focusFlow} visible={flowVisible}
                onMore={() => setFlowVisible((n) => n + FLOW_PAGE)} />
            ) : null}
            {tab === "http" ? <HttpTab http={result.http} onFlow={jumpToFlow} /> : null}
            {tab === "objects" ? <ObjectsTab objects={result.objects} onExport={(id) => void onExport(id)} busy={busy} /> : null}
            {tab === "alerts" ? <AlertsTab alerts={result.alerts} onFlow={jumpToFlow} onTx={jumpToTx} /> : null}
            {tab === "echoes" ? <EchoesTab echoes={result.echoes} onFlow={jumpToFlow} /> : null}
          </section>
        </>
      ) : !running && status?.state !== "failed" && status?.state !== "cancelled" ? (
        <section className="empty-state" data-testid="pcap-empty">
          <p>还没有分析结果。点「导入抓包文件…」选择本机的 .pcap / .pcapng 文件，或在「网络抓包」页对已留证的抓包点「离线分析」。</p>
        </section>
      ) : null}
      {active ? null : null}
    </div>
  );
}

function SummaryTab({ summary }: { summary: PcapSummary }) {
  const linkNames = summary.linkTypes.map((t) => LINK_TYPE_NAMES[t] ?? `类型 ${t}`).join("、");
  const truncated = summary.flowCapHit || summary.streamCapHit || summary.packetCapHit;
  return (
    <div data-testid="pcap-summary">
      <dl className="detail-grid">
        <div><dt>格式</dt><dd>{summary.format}</dd></div>
        <div><dt>链路类型</dt><dd>{linkNames === "" ? "未知" : linkNames}</dd></div>
        <div><dt>数据包</dt><dd>{summary.packetCount}（成功解析 {summary.parsedCount}）</dd></div>
        <div><dt>畸形或截断</dt><dd>{summary.malformedCount}</dd></div>
        <div><dt>分片未重组</dt><dd>{summary.fragmentCount}</dd></div>
      </dl>
      {truncated ? (
        <p className="pcap-truncated" role="status" data-testid="pcap-truncated">
          结果不完整：{summary.flowCapHit ? "会话数达到上限；" : ""}{summary.streamCapHit ? "TCP 重组超出上限；" : ""}
          {summary.packetCapHit ? "已停止继续解析。" : ""}下列发现只覆盖已解析的部分。
        </p>
      ) : null}
      {summary.warnings.length > 0 ? (
        <ul className="pcap-warnings" data-testid="pcap-warnings">
          {summary.warnings.map((w, i) => <li key={i}>{w}</li>)}
        </ul>
      ) : null}
    </div>
  );
}

function FlowsTab({ flows, focusFlow, visible, onMore }: { flows: PcapFlow[]; focusFlow: number | null; visible: number; onMore: () => void }) {
  const shown = focusFlow !== null ? flows.filter((f) => f.id === focusFlow) : flows.slice(0, visible);
  if (flows.length === 0) return <p className="empty-state">没有识别出会话。</p>;
  return (
    <div data-testid="pcap-flows">
      {focusFlow !== null ? <p className="pcap-focus">只看会话 #{focusFlow}（来自告警联动）。</p> : null}
      <table className="data-table">
        <thead><tr><th>#</th><th>协议</th><th>端点 A</th><th>端点 B</th><th>包</th><th>字节</th><th>时长</th><th>重组</th></tr></thead>
        <tbody>
          {shown.map((f) => (
            <tr key={f.id} data-flow-id={f.id}>
              <td>{f.id}</td><td>{f.proto}</td>
              <td><code>{f.endpointA}</code></td><td><code>{f.endpointB}</code></td>
              <td>{f.packets}</td><td>{formatBytes(f.bytes)}</td>
              <td>{fmtDuration(f.lastMs - f.firstMs)}</td>
              <td>{f.streamTruncated ? "已截断" : f.tcpGaps > 0 ? `${f.tcpGaps} 处缺口` : "完整"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {focusFlow === null && flows.length > visible ? (
        <button type="button" className="more" onClick={onMore}>显示更多（共 {flows.length} 条会话）</button>
      ) : null}
    </div>
  );
}

function HttpTab({ http, onFlow }: { http: PcapHttpTx[]; onFlow: (id: number) => void }) {
  const [open, setOpen] = useState<number | null>(null);
  if (http.length === 0) return <p className="empty-state">没有识别出 HTTP 事务。</p>;
  return (
    <div data-testid="pcap-http">
      <table className="data-table">
        <thead><tr><th>#</th><th>方法</th><th>URI</th><th>主机</th><th>状态</th><th>请求体</th><th>响应体</th></tr></thead>
        <tbody>
          {http.map((t) => (
            <tr key={t.id} className={open === t.id ? "expanded" : ""} onClick={() => setOpen(open === t.id ? null : t.id)}
              data-tx-id={t.id}>
              <td>{t.id}</td><td>{t.method}</td>
              <td className="pcap-uri"><code>{t.uri}</code></td>
              <td><code>{t.host}</code></td>
              <td>{t.incomplete ? `${t.status}（不完整）` : t.status}</td>
              <td>{formatBytes(t.reqBodySize)}</td><td>{formatBytes(t.respBodySize)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {open !== null ? (() => {
        const t = http.find((x) => x.id === open);
        if (t === undefined) return null;
        return (
          <div className="pcap-tx-detail" data-testid="pcap-tx-detail">
            <p><button type="button" className="link" onClick={() => onFlow(t.flowId)}>查看所属会话 #{t.flowId}</button></p>
            <h4>请求头</h4>
            <pre className="pcap-plain">{t.reqHeaders.join("\n") || "（无）"}</pre>
            <h4>响应头</h4>
            <pre className="pcap-plain">{t.respHeaders.join("\n") || "（无）"}</pre>
            <p className="pcap-plain-note">正文见「对象」页；内容按不可信纯文本处理。</p>
          </div>
        );
      })() : null}
    </div>
  );
}

function ObjectsTab({ objects, onExport, busy }: { objects: PcapObjectInfo[]; onExport: (id: string) => void; busy: boolean }) {
  if (objects.length === 0) return <p className="empty-state">没有提取出对象。</p>;
  return (
    <div data-testid="pcap-objects">
      <table className="data-table">
        <thead><tr><th>ID</th><th>大小</th><th>类型</th><th>来源 URI</th><th>SHA-256</th><th>操作</th></tr></thead>
        <tbody>
          {objects.map((o) => (
            <tr key={o.id}>
              <td><code>{o.id}</code></td>
              <td>{formatBytes(o.size)}{o.stored ? "" : "（未留存）"}</td>
              <td>{o.contentType === "" ? o.kind : `${o.kind} · ${o.contentType}`}</td>
              <td className="pcap-uri"><code>{o.uri}</code></td>
              <td><code className="pcap-sha">{o.sha256.slice(0, 16)}…</code></td>
              <td>{o.stored ? <button type="button" disabled={busy} onClick={() => onExport(o.id)} data-testid={`pcap-export-${o.id}`}>导出…</button> : null}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="pcap-plain-note">导出的对象按原始字节写入所选位置，不会在本页渲染；未知内容请勿直接运行。</p>
    </div>
  );
}

function AlertsTab({ alerts, onFlow, onTx }: { alerts: PcapAlert[]; onFlow: (id: number | null) => void; onTx: (id: number | null) => void }) {
  if (alerts.length === 0) return <p className="empty-state">没有命中任何特征。这不能证明流量一定无害。</p>;
  return (
    <div data-testid="pcap-alerts">
      <ul className="pcap-alert-list">
        {alerts.map((a, i) => (
          <li key={i} className={`pcap-alert level-${a.level}`}>
            <span className="pcap-alert-badge">{alertLevelLabel(a.level)}</span>
            <strong>{a.rule}</strong>
            <p>{a.message}</p>
            <p className="pcap-alert-links">
              {a.flowId !== null ? <button type="button" className="link" onClick={() => onFlow(a.flowId)}>会话 #{a.flowId}</button> : null}
              {a.txId !== null ? <button type="button" className="link" onClick={() => onTx(a.txId)}>事务 #{a.txId}</button> : null}
            </p>
          </li>
        ))}
      </ul>
      <p className="pcap-plain-note">线索只是值得核实的方向，不是定论；请结合会话、对象与留证继续调查。</p>
    </div>
  );
}

function EchoesTab({ echoes, onFlow }: { echoes: PcapEcho[]; onFlow: (id: number) => void }) {
  if (echoes.length === 0) return <p className="empty-state">没有发现菜刀回显。</p>;
  return (
    <div data-testid="pcap-echoes">
      <ul className="pcap-echo-list">
        {echoes.map((e, i) => (
          <li key={i}>
            <p>
              <span className="pcap-alert-badge">菜刀回显</span>
              标记 <code>{e.marker === "x@y" ? "X@Y" : "->|…|<-"}</code>
              <button type="button" className="link" onClick={() => onFlow(e.flowId)}>会话 #{e.flowId}</button>
            </p>
            <pre className="pcap-plain">{e.text}</pre>
          </li>
        ))}
      </ul>
    </div>
  );
}
