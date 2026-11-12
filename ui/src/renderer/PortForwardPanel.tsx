import { useCallback, useEffect, useRef, useState } from "react";
import { isPortForward, isPortForwardList, type PortForward } from "../shared/port-forward-contract";
import { useConfirmDialog } from "./use-confirm-dialog";
import { useModalScrim } from "./modal-scrim";
import { DialogHost } from "./DialogHost";

export interface PortForwardApi {
  portForward(request: import("../shared/port-forward-contract").PortForwardRequest): Promise<unknown>;
}

export interface ForwardPrefill {
  host: string;
  port: number;
}

/**
 * The 端口转发 panel: every forward this connection runs, with counters,
 * copy-address and stop actions, and a form for a new one. The backend
 * re-checks everything — this dialog only collects intent.
 */
export function PortForwardPanel({ bindingHandle, api, prefill, writeClipboard, onClose }: {
  bindingHandle: string;
  api: PortForwardApi;
  prefill: ForwardPrefill | null;
  writeClipboard?: ((text: string) => Promise<void>) | undefined;
  onClose: () => void;
}) {
  useModalScrim();
  const confirm = useConfirmDialog();
  const [forwards, setForwards] = useState<PortForward[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [localPort, setLocalPort] = useState("0");
  const [destHost, setDestHost] = useState(prefill?.host ?? "127.0.0.1");
  const [destPort, setDestPort] = useState(String(prefill?.port ?? ""));
  const [busy, setBusy] = useState(false);
  const binding = useRef(bindingHandle);
  binding.current = bindingHandle;

  const refresh = useCallback(async () => {
    try {
      const value = await api.portForward({ action: "list", bindingHandle: binding.current });
      if (value !== null && isPortForwardList(value)) setForwards(value);
    } catch {
      setError("无法读取转发列表。");
    }
  }, [api]);
  useEffect(() => { void refresh(); }, [refresh]);

  async function start() {
    if (busy) return;
    const local = Number.parseInt(localPort.trim() === "" ? "0" : localPort.trim(), 10);
    const remote = Number.parseInt(destPort.trim(), 10);
    const host = destHost.trim();
    if (!Number.isInteger(local) || local < 0 || (local !== 0 && local < 1024) || local > 65535) {
      setError("本机端口填 0 让系统分配，或 1024-65535。");
      return;
    }
    if (!Number.isInteger(remote) || remote < 1 || remote > 65535 || host === "") {
      setError("目标地址需为 IP 加 1-65535 端口。");
      return;
    }
    const yes = await confirm.ask("开启端口转发",
      `在本机监听端口 ${local === 0 ? "（自动分配）" : String(local)}，经当前 SSH 连接转发到目标 ${host}:${remote}？本机任何进程都能访问该监听地址；目标不在监听表内的地址会被拒绝。`,
      "开启");
    if (!yes) return;
    setBusy(true);
    setError(null);
    try {
      const value = await api.portForward({
        action: "start", bindingHandle: binding.current,
        localPort: local, destinationHost: host, destinationPort: remote,
      });
      if (value !== null && !isPortForward(value)) {
        setError("转发开启结果未通过校验。");
        return;
      }
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error && reason.message !== "" ? reason.message : "转发没有开启。");
    } finally {
      setBusy(false);
    }
  }

  async function stop(forward: PortForward) {
    try {
      await api.portForward({ action: "stop", bindingHandle: binding.current, forwardHandle: forward.forwardHandle });
      await refresh();
    } catch {
      setError("未能停止转发。");
    }
  }

  async function copyAddress(forward: PortForward) {
    try {
      await (writeClipboard ?? ((value) => window.lovelyhawk.writeClipboard(value)))(forward.localAddress);
      setCopied(forward.forwardHandle);
      window.setTimeout(() => setCopied((current) => (current === forward.forwardHandle ? null : current)), 2000);
    } catch {
      setError("没能写入剪贴板。");
    }
  }

  return (
    <div className="sftp-operation-backdrop" role="presentation">
      <section className="sftp-operation-dialog" role="dialog" aria-modal="true"
        aria-label="端口转发" data-testid="port-forward-panel">
        <header>
          <h2>端口转发</h2>
          <p>把目标的监听地址经当前 SSH 连接转到本机回环地址。本机任何进程都能访问；断开连接或关闭窗口即全部停止。</p>
        </header>
        {forwards === null || forwards.length === 0 ? (
          <p className="sftp-browser-empty">当前没有运行中的转发。</p>
        ) : (
          <ul className="sftp-queue-items" data-testid="port-forward-list">
            {forwards.map((forward) => (
              <li key={forward.forwardHandle} className="sftp-queue-item">
                <span className="sftp-queue-item-name" title={`${forward.localAddress} → ${forward.destination}`}>
                  {forward.localAddress} → {forward.destination}
                </span>
                <span className="sftp-queue-item-detail">
                  {forward.connections} 连接 · 入 {forward.bytesIn} B · 出 {forward.bytesOut} B
                  {forward.lastError === null ? "" : ` · ${forward.lastError}`}
                </span>
                <button type="button" data-testid={`port-forward-copy-${forward.forwardHandle}`}
                  onClick={() => void copyAddress(forward)}>
                  {copied === forward.forwardHandle ? "已复制" : "复制地址"}
                </button>
                <button type="button" data-testid={`port-forward-stop-${forward.forwardHandle}`}
                  onClick={() => void stop(forward)}>停止</button>
              </li>
            ))}
          </ul>
        )}
        <div className="sftp-relay-dest" data-testid="port-forward-form">
          <label>本机端口
            <input type="text" value={localPort} data-testid="port-forward-local" spellCheck={false}
              onChange={(event) => { const typed = event.currentTarget.value; setLocalPort(typed); }} />
          </label>
          <label>目标地址
            <input type="text" value={destHost} data-testid="port-forward-host" spellCheck={false}
              onChange={(event) => { const typed = event.currentTarget.value; setDestHost(typed); }} />
          </label>
          <label>目标端口
            <input type="text" value={destPort} data-testid="port-forward-remote" spellCheck={false}
              onChange={(event) => { const typed = event.currentTarget.value; setDestPort(typed); }} />
          </label>
          <button type="button" className="is-primary" disabled={busy}
            data-testid="port-forward-start" onClick={() => void start()}>
            {busy ? "正在开启…" : "开启转发"}
          </button>
        </div>
        {error === null ? null : <p className="sftp-browser-transfer is-error" role="alert">{error}</p>}
        <footer>
          <button type="button" onClick={onClose}>关闭</button>
        </footer>
        {confirm.dialog === null ? null : (
          <DialogHost dialog={confirm.dialog} onResolve={confirm.resolve} />
        )}
      </section>
    </div>
  );
}
