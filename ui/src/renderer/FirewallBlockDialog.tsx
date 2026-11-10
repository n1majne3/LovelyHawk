import { useEffect, useRef, useState } from "react";

import {
  isSystemInfoFirewallAddress,
  isSystemInfoFirewallPlan,
  isSystemInfoFirewallRestorePlan,
  isSystemInfoFirewallResult,
  type SystemInfoApi,
  type SystemInfoFirewallBackend,
  type SystemInfoFirewallDirection,
  type SystemInfoFirewallPlan,
  type SystemInfoFirewallRestorePlan,
  type SystemInfoFirewallResult,
} from "../shared/system-info-contract";
import { useModalScrim } from "./modal-scrim";
import { rowActionFailureText } from "./system-info-row-actions";

export const FIREWALL_BACKEND_LABELS: Record<SystemInfoFirewallBackend, string> = {
  firewalld: "firewalld（运行时规则）",
  iptables: "iptables",
  nftables: "nftables（LovelyHawk 自有规则表）",
};

export const FIREWALL_DIRECTION_LABELS: Record<SystemInfoFirewallDirection, string> = {
  inbound: "入站（拦截来自该地址的连接）",
  outbound: "出站（拦截本机连往该地址，如回连 C2）",
  both: "双向",
};

type Step =
  | { kind: "input" }
  | { kind: "planning" }
  | { kind: "confirm"; plan: SystemInfoFirewallPlan; deadline: number }
  | { kind: "executing"; plan: SystemInfoFirewallPlan }
  | { kind: "result"; plan: SystemInfoFirewallPlan; result: SystemInfoFirewallResult; undoNote: string | null }
  | { kind: "restore-confirm"; plan: SystemInfoFirewallPlan; restore: SystemInfoFirewallRestorePlan; restoreHandle: string; deadline: number }
  | { kind: "restoring"; plan: SystemInfoFirewallPlan }
  | { kind: "restored"; plan: SystemInfoFirewallPlan; result: SystemInfoFirewallResult };

export interface FirewallBlockDialogProps {
  api: SystemInfoApi;
  bindingHandle: string;
  initialAddress: string | null;
  initialDirection: SystemInfoFirewallDirection;
  onChanged: () => void;
  onClose: () => void;
}

/** Whether the dialog may close without losing an in-flight change. */
export function firewallDialogBusy(kind: Step["kind"]): boolean {
  return kind === "planning" || kind === "executing" || kind === "restoring";
}

export function FirewallBlockDialog({
  api, bindingHandle, initialAddress, initialDirection, onChanged, onClose,
}: FirewallBlockDialogProps) {
  useModalScrim();
  const [step, setStep] = useState<Step>({ kind: "input" });
  const [address, setAddress] = useState(initialAddress ?? "");
  const [direction, setDirection] = useState<SystemInfoFirewallDirection>(initialDirection);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());
  const firstField = useRef<HTMLInputElement>(null);
  const cancelButton = useRef<HTMLButtonElement>(null);
  const busy = firewallDialogBusy(step.kind);

  useEffect(() => { firstField.current?.focus(); }, []);
  useEffect(() => {
    if (step.kind === "confirm" || step.kind === "restore-confirm") cancelButton.current?.focus();
  }, [step.kind]);
  useEffect(() => {
    if (step.kind !== "confirm" && step.kind !== "restore-confirm") return;
    const timer = setInterval(() => setNow(Date.now()), 1_000);
    return () => clearInterval(timer);
  }, [step.kind]);
  useEffect(() => {
    if (step.kind === "confirm" && now >= step.deadline) {
      setStep({ kind: "input" });
      setError("计划已过期，请重新生成。");
    }
    if (step.kind === "restore-confirm" && now >= step.deadline) {
      setStep({ kind: "result", plan: step.plan, result: { verified: true, detail: "", restoreHandle: step.restoreHandle }, undoNote: "撤销计划已过期，可重新发起撤销。" });
    }
  }, [now, step]);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busy) { event.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, onClose]);

  const addressValid = isSystemInfoFirewallAddress(address.trim());

  async function plan(): Promise<void> {
    if (!addressValid) { setError("请输入一个 IPv4 或 IPv6 主机地址（不支持网段）。"); return; }
    setError(null);
    setStep({ kind: "planning" });
    try {
      const value = await api.planSystemInfoFirewallBlock(bindingHandle, address.trim(), direction);
      if (!isSystemInfoFirewallPlan(value)) throw new Error("invalid plan");
      setNow(Date.now());
      setStep({ kind: "confirm", plan: value, deadline: Date.now() + value.expiresInMs });
    } catch (failure) {
      setStep({ kind: "input" });
      setError(rowActionFailureText(failure));
    }
  }

  async function execute(planned: SystemInfoFirewallPlan): Promise<void> {
    setError(null);
    setStep({ kind: "executing", plan: planned });
    try {
      const value = await api.executeSystemInfoFirewallBlock(bindingHandle, planned.planHandle);
      if (!isSystemInfoFirewallResult(value)) throw new Error("invalid result");
      setStep({ kind: "result", plan: planned, result: value, undoNote: null });
      onChanged();
    } catch (failure) {
      setStep({ kind: "input" });
      setError(`${rowActionFailureText(failure)}请刷新防火墙标签核对规则是否已经加上。`);
      onChanged();
    }
  }

  async function planUndo(planned: SystemInfoFirewallPlan, restoreHandle: string): Promise<void> {
    setError(null);
    try {
      const value = await api.planSystemInfoFirewallRestore(bindingHandle, restoreHandle);
      if (!isSystemInfoFirewallRestorePlan(value)) throw new Error("invalid restore plan");
      setNow(Date.now());
      setStep({ kind: "restore-confirm", plan: planned, restore: value, restoreHandle, deadline: Date.now() + value.expiresInMs });
    } catch (failure) {
      setError(rowActionFailureText(failure));
    }
  }

  async function executeUndo(planned: SystemInfoFirewallPlan, restore: SystemInfoFirewallRestorePlan): Promise<void> {
    setError(null);
    setStep({ kind: "restoring", plan: planned });
    try {
      const value = await api.executeSystemInfoFirewallRestore(bindingHandle, restore.planHandle);
      if (!isSystemInfoFirewallResult(value)) throw new Error("invalid result");
      setStep({ kind: "restored", plan: planned, result: value });
      onChanged();
    } catch (failure) {
      setStep({ kind: "restored", plan: planned, result: { verified: false, detail: rowActionFailureText(failure), restoreHandle: null } });
      onChanged();
    }
  }

  const seconds = (deadline: number) => Math.max(0, Math.ceil((deadline - now) / 1_000));

  return (
    <div className="system-info-detail-backdrop" role="presentation">
      <section className="system-info-detail-dialog system-info-action-dialog" role="dialog" aria-modal="true" aria-label="封禁地址" data-testid="firewall-block-dialog">
        <header>
          <div>
            <p>处置</p>
            <h2>封禁地址</h2>
            <span className="system-info-action-subject">在目标机防火墙上拦截一个地址；只加运行时规则</span>
          </div>
          <button type="button" onClick={onClose} disabled={busy}>关闭</button>
        </header>

        {step.kind === "input" || step.kind === "planning" ? (
          <form className="system-info-action-body" onSubmit={(event) => { event.preventDefault(); void plan(); }}>
            <label>
              要封禁的地址
              <input ref={firstField} value={address} maxLength={45} spellCheck={false} disabled={step.kind === "planning"}
                aria-invalid={address.length > 0 && !addressValid}
                onChange={(event) => setAddress(event.currentTarget.value)} placeholder="例如 203.0.113.7 或 2001:db8::7" />
            </label>
            <fieldset disabled={step.kind === "planning"}>
              <legend>方向</legend>
              {(["inbound", "outbound", "both"] as const).map((key) => (
                <label key={key}>
                  <input type="radio" name="firewall-direction" value={key} checked={direction === key} onChange={() => setDirection(key)} />
                  {FIREWALL_DIRECTION_LABELS[key]}
                </label>
              ))}
            </fieldset>
            <p className="system-info-detail-note">只加运行时规则：重启、防火墙重载或服务重启后会失效。生成计划时会先读取目标机的防火墙和当前 SSH 连接，避免把自己封在外面。</p>
            {step.kind === "planning" ? <div className="system-info-detail-state" role="status">正在读取目标机防火墙并准备计划…</div> : null}
            {error !== null ? <div className="system-info-detail-state error" role="alert">{error}</div> : null}
            <footer>
              <button type="button" onClick={onClose} disabled={step.kind === "planning"}>取消</button>
              <button type="submit" className="is-primary" disabled={step.kind === "planning" || !addressValid}>检查并生成计划</button>
            </footer>
          </form>
        ) : null}

        {step.kind === "confirm" || step.kind === "executing" ? (
          <div className="system-info-action-body">
            <div className="system-info-action-panel is-dangerous">
              <dl>
                <div><dt>地址</dt><dd>{step.plan.address}</dd></div>
                <div><dt>方向</dt><dd>{FIREWALL_DIRECTION_LABELS[step.plan.direction]}</dd></div>
                <div><dt>使用的防火墙</dt><dd>{FIREWALL_BACKEND_LABELS[step.plan.backend]}</dd></div>
                {step.kind === "confirm" ? <div><dt>计划有效期</dt><dd>剩余 {seconds(step.deadline)} 秒</dd></div> : null}
              </dl>
              {step.plan.warnings.length > 0 ? (
                <ul className="system-info-action-warnings">{step.plan.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>
              ) : null}
              <details>
                <summary>具体规则（{step.plan.commands.length} 条）</summary>
                <pre className="system-info-action-output">{step.plan.commands.join("\n")}</pre>
              </details>
            </div>
            {step.kind === "executing" ? <div className="system-info-detail-state" role="status">正在添加规则并回读核对…</div> : null}
            <footer>
              <button ref={cancelButton} type="button" onClick={() => setStep({ kind: "input" })} disabled={step.kind === "executing"}>取消</button>
              <button type="button" className="is-dangerous" disabled={step.kind === "executing"} data-testid="firewall-block-execute"
                onClick={() => { if (step.kind === "confirm") void execute(step.plan); }}>
                {step.kind === "executing" ? "执行中…" : "确认封禁"}
              </button>
            </footer>
          </div>
        ) : null}

        {step.kind === "result" || step.kind === "restore-confirm" || step.kind === "restoring" ? (
          <div className="system-info-action-body">
            <div className={step.kind !== "result" || step.result.verified ? "system-info-action-panel" : "system-info-action-panel is-dangerous"}>
              <p className="system-info-action-summary">
                {step.kind !== "result" ? `已封禁 ${step.plan.address}。`
                  : step.result.verified ? `已封禁 ${step.plan.address}，并在目标机上回读确认规则存在。`
                    : "规则没有全部确认，请在防火墙标签里核对。"}
              </p>
              {step.kind === "result" && step.result.detail.length > 0 ? <dl><div><dt>目标机反馈</dt><dd>{step.result.detail}</dd></div></dl> : null}
              <p className="system-info-detail-note">这些规则只在运行时生效，重启或防火墙重载后会失效。</p>
              {step.kind === "result" && step.undoNote !== null ? <p className="system-info-detail-note">{step.undoNote}</p> : null}
            </div>
            {step.kind === "restore-confirm" ? (
              <div className="system-info-action-panel is-dangerous">
                <p>将删除本次为 {step.restore.address} 添加的规则（{FIREWALL_DIRECTION_LABELS[step.restore.direction]}），不改动其他规则。计划剩余 {seconds(step.deadline)} 秒。</p>
              </div>
            ) : null}
            {step.kind === "restoring" ? <div className="system-info-detail-state" role="status">正在删除规则并回读核对…</div> : null}
            {error !== null ? <div className="system-info-detail-state error" role="alert">{error}</div> : null}
            <footer>
              {step.kind === "restore-confirm" ? (
                <>
                  <button ref={cancelButton} type="button" onClick={() => setStep({ kind: "result", plan: step.plan, result: { verified: true, detail: "", restoreHandle: step.restoreHandle }, undoNote: null })}>不撤销</button>
                  <button type="button" className="is-dangerous" onClick={() => void executeUndo(step.plan, step.restore)}>确认撤销封禁</button>
                </>
              ) : (
                <>
                  {step.kind === "result" && step.result.restoreHandle !== null ? (
                    <button type="button" onClick={() => { if (step.kind === "result" && step.result.restoreHandle !== null) void planUndo(step.plan, step.result.restoreHandle); }}>撤销封禁…</button>
                  ) : null}
                  <button type="button" className="is-primary" onClick={onClose} disabled={step.kind === "restoring"}>关闭</button>
                </>
              )}
            </footer>
          </div>
        ) : null}

        {step.kind === "restored" ? (
          <div className="system-info-action-body">
            <div className={step.result.verified ? "system-info-action-panel" : "system-info-action-panel is-dangerous"}>
              <p className="system-info-action-summary">
                {step.result.verified ? `已删除为 ${step.plan.address} 添加的规则，并回读确认不再存在。` : "撤销没有全部确认，请在防火墙标签里核对。"}
              </p>
              {step.result.detail.length > 0 ? <dl><div><dt>目标机反馈</dt><dd>{step.result.detail}</dd></div></dl> : null}
            </div>
            <footer><button type="button" className="is-primary" onClick={onClose}>关闭</button></footer>
          </div>
        ) : null}
      </section>
    </div>
  );
}
