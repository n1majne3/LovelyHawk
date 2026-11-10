import { useState } from "react";

import type { SystemInfoRowActionState } from "./system-info-row-actions";
import { useModalScrim } from "./modal-scrim";
import { planExpiryLabel } from "./plan-expiry";

export interface SystemInfoRowActionDialogProps {
  state: SystemInfoRowActionState;
  onConfirm: () => void;
  onSubmitPassword: (password: string) => void;
  onCopyOutput: (text: string) => void;
  onClose: () => void;
}

/**
 * One dialog for both kinds of row action.
 *
 * A read-only action shows what the target printed, whole, with the one
 * notice that matters when it was cut short. A change shows the plan first —
 * in the words of the layer that will carry it out and verify it — and only
 * runs after the operator has read it and confirmed, then shows what the
 * target reported afterwards.
 */
export function SystemInfoRowActionDialog({
  state,
  onConfirm,
  onSubmitPassword,
  onCopyOutput,
  onClose,
}: SystemInfoRowActionDialogProps) {
  useModalScrim();
  const { action, subject, inspection, plan, receipt, busy, error, needsPassword } = state;
  const [password, setPassword] = useState("");
  const [passwordAgain, setPasswordAgain] = useState("");
  const isChange = action.kind === "change";
  const passwordMismatch = passwordAgain.length > 0 && password !== passwordAgain;
  const passwordReady = password.length >= 12 && password === passwordAgain;
  return (
    <div className="system-info-detail-backdrop" role="presentation">
      <section
        className="system-info-detail-dialog system-info-action-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={action.label}
        data-testid="system-info-row-action-dialog"
      >
        <header>
          <div>
            <p>{isChange ? "处置" : "排查"}</p>
            <h2>{action.label}</h2>
            <span className="system-info-action-subject" title={subject}>{subject}</span>
          </div>
          <button type="button" onClick={onClose} disabled={busy && isChange}>关闭</button>
        </header>

        {!isChange ? (
          <div className="system-info-action-body">
            {busy ? <div className="system-info-detail-state" role="status">正在向目标机查询…</div> : null}
            {error !== null ? <div className="system-info-detail-state error" role="alert">{error}</div> : null}
            {inspection !== null ? (
              <>
                {inspection.truncated ? (
                  <p className="system-info-truncated">输出太长，只显示了目标机返回的前一部分。</p>
                ) : null}
                <pre className="system-info-action-output" data-testid="system-info-row-action-output">
                  {inspection.output.length > 0 ? inspection.output : "（目标机没有返回任何内容）"}
                </pre>
              </>
            ) : null}
            <footer>
              <button
                type="button"
                disabled={inspection === null || inspection.output.length === 0}
                onClick={() => { if (inspection !== null) onCopyOutput(inspection.output); }}
              >
                复制输出
              </button>
            </footer>
          </div>
        ) : receipt === null ? (
          <div className="system-info-action-body">
            {needsPassword && plan === null ? (
              <div className="system-info-action-panel">
                <p className="system-info-action-summary">
                  输入要设置的新口令。口令只在本机计算成 SHA-512 crypt 散列，目标机收到的只有散列，不会看到明文。
                </p>
                <dl>
                  <div>
                    <dt><label htmlFor="row-password">新口令</label></dt>
                    <dd>
                      <input
                        id="row-password"
                        type="password"
                        autoComplete="new-password"
                        value={password}
                        disabled={busy}
                        onChange={(event) => setPassword(event.target.value)}
                        data-testid="system-info-row-password"
                      />
                    </dd>
                  </div>
                  <div>
                    <dt><label htmlFor="row-password-again">再次输入</label></dt>
                    <dd>
                      <input
                        id="row-password-again"
                        type="password"
                        autoComplete="new-password"
                        value={passwordAgain}
                        disabled={busy}
                        onChange={(event) => setPasswordAgain(event.target.value)}
                        data-testid="system-info-row-password-again"
                      />
                    </dd>
                  </div>
                  <div>
                    <dt>要求</dt>
                    <dd>12–1024 字节，不含控制字符，至少包含大写/小写/数字/其他中的三类，不含账号名。锁定账户改口令后仍是锁定状态。</dd>
                  </div>
                </dl>
                {passwordMismatch ? (
                  <p className="system-info-detail-state error" role="alert">两次输入的口令不一致。</p>
                ) : null}
              </div>
            ) : null}
            {plan === null && error === null && !needsPassword ? (
              <div className="system-info-detail-state" role="status">正在读取目标机上的当前状态并准备计划…</div>
            ) : null}
            {plan !== null ? (
              <div className={plan.dangerous ? "system-info-action-panel is-dangerous" : "system-info-action-panel"}>
                <dl>
                  {/* Worded by the layer that will carry the change out and
                      verify it, so it is shown as that layer stated it. */}
                  <div><dt>将要执行</dt><dd>{plan.summary}</dd></div>
                  <div><dt>风险</dt><dd>{plan.dangerous ? "高风险，需要确认" : "常规操作，仍需确认"}</dd></div>
                  <div><dt>出错后如何还原</dt><dd>{plan.restoreDescription ?? "无备份，执行后不可自动还原"}</dd></div>
                  <div><dt>计划有效期</dt><dd>{planExpiryLabel(plan.expiresInSeconds)}</dd></div>
                </dl>
              </div>
            ) : null}
            {error !== null ? <div className="system-info-detail-state error" role="alert">{error}</div> : null}
            <footer>
              <button type="button" onClick={onClose} disabled={busy}>取消</button>
              {needsPassword && plan === null ? (
                <button
                  type="button"
                  className="is-primary"
                  disabled={busy || !passwordReady}
                  data-testid="system-info-row-password-submit"
                  onClick={() => {
                    const value = password;
                    setPassword("");
                    setPasswordAgain("");
                    onSubmitPassword(value);
                  }}
                >
                  {busy ? "正在计划…" : "生成计划"}
                </button>
              ) : (
                <button
                  type="button"
                  className="is-dangerous"
                  disabled={busy || plan === null}
                  data-testid="system-info-row-action-execute"
                  onClick={onConfirm}
                >
                  {busy && plan !== null ? "执行中…" : "确认并执行"}
                </button>
              )}
            </footer>
          </div>
        ) : (
          <div className="system-info-action-body">
            <div className={receipt.verified ? "system-info-action-panel" : "system-info-action-panel is-dangerous"}>
              <p className="system-info-action-summary">
                {receipt.verified ? "已完成，并在目标机上核对过。" : "没有完成。"}
              </p>
              <dl>
                <div><dt>目标机反馈</dt><dd>{receipt.detail}</dd></div>
                {receipt.verified ? null : (
                  <div>
                    <dt>是否已还原</dt>
                    <dd>{receipt.restored ? "已还原到操作前的状态" : "未能自动还原，请手动检查"}</dd>
                  </div>
                )}
              </dl>
            </div>
            <footer>
              <button type="button" className="is-primary" onClick={onClose}>关闭</button>
            </footer>
          </div>
        )}
      </section>
    </div>
  );
}
