import { useEffect, useRef, useState } from "react";
import type {
  PostgresqlPasswordPlanView, PostgresqlPasswordRestorePlanView, PostgresqlPasswordRole,
  PostgresqlPasswordResult, PostgresqlPasswordRestoreResult, PostgresqlProfileSummary,
  PostgresqlRuntimeApi, PostgresqlRuntimeResponse, PostgresqlPasswordWarning,
} from "../shared/postgresql-runtime-contract";
import { useModalScrim } from "./modal-scrim";

const warningText: Record<PostgresqlPasswordWarning, string> = {
  "md5-weak": "数据库将存储 md5 口令校验值，强度偏弱；建议先评估升级到 scram-sha-256。",
  "replication-role": "目标角色具有复制权限，口令用于复制连接，修改后需要同步维护复制端配置。",
  "superuser-role": "目标角色是超级用户；其口令泄露或失效影响面最大。",
  "connection-role": "目标就是当前连接账号；修改立即影响此连接以后的认证。",
  "not-restorable": "当前连接账号没有读取旧口令校验值的权限，改后无法取回旧口令。",
};
const reasonText = { "access-rule": "访问规则拒绝新口令连接", network: "网络或连接中断", timeout: "连接或读取超时", other: "其他原因" } as const;
export const savedUpdateText = { "not-requested": "未要求更新", updated: "已保存连接已更新为新口令", "profile-changed": "连接配置已被其他修改改变，未更新", "skipped-verification-not-passed": "复核未通过，未更新", failed: "更新已保存口令失败" } as const;
export const savedRestoreText = { "not-applicable": "无已保存口令需要处理", restored: "已保存口令已改回修改前的值", "profile-changed": "连接配置已被其他修改改变，未改回", "skipped-verification-not-passed": "回读复核未通过，未改回", failed: "改回已保存口令失败" } as const;
export function passwordRules(password: string, confirm: string, roleName: string): string[] {
  const bytes = new TextEncoder().encode(password).length;
  const rules: string[] = [];
  if (bytes < 12 || bytes > 1024) rules.push("口令需为 12–1024 个 UTF-8 字节");
  if ([...password].some(c => c.charCodeAt(0)! < 0x20 || (c.charCodeAt(0)! >= 0x7f && c.charCodeAt(0)! <= 0x9f))) rules.push("口令不能包含控制字符");
  const classes = [/[A-Z]/u, /[a-z]/u, /[0-9]/u, /[^A-Za-z0-9]/u].filter(re => re.test(password)).length;
  if (classes < 3) rules.push("口令需至少包含大写、小写、数字、其他字符中的三类");
  if (roleName && password.toLowerCase().includes(roleName.toLowerCase())) rules.push("口令不能包含账号名称");
  if (password !== confirm) rules.push("两次输入的口令不一致");
  return rules;
}
export type PasswordDirty = "none" | "dirty" | "busy";
export function rejectionTarget(code: string | null): "unknown" | "input" { return code === "unknown-state" ? "unknown" : "input"; }
export function restoreAvailable(held: { result: PostgresqlPasswordResult; restoreUsed: boolean }, remaining: number): boolean {
  return !held.restoreUsed && held.result.restoreHandle !== null && remaining > 0;
}
export function closeNeedsConfirm(step: { kind: string; held?: { result: PostgresqlPasswordResult; restoreUsed: boolean; restoreDeadline: number } }, now: number): boolean {
  return step.kind === "result" && !!step.held && step.held.result.restoreHandle !== null && !step.held.restoreUsed && step.held.restoreDeadline > now;
}
type ResultState = { result: PostgresqlPasswordResult; restoreDeadline: number; restoreUsed: boolean; unknown?: false };
type Step =
  | { kind: "input" }
  | { kind: "confirm"; planHandle: string; plan: PostgresqlPasswordPlanView; deadline: number }
  | { kind: "executing" }
  | { kind: "result"; held: ResultState }
  | { kind: "unknown" }
  | { kind: "restore-confirm"; planHandle: string; plan: PostgresqlPasswordRestorePlanView; deadline: number; held: ResultState }
  | { kind: "restoring" }
  | { kind: "restore-result"; result: PostgresqlPasswordRestoreResult };

export function PostgresqlPasswordDialog({ api, bindingHandle, profile, role, roleName, targetLabel, onClose, onDirty, onProfile, onInvalidate, ask }: {
  api: PostgresqlRuntimeApi; bindingHandle: string; profile: PostgresqlProfileSummary;
  role: PostgresqlPasswordRole; roleName: string; targetLabel: string;
  onClose(): void; onDirty(dirty: PasswordDirty): void; onProfile(profile: PostgresqlProfileSummary): void;
  onInvalidate(): void;
  ask(title: string, detail: string, confirm: string): Promise<boolean>;
}): React.JSX.Element {
  useModalScrim();
  const [step, setStep] = useState<Step>({ kind: "input" });
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [updateSaved, setUpdateSaved] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [remaining, setRemaining] = useState(0);
  const [busy, setBusy] = useState(false);
  const dialogRef = useRef<HTMLElement>(null);
  const firstInput = useRef<HTMLInputElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const dirtyKind: PasswordDirty = step.kind === "executing" || step.kind === "restoring" ? "busy" : password !== "" || step.kind !== "input" ? "dirty" : "none";
  useEffect(() => { onDirty(dirtyKind); }, [dirtyKind, onDirty]);
  useEffect(() => { firstInput.current?.focus(); }, []);
  useEffect(() => {
    const deadline = step.kind === "confirm" || step.kind === "restore-confirm" ? step.deadline : step.kind === "result" && !step.held.restoreUsed ? step.held.restoreDeadline : 0;
    if (!deadline) { setRemaining(0); return; }
    setRemaining(deadline - Date.now());
    const tick = setInterval(() => setRemaining(Math.max(0, deadline - Date.now())), 500);
    return () => clearInterval(tick);
  }, [step]);
  useEffect(() => {
    if ((step.kind === "confirm" || step.kind === "restore-confirm") && step.deadline && remaining === 0 && step.deadline <= Date.now()) {
      setPassword(""); setConfirm(""); setError("计划已过期，请重新输入口令并生成计划。");
      setStep(step.kind === "restore-confirm" ? { kind: "result", held: { ...step.held, restoreUsed: true } } : { kind: "input" });
    }
  }, [remaining, step]);
  const isConnectionRole = role.kind === "current" || roleName === profile.username;
  const run = async (request: Parameters<PostgresqlRuntimeApi["postgresqlRuntime"]>[0]): Promise<{ response: PostgresqlRuntimeResponse | null; code: string | null }> => {
    setBusy(true); setError(null);
    try {
      const response = await api.postgresqlRuntime(request);
      if (response.kind === "rejected") { setError(response.detail); return { response: null, code: response.code }; }
      return { response, code: null };
    } catch { setError("请求失败或返回无法核实的结果，请刷新后重试。"); return { response: null, code: null }; }
    finally { setBusy(false); }
  };
  const plan = async (): Promise<void> => {
    const problems = passwordRules(password, confirm, roleName);
    if (problems.length) { setError(`口令不符合规则：${problems[0]}`); return; }
    const { response } = await run({ action: "plan-password", bindingHandle, profileHandle: profile.profileHandle, role, password, updateSavedPassword: updateSaved && isConnectionRole });
    setPassword(""); setConfirm("");
    if (response?.kind === "password-plan") setStep({ kind: "confirm", planHandle: response.planHandle, plan: response.plan, deadline: Date.now() + response.expiresInMs });
  };
  const execute = async (planHandle: string): Promise<void> => {
    setStep({ kind: "executing" });
    const { response, code } = await run({ action: "execute-password", bindingHandle, planHandle });
    if (response?.kind === "password-result") {
      setStep({ kind: "result", held: { result: response.result, restoreDeadline: Date.now() + 600_000, restoreUsed: false } });
      if (response.result.profile) onProfile(response.result.profile);
      onInvalidate();
    } else { setStep({ kind: rejectionTarget(code) }); if (code === "unknown-state") onInvalidate(); }
  };
  const planRestore = async (held: ResultState): Promise<void> => {
    const { response } = await run({ action: "plan-password-restore", bindingHandle, restoreHandle: held.result.restoreHandle!, profileHandle: profile.profileHandle });
    if (response?.kind === "password-restore-plan") setStep({ kind: "restore-confirm", planHandle: response.planHandle, plan: response.plan, deadline: Date.now() + response.expiresInMs, held });
    else setStep({ kind: "result", held: { ...held, restoreUsed: true } });
  };
  const executeRestore = async (planHandle: string): Promise<void> => {
    setStep({ kind: "restoring" });
    const { response, code } = await run({ action: "execute-password-restore", bindingHandle, planHandle });
    if (response?.kind === "password-restore-result") {
      setStep({ kind: "restore-result", result: response.result });
      if (response.result.profile) onProfile(response.result.profile);
      onInvalidate();
    } else { setStep({ kind: rejectionTarget(code) }); if (code === "unknown-state") onInvalidate(); }
  };
  const close = async (): Promise<void> => {
    if (closeNeedsConfirm(step, Date.now())) {
      if (!(await ask("关闭后将无法再放回旧口令", "放回旧口令只能在限定时间内进行一次。关闭对话框后本次机会即失效，需重新修改口令。", "仍然关闭"))) return;
    }
    setPassword(""); setConfirm(""); onDirty("none"); onClose();
  };
  const closeRef = useRef(close); closeRef.current = close;
  useEffect(() => {
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === "Escape" && stepRefBusy() === false) { event.preventDefault(); void closeRef.current(); return; }
      if (event.key === "Tab" && dialogRef.current) {
        const focusables = Array.from(dialogRef.current.querySelectorAll<HTMLElement>("button, input, [tabindex]")).filter(el => !el.hasAttribute("disabled"));
        const first = focusables[0], last = focusables[focusables.length - 1];
        if (!first || !last) return;
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    };
    const stepRefBusy = (): boolean => { const current = stepRef.current; return current.kind === "executing" || current.kind === "restoring"; };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);
  const stepRef = useRef(step); stepRef.current = step;
  useEffect(() => { if (step.kind === "confirm" || step.kind === "restore-confirm") cancelRef.current?.focus(); }, [step.kind]);
  return <div className="dialog-backdrop" role="presentation"><section className="dialog" role="dialog" aria-modal="true" aria-label="修改数据库账号口令" ref={dialogRef}>
    <h3>修改数据库账号口令</h3>
    <p>目标主机：{targetLabel} · 连接：{profile.name}（{profile.username}@{profile.host}:{profile.port}）· 账号：{roleName}</p>
    {step.kind === "input" ? <>
      <form className="database-fields" onSubmit={event => { event.preventDefault(); void plan(); }}>
        <label>新口令<input ref={firstInput} type="password" required maxLength={1024} autoComplete="new-password" value={password} onChange={event => setPassword(event.target.value)} /></label>
        <label>再次输入新口令<input type="password" required maxLength={1024} autoComplete="new-password" value={confirm} onChange={event => setConfirm(event.target.value)} /></label>
        <p className="database-hint">口令需为 12–1024 个 UTF-8 字节，不含控制字符，至少包含大写、小写、数字、其他字符中的三类，不能包含账号名称。</p>
        {isConnectionRole ? <label className="database-check"><input type="checkbox" checked={updateSaved} onChange={event => setUpdateSaved(event.target.checked)} />同时更新已保存的连接口令</label> : null}
        <div className="database-toolbar"><button type="submit" disabled={busy}>检查并生成计划</button><button type="button" onClick={() => void close()} disabled={busy}>取消</button></div>
      </form>
    </> : null}
    {step.kind === "confirm" ? <>
      <p>即将在 {targetLabel} 的 {profile.host}:{profile.port}/{profile.database} 上修改账号 {step.plan.roleName} 的口令，格式 {step.plan.format}。已经连上的会话不受影响，业务程序下次用旧口令连接会失败，请同步更新应用配置。</p>
      <ul>{step.plan.warnings.map(warning => <li key={warning}>{warningText[warning]}</li>)}</ul>
      <p>{step.plan.restorable ? "修改提交后可在限定时间内放回旧口令。" : "改后无法取回旧口令，无法自动放回。"}{step.plan.updatesSavedPassword ? "复核通过后将同时更新已保存的连接口令。" : ""}</p>
      <p role="status">计划剩余 {Math.ceil(remaining / 1000)} 秒。</p>
      <div className="database-toolbar"><button ref={cancelRef} type="button" onClick={() => { setStep({ kind: "input" }); }}>取消</button><button type="button" disabled={busy} onClick={() => void execute(step.planHandle)}>确认修改</button></div>
    </> : null}
    {step.kind === "executing" || step.kind === "restoring" ? <p role="status">正在{step.kind === "executing" ? "修改" : "放回"}，不能取消。</p> : null}
    {step.kind === "unknown" ? <>
      <p role="alert">口令修改的执行结果未确认，数据库上的口令可能已经改变。请关闭本对话框，刷新并重新读取数据库状态后再判断是否需要放回或重试，不要重复执行。</p>
      <div className="database-toolbar"><button type="button" onClick={() => { onDirty("none"); onClose(); }}>关闭</button></div>
    </> : null}
    {step.kind === "result" ? <>
      {step.held.result.verification.state === "passed" ? <p role="status">口令已修改并用新口令完成独立登录复核。</p>
        : step.held.result.verification.state === "rejected" ? <p role="alert">新口令认证被数据库拒绝，口令状态可能不一致。建议放回旧口令或重新修改。</p>
        : <p role="alert">口令修改已提交，但无法确认新口令是否可登录（{reasonText[step.held.result.verification.reason ?? "other"]}）。建议放回旧口令或刷新核对后再操作。</p>}
      <p>已保存口令：{savedUpdateText[step.held.result.savedPassword]}。</p>
      {step.held.result.restoreUnavailable ? <p role="alert">本次的自动放回状态未能保留，旧口令无法再自动放回。</p> : null}
      {!step.held.result.journalRecorded ? <p role="alert">本次操作未能写入本机操作记录，请人工核对账号状态。</p> : null}
      {step.held.restoreUsed ? <p role="status">放回计划已取消，自动放回旧口令不再可用。</p> : null}
      <div className="database-toolbar">
        {restoreAvailable(step.held, remaining) ? <button type="button" disabled={busy} onClick={() => void planRestore(step.held)}>放回旧口令（剩余 {Math.ceil(remaining / 1000)} 秒）</button> : null}
        <button type="button" onClick={() => void close()}>关闭</button>
      </div>
    </> : null}
    {step.kind === "restore-confirm" ? <>
      <p>即将把账号 {step.plan.roleName} 的口令放回为修改前保存的校验值；这是本次唯一一次自动放回机会。{step.plan.savedPasswordWasUpdated ? "已保存的连接口令已改为新口令，回读复核通过后会自动改回修改前的已存口令。" : ""}</p>
      <p role="status">计划剩余 {Math.ceil(remaining / 1000)} 秒。</p>
      <div className="database-toolbar"><button ref={cancelRef} type="button" onClick={() => setStep({ kind: "result", held: { ...step.held, restoreUsed: true } })}>取消</button><button type="button" disabled={busy} onClick={() => void executeRestore(step.planHandle)}>确认放回</button></div>
    </> : null}
    {step.kind === "restore-result" ? <>
      {step.result.verification === "passed" ? <p role="status">旧口令已放回并回读复核一致。</p>
        : step.result.verification === "mismatch" ? <p role="alert">放回已提交，但回读校验值与旧值不一致。请刷新核对账号状态。</p>
        : <p role="alert">放回已提交，但未能完成回读复核。请刷新核对账号状态。</p>}
      <p>已保存口令：{savedRestoreText[step.result.savedPassword]}。</p>
      {!step.result.journalRecorded ? <p role="alert">本次操作未能写入本机操作记录，请人工核对账号状态。</p> : null}
      <div className="database-toolbar"><button type="button" onClick={() => void close()}>关闭</button></div>
    </> : null}
    {error ? <p role="alert" className="database-error">{error}</p> : null}
  </section></div>;
}
