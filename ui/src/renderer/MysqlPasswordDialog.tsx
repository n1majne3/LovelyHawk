import { useEffect, useRef, useState } from "react";
import type {
  MySqlAccountInput, MySqlPasswordPlanView, MySqlPasswordRestorePlanView,
  MySqlPasswordResult, MySqlPasswordRestoreResult, MySqlProfileSummary,
  MySqlRuntimeApi, MySqlRuntimeRequest, MySqlRuntimeResponse,
} from "../shared/mysql-runtime-contract";
import { useModalScrim } from "./modal-scrim";

export const savedUpdateText = { "not-requested": "未要求更新", updated: "已保存连接已更新为新口令", "profile-changed": "连接配置已被其他修改改变，未更新", "skipped-verification-not-passed": "复核未通过，未更新", failed: "更新已保存口令失败" } as const;
export const unverifiableReasonText = { path: "该账号的来源限制使当前连接无法复核新口令" } as const;
export function passwordRules(password: string, confirm: string, user: string): string[] {
  const rules: string[] = [];
  if (/[-￿]/u.test(password)) rules.push("口令只能使用英文字母、数字和英文符号");
  if (password.length < 12 || password.length > 1024) rules.push("口令需为 12–1024 个字符");
  if ([...password].some(c => c.charCodeAt(0) < 0x20 || (c.charCodeAt(0) >= 0x7f && c.charCodeAt(0) <= 0x9f))) rules.push("口令不能包含控制字符");
  const classes = [/[A-Z]/u, /[a-z]/u, /[0-9]/u, /[^A-Za-z0-9]/u].filter(re => re.test(password)).length;
  if (classes < 3) rules.push("口令需至少包含大写、小写、数字、其他字符中的三类");
  if (user && password.toLowerCase().includes(user.toLowerCase())) rules.push("口令不能包含账号用户名");
  if (password !== confirm) rules.push("两次输入的口令不一致");
  return rules;
}
export type PasswordDirty = "none" | "dirty" | "busy";
export function rejectionTarget(code: string | null): "unknown" | "input" { return code === "unknown-state" ? "unknown" : "input"; }
export function planPasswordRequest(bindingHandle: string, profile: MySqlProfileSummary, account: MySqlAccountInput, password: string, updateSaved: boolean): MySqlRuntimeRequest {
  return { action: "plan-password", bindingHandle, profileHandle: profile.profileHandle, account, password, updateSavedPassword: updateSaved && account.user === profile.username };
}
export function restoreAvailable(held: { result: MySqlPasswordResult; restoreUsed: boolean }, remaining: number): boolean {
  return !held.restoreUsed && held.result.restoreHandle !== null && remaining > 0;
}
export function closeNeedsConfirm(step: { kind: string; held?: { result: MySqlPasswordResult; restoreUsed: boolean; restoreDeadline: number } }, now: number): boolean {
  return step.kind === "result" && !!step.held && step.held.result.restoreHandle !== null && !step.held.restoreUsed && step.held.restoreDeadline > now;
}
type ResultState = { result: MySqlPasswordResult; restoreDeadline: number; restoreUsed: boolean };
type Step =
  | { kind: "input" }
  | { kind: "confirm"; planHandle: string; plan: MySqlPasswordPlanView; deadline: number }
  | { kind: "executing" }
  | { kind: "result"; held: ResultState }
  | { kind: "unknown" }
  | { kind: "restore-confirm"; planHandle: string; plan: MySqlPasswordRestorePlanView; deadline: number; held: ResultState }
  | { kind: "restoring" }
  | { kind: "restore-result"; result: MySqlPasswordRestoreResult };

export function MysqlPasswordDialog({ api, bindingHandle, profile, targetLabel, onClose, onDirty, onProfile, onInvalidate, ask }: {
  api: MySqlRuntimeApi; bindingHandle: string; profile: MySqlProfileSummary; targetLabel: string;
  onClose(): void; onDirty(dirty: PasswordDirty): void; onProfile(profile: MySqlProfileSummary): void; onInvalidate(): void;
  ask(title: string, detail: string, confirm: string): Promise<boolean>;
}): React.JSX.Element {
  useModalScrim();
  const [step, setStep] = useState<Step>({ kind: "input" });
  const [accountUser, setAccountUser] = useState(profile.username);
  const [accountHost, setAccountHost] = useState("localhost");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [updateSaved, setUpdateSaved] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [remaining, setRemaining] = useState(0);
  const [busy, setBusy] = useState(false);
  const dialogRef = useRef<HTMLElement>(null);
  const firstInput = useRef<HTMLInputElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const dirtyKind: PasswordDirty = step.kind === "executing" || step.kind === "restoring" ? "busy"
    : password !== "" || accountUser !== profile.username || accountHost !== "localhost" || step.kind !== "input" ? "dirty" : "none";
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
  const run = async (request: MySqlRuntimeRequest): Promise<{ response: MySqlRuntimeResponse | null; code: string | null }> => {
    setBusy(true); setError(null);
    try {
      const response = await api.mysqlRuntime(request);
      if (response.kind === "rejected") { setError(response.detail); return { response: null, code: response.code }; }
      return { response, code: null };
    } catch { setError("请求失败或返回无法核实的结果，请刷新后重试。"); return { response: null, code: null }; }
    finally { setBusy(false); }
  };
  const plan = async (): Promise<void> => {
    if (!accountUser.trim() || !accountHost.trim()) { setError("请填写账号用户名和账号来源主机。"); return; }
    const problems = passwordRules(password, confirm, accountUser);
    if (problems.length) { setError(`口令不符合规则：${problems[0]}`); return; }
    const { response } = await run(planPasswordRequest(bindingHandle, profile, { user: accountUser, host: accountHost }, password, updateSaved));
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
      if (!(await ask("关闭后将无法再恢复旧口令", "恢复旧口令只能在限定时间内进行一次。关闭对话框后本次机会即失效，需重新修改口令。", "仍然关闭"))) return;
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
    <p>目标主机：{targetLabel} · 连接：{profile.name}（{profile.username}@{profile.host}:{profile.port}）</p>
    {step.kind === "input" ? <>
      <form className="database-fields" onSubmit={event => { event.preventDefault(); void plan(); }}>
        <label>账号用户名<input ref={firstInput} required maxLength={128} autoComplete="off" value={accountUser} onChange={event => setAccountUser(event.target.value)} /></label>
        <label>账号来源主机<input required maxLength={255} autoComplete="off" spellCheck={false} placeholder="例如 localhost 或 %" value={accountHost} onChange={event => setAccountHost(event.target.value)} /></label>
        <label>新口令<input type="password" required maxLength={1024} autoComplete="new-password" value={password} onChange={event => setPassword(event.target.value)} /></label>
        <label>再次输入新口令<input type="password" required maxLength={1024} autoComplete="new-password" value={confirm} onChange={event => setConfirm(event.target.value)} /></label>
        <p className="database-hint">账号来源主机是 MySQL 账号的 host 部分（例如 localhost、%、192.168.%），决定修改哪一个账号，不是连接地址。口令需为 12–1024 个字符，仅限英文字母、数字和英文符号，至少包含大写、小写、数字、符号中的三类，不能包含账号用户名。</p>
        {accountUser === profile.username ? <label className="database-check"><input type="checkbox" checked={updateSaved} onChange={event => setUpdateSaved(event.target.checked)} />同时更新已保存的连接口令</label> : null}
        <div className="database-toolbar"><button type="submit" disabled={busy}>检查并生成计划</button><button type="button" onClick={() => void close()} disabled={busy}>取消</button></div>
      </form>
    </> : null}
    {step.kind === "confirm" ? <>
      <p>即将在 {targetLabel} 的 {profile.host}:{profile.port} 上修改 {step.plan.product} 账号 {step.plan.account} 的口令，认证插件 {step.plan.plugin}。已经连上的会话不受影响，业务程序下次用旧口令连接会失败，请同步更新应用配置。</p>
      {step.plan.warnings.length ? <ul>{step.plan.warnings.map(warning => <li key={warning}>{warning}</li>)}</ul> : null}
      <p>{step.plan.restorable ? "修改提交后可在限定时间内恢复旧口令。" : "改后无法取回旧口令，无法自动恢复。"}{step.plan.updateSavedPassword ? "复核通过后将同时更新已保存的连接口令。" : ""}</p>
      <p role="status">计划剩余 {Math.ceil(remaining / 1000)} 秒。</p>
      <div className="database-toolbar"><button ref={cancelRef} type="button" onClick={() => { setStep({ kind: "input" }); }}>取消</button><button type="button" disabled={busy} onClick={() => void execute(step.planHandle)}>确认修改</button></div>
    </> : null}
    {step.kind === "executing" || step.kind === "restoring" ? <p role="status">正在{step.kind === "executing" ? "修改" : "恢复"}，不能取消。</p> : null}
    {step.kind === "unknown" ? <>
      <p role="alert">口令修改的执行结果未确认，数据库上的口令可能已经改变。请关闭本对话框，刷新连接列表并核对账号状态后再判断是否需要恢复或重试，不要重复执行。</p>
      <div className="database-toolbar"><button type="button" onClick={() => { onDirty("none"); onClose(); }}>关闭</button></div>
    </> : null}
    {step.kind === "result" ? <>
      {step.held.result.verification.state === "passed" ? <p role="status">口令已修改并用新口令完成独立登录复核。</p>
        : step.held.result.verification.state === "rejected" ? <p role="alert">新口令认证被数据库拒绝，口令状态可能不一致。建议恢复旧口令或重新修改。</p>
        : <p role="alert">口令修改已提交，但无法确认新口令是否可登录（{step.held.result.verification.state === "unverifiable" ? unverifiableReasonText[step.held.result.verification.reason] : ""}）。建议恢复旧口令或刷新核对后再操作。</p>}
      <p>已保存口令：{savedUpdateText[step.held.result.savedPassword]}。</p>
      {step.held.result.restoreUnavailable ? <p role="alert">本次的自动恢复状态未能保留，旧口令无法再自动恢复。</p> : null}
      {!step.held.result.journalRecorded ? <p role="alert">本次操作未能写入本机操作记录，请人工核对账号状态。</p> : null}
      {step.held.restoreUsed ? <p role="status">恢复计划已取消，自动恢复旧口令不再可用。</p> : null}
      <div className="database-toolbar">
        {restoreAvailable(step.held, remaining) ? <button type="button" disabled={busy} onClick={() => void planRestore(step.held)}>恢复旧口令（剩余 {Math.ceil(remaining / 1000)} 秒）</button> : null}
        <button type="button" onClick={() => void close()}>关闭</button>
      </div>
    </> : null}
    {step.kind === "restore-confirm" ? <>
      <p>即将把账号 {step.plan.account} 的口令恢复为修改前保存的校验值；这是本次唯一一次自动恢复机会。{step.plan.savedPasswordWasUpdated ? "已保存的连接口令已改为新口令，恢复复核通过后会自动改回修改前的已存口令。" : ""}</p>
      <p role="status">计划剩余 {Math.ceil(remaining / 1000)} 秒。</p>
      <div className="database-toolbar"><button ref={cancelRef} type="button" onClick={() => setStep({ kind: "result", held: { ...step.held, restoreUsed: true } })}>取消</button><button type="button" disabled={busy} onClick={() => void executeRestore(step.planHandle)}>确认恢复</button></div>
    </> : null}
    {step.kind === "restore-result" ? <>
      {step.result.verified ? <p role="status">旧口令已恢复并完成复核。</p>
        : <p role="alert">恢复已提交，但未能完成复核。请刷新核对账号状态。</p>}
      <p>已保存口令：{step.result.savedPasswordRestored ? "已保存的连接口令已改回修改前的值" : "未改回"}。</p>
      {!step.result.journalRecorded ? <p role="alert">本次操作未能写入本机操作记录，请人工核对账号状态。</p> : null}
      <div className="database-toolbar"><button type="button" onClick={() => void close()}>关闭</button></div>
    </> : null}
    {error ? <p role="alert" className="database-error">{error}</p> : null}
  </section></div>;
}
