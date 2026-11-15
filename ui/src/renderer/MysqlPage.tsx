import { TransientNotice } from "./NotificationCenter";
import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState, useSyncExternalStore } from "react";
import type { MySqlInstanceReview, MySqlPasswordChange, MySqlProfileInput, MySqlProfileSummary, MySqlReviewLevel, MySqlRuntimeApi } from "../shared/mysql-runtime-contract";
import { MysqlRuntimeController } from "./mysql-runtime-controller";
import { DialogHost } from "./DialogHost";
import { useConfirmDialog } from "./use-confirm-dialog";
import { useModalScrim } from "./modal-scrim";
import { MysqlPasswordDialog, type PasswordDirty } from "./MysqlPasswordDialog";
import "./database-page.css";

export interface MysqlPageHandle { beforeDeactivate(): Promise<boolean> }
export interface MysqlPageProps { api: MySqlRuntimeApi; bindingHandle: string | null; targetLabel: string }
interface Editor { handle: string | null; input: MySqlProfileInput; initial: string; password: string; passwordAction: "keep" | "replace" | "remove"; unassigned: boolean; hasCa: boolean }
const initial: MySqlProfileInput = { name: "", host: "127.0.0.1", port: 3306, username: "root", database: "", tlsMode: "verify-full", caPem: null };

function MysqlProfileEditor({ editor, saving, error, onChange, onSubmit, onCancel, nameInput, dialogRef }: {
  editor: Editor; saving: boolean; error: string | null; nameInput: React.RefObject<HTMLInputElement | null>; dialogRef: React.RefObject<HTMLElement | null>;
  onChange(next: Editor): void; onSubmit(): void; onCancel(): void;
}): React.JSX.Element {
  useModalScrim();
  const field = (key: keyof MySqlProfileInput, value: string | number | null): void => onChange({ ...editor, input: { ...editor.input, [key]: value } });
  return <div className="dialog-backdrop" role="presentation"><section className="dialog" role="dialog" aria-modal="true" aria-label={editor.handle ? "编辑数据库连接" : "新建数据库连接"} ref={dialogRef}>
    <h3>{editor.handle ? "编辑数据库连接" : "新建数据库连接"}</h3>
    {editor.unassigned ? <p>此旧连接尚未关联 SSH 主机。请核对以下地址；保存后将关联到当前主机。</p> : null}
    <p>数据库地址从 SSH 主机访问；127.0.0.1 指 SSH 主机自身。口令只用于数据库认证，加密保存在本机。</p>
    <form onSubmit={event => { event.preventDefault(); onSubmit(); }}>
      <fieldset disabled={saving}>
        <div className="database-fields">
          <label>连接名称<input ref={nameInput} required maxLength={256} value={editor.input.name} onChange={event => field("name", event.target.value)} /></label>
          <label>数据库地址<input required maxLength={253} value={editor.input.host} onChange={event => field("host", event.target.value)} /></label>
          <label>端口<input type="number" required min={1} max={65535} value={editor.input.port || ""} onChange={event => field("port", Number(event.target.value))} /></label>
          <label>数据库用户名<input required maxLength={128} autoComplete="off" value={editor.input.username} onChange={event => field("username", event.target.value)} /></label>
          <label>数据库名称（可选）<input maxLength={128} value={editor.input.database} onChange={event => field("database", event.target.value)} /></label>
        </div>
        <fieldset><legend>数据库加密</legend>
          <label className="database-check"><input type="radio" name="mysql-tls-mode" checked={editor.input.tlsMode === "verify-full"} onChange={() => onChange({ ...editor, input: { ...editor.input, tlsMode: "verify-full" } })} />TLS · 校验证书和地址</label>
          <label className="database-check"><input type="radio" name="mysql-tls-mode" checked={editor.input.tlsMode === "ssh-loopback"} onChange={() => onChange({ ...editor, input: { ...editor.input, tlsMode: "ssh-loopback", caPem: null } })} />仅 SSH 加密 · 数据库必须在回环地址</label>
        </fieldset>
        {editor.input.tlsMode === "verify-full" ? <>
          <label>CA 证书（PEM，可选）<textarea rows={4} maxLength={65536} autoComplete="off" spellCheck={false} placeholder="留空使用系统信任的证书机构；私有证书可粘贴一张 CA 公钥证书。" value={editor.input.caPem ?? ""} onChange={event => field("caPem", event.target.value || null)} /></label>
          {editor.hasCa ? <p>此连接已保存一张 CA 证书，证书内容不回显。粘贴新证书可替换；保存时留空将移除已保存证书，改用系统信任的证书机构。</p> : null}
        </> : <p>SSH 加密通道保护字面回环地址（127.0.0.0/8 或 ::1）上的数据库连接；SSH 主机到数据库这一段不使用 TLS。</p>}
        <fieldset><legend>口令处理</legend>
          <label className="database-check"><input type="radio" name="mysql-password-action" checked={editor.passwordAction === "keep"} onChange={() => onChange({ ...editor, passwordAction: "keep", password: "" })} />{editor.handle ? "保留已保存口令" : "暂不保存口令"}</label>
          <label className="database-check"><input type="radio" name="mysql-password-action" checked={editor.passwordAction === "replace"} onChange={() => onChange({ ...editor, passwordAction: "replace" })} />设置新口令</label>
          <label className="database-check"><input type="radio" name="mysql-password-action" checked={editor.passwordAction === "remove"} onChange={() => onChange({ ...editor, passwordAction: "remove", password: "" })} />移除已保存口令</label>
        </fieldset>
        {editor.passwordAction === "replace" ? <label>新口令<input type="password" required maxLength={16384} autoComplete="new-password" value={editor.password} onChange={event => onChange({ ...editor, password: event.target.value })} /></label> : null}
        {error ? <p role="alert" className="database-error">{error}</p> : null}
        <div className="database-toolbar"><button type="submit">{saving ? "正在保存…" : editor.unassigned ? "保存并关联此主机" : "保存连接"}</button><button type="button" onClick={() => onCancel()}>取消</button></div>
      </fieldset>
    </form>
  </section></div>;
}

const reviewLevelText: Record<MySqlReviewLevel, string> = { info: "参考", review: "需人工核对", high: "高风险" };
const reviewLevelClass: Record<MySqlReviewLevel, string> = { info: "is-info", review: "is-review", high: "is-high" };
const reviewVariables = ["general_log", "general_log_file", "log_output", "local_infile", "secure_file_priv"] as const;
export function MysqlReviewPanel({ profile, review, onClose }: { profile: MySqlProfileSummary; review: MySqlInstanceReview; onClose(): void }): React.JSX.Element {
  return <section className="database-result" aria-label={`实例检查：${profile.name}`}>
    <h3>实例检查：{profile.name}</h3>
    <p>{review.product} {review.serverVersion} · 连接账号 {review.connecting} · 账号 {review.accounts.length}/{review.accountTotal} 个 · 自定义函数 {review.udfTotal} 个</p>
    <p role="note">以下均为需人工核对的线索，不代表已确认的风险结论；未发现条目也不代表无风险。</p>
    <h4>线索</h4>
    {review.findings.length ? <ul className="database-findings">{review.findings.map((finding, index) => <li key={`${finding.code}-${index}`}>
      <span className={`database-badge ${reviewLevelClass[finding.level]}`}>{reviewLevelText[finding.level]}</span> <code>{finding.code}</code> {finding.detail}
    </li>)}</ul> : <p>未返回线索条目。</p>}
    <h4>数据库账号（{review.accounts.length}/{review.accountTotal}）</h4>
    {review.accounts.length ? <div className="database-table" tabIndex={0} role="region" aria-label="数据库账号，可横向滚动"><table>
      <thead><tr><th>账号</th><th>认证插件</th><th>高危权限</th><th>状态</th></tr></thead>
      <tbody>{review.accounts.map((account, index) => <tr key={`${account.user}@${account.host}-${index}`}>
        <th scope="row">{account.user}@{account.host}</th><td>{account.plugin}</td>
        <td>{[account.superuser ? "SUPER" : null, account.filePriv ? "FILE" : null, account.grantPriv ? "GRANT" : null].filter(Boolean).join("、") || "—"}</td>
        <td>{account.emptySecret ? <span className="database-badge is-high">空口令</span> : null}{account.locked === true ? <> <span className="database-badge">已锁定</span></> : account.locked === null ? <> <span className="database-badge">锁定状态未知</span></> : null}{!account.emptySecret && account.locked === false ? "—" : null}</td>
      </tr>)}</tbody></table></div> : <p>未取得账号列表。</p>}
    {review.udfs.length || review.udfTotal ? <>
      <h4>自定义函数 UDF（{review.udfs.length}/{review.udfTotal}）</h4>
      {review.udfs.length ? <ul>{review.udfs.map((udf, index) => <li key={`${udf.name}-${index}`}><code>{udf.name}</code> · 动态库 {udf.library}</li>)}</ul> : <p>仅取得数量，未列出条目。</p>}
    </> : null}
    <h4>重点变量</h4>
    <dl className="database-variables">{reviewVariables.map(name => <div key={name}><dt><code>{name}</code></dt><dd>{name in review.variables ? (review.variables[name] === "" ? "空值" : review.variables[name]) : "未提供"}</dd></div>)}</dl>
    {review.gaps.length ? <><h4>读取缺口</h4><ul>{review.gaps.map((gap, index) => <li key={index}>无法读取：{gap}</li>)}</ul></> : null}
    {review.log ? <><h4>错误日志线索</h4>
      <p>日志 {review.log.path} · 读取末尾 {review.log.tailBytes} 字节。</p>
      {review.log.denied.length ? <p>连接被拒来源：{review.log.denied.map(item => `${item.user}@${item.host} × ${item.count}`).join("、")}</p> : null}
      {review.log.hits.length ? <ul>{review.log.hits.map((hit, index) => <li key={index}><code>{hit.kind}</code> {hit.excerpt}</li>)}</ul> : null}
      {!review.log.denied.length && !review.log.hits.length ? <p>日志末尾未检出相关条目。</p> : null}
    </> : null}
    <div className="database-toolbar"><button type="button" onClick={onClose}>关闭检查结果</button></div>
  </section>;
}

export const MysqlPage = forwardRef<MysqlPageHandle, MysqlPageProps>(function MysqlPage({ api, bindingHandle, targetLabel }, ref) {
  const controller = useMemo(() => new MysqlRuntimeController(api, bindingHandle ?? ""), [api, bindingHandle]);
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const [editor, setEditor] = useState<Editor | null>(null);
  const activeController = useRef(controller); activeController.current = controller;
  const editorRef = useRef(editor); editorRef.current = editor;
  const savingTask = useRef<Promise<void> | null>(null);
  const [saving, setSaving] = useState(false);
  const [dialogBusy, setDialogBusy] = useState(false);
  const [passwordProfile, setPasswordProfile] = useState<MySqlProfileSummary | null>(null);
  const passwordDirty = useRef<PasswordDirty>("none");
  const passwordOpener = useRef<HTMLElement | null>(null);
  const dialog = useConfirmDialog();
  const nameInput = useRef<HTMLInputElement>(null);
  const editorDialog = useRef<HTMLElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const blocked = state.busy || saving || dialogBusy;
  useEffect(() => {
    setEditor(null); editorRef.current = null; setSaving(false); setDialogBusy(false); setPasswordProfile(null); passwordDirty.current = "none";
    if (dialog.dialog) dialog.resolve({ kind: "cancelled", dialogId: dialog.dialog.id });
    if (bindingHandle) void controller.list();
    return controller.dispose;
  }, [bindingHandle, controller]);
  useEffect(() => { if (editor) nameInput.current?.focus(); }, [editor?.handle, editor !== null]);
  useEffect(() => {
    if (!editor) return;
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === "Escape" && !savingRef.current) { event.preventDefault(); void requestEditorClose(); return; }
      if (event.key === "Tab" && editorDialog.current) {
        const focusables = Array.from(editorDialog.current.querySelectorAll<HTMLElement>("button, input, textarea, [tabindex]")).filter(el => !el.hasAttribute("disabled"));
        const first = focusables[0], last = focusables[focusables.length - 1];
        if (!first || !last) return;
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [editor !== null]);
  const savingRef = useRef(saving); savingRef.current = saving;
  const editorDirty = (current: Editor | null): boolean =>
    current !== null && (JSON.stringify(current.input) !== current.initial || current.passwordAction !== "keep" || current.password !== "");
  const leaveEditor = async (): Promise<boolean> => {
    const current = editorRef.current;
    if (editorDirty(current) && !(await dialog.ask("保留连接编辑？", "当前数据库连接尚未保存。离开会丢弃本次编辑和未保存的口令。", "丢弃并离开"))) return false;
    if (activeController.current !== controller) return false;
    editorRef.current = null; setEditor(null); return true;
  };
  const requestEditorClose = async (): Promise<void> => {
    if (savingRef.current || savingTask.current) return;
    if (await leaveEditor()) heading.current?.focus();
  };
  useImperativeHandle(ref, () => ({ beforeDeactivate: async () => {
    if (dialogBusy) return false;
    if (passwordDirty.current === "busy") {
      await dialog.ask("口令修改正在执行", "口令修改或恢复正在执行，完成前不能离开此页面。", "继续等待");
      return false;
    }
    if (passwordDirty.current === "dirty") {
      if (!(await dialog.ask("丢弃口令修改？", "口令对话框中还有输入或待确认的计划，离开会丢弃这些内容。", "丢弃并离开"))) return false;
      passwordDirty.current = "none"; setPasswordProfile(null);
    }
    await savingTask.current;
    if (activeController.current !== controller) return false;
    if (!(await leaveEditor())) return false;
    await controller.settle();
    return activeController.current === controller;
  } }));
  const startEditor = (profile: MySqlProfileSummary | null): void => {
    if (profile === null) { setEditor({ handle: null, input: { ...initial }, initial: JSON.stringify(initial), password: "", passwordAction: "keep", unassigned: false, hasCa: false }); return; }
    const { name, host, port, username, database, tlsMode } = profile;
    const input = { name, host, port, username, database, tlsMode, caPem: null };
    setEditor({ handle: profile.profileHandle, input, initial: JSON.stringify(input), password: "", passwordAction: "keep", unassigned: profile.unassigned, hasCa: profile.hasCa });
  };
  const save = (): void => {
    const current = editorRef.current;
    if (!current || savingTask.current) return;
    setSaving(true);
    const password: MySqlPasswordChange = current.passwordAction === "replace" ? { action: "replace", value: current.password } : { action: current.passwordAction };
    const task = (async () => {
      try {
        const result = await controller.request({ action: "save", bindingHandle: controller.binding, profileHandle: current.handle, profile: current.input, password });
        if (activeController.current !== controller) return;
        if (result?.kind === "saved") { editorRef.current = null; setEditor(null); heading.current?.focus(); }
        else setEditor(existing => existing ? { ...existing, password: "" } : null);
      } finally { if (activeController.current === controller) setSaving(false); }
    })();
    savingTask.current = task;
    void task.finally(() => { if (savingTask.current === task) savingTask.current = null; });
  };
  const remove = async (profile: MySqlProfileSummary): Promise<void> => {
    if (blocked) return;
    setDialogBusy(true);
    try {
      const result = await controller.request({ action: "plan-delete", bindingHandle: controller.binding, profileHandle: profile.profileHandle });
      if (result?.kind !== "delete-plan") return;
      if (!(await dialog.ask("删除保存的数据库连接？", `SSH 主机：${targetLabel}\n连接：${result.profile.name}\n数据库：${result.profile.username}@${result.profile.host}:${result.profile.port}${result.profile.database ? `/${result.profile.database}` : ""}\n\n将删除本机保存的连接和加密口令。数据库内容不受影响；以后需重新填写连接。确认在两分钟内有效，配置发生变化时会拒绝删除。`, "删除本机连接"))) return;
      await controller.request({ action: "delete", bindingHandle: controller.binding, planHandle: result.planHandle });
    } finally { if (activeController.current === controller) { setDialogBusy(false); heading.current?.focus(); } }
  };
  return <section className="database-page" aria-label="MySQL 数据库">
    <div inert={dialog.dialog !== null}>
      <header><div><h2 ref={heading} tabIndex={-1}>MySQL / MariaDB 数据库</h2><p>通过 SSH 加密通道连接数据库，保存连接并修改账号口令；每次修改先生成计划、确认后执行并独立复核，可在限定时间内恢复旧口令。</p></div></header>
      <p className="database-target">SSH 主机：<strong>{targetLabel}</strong></p>
      {!bindingHandle ? <p className="database-empty">请先连接 SSH 主机，再添加数据库连接。</p> : <>
        <div className="database-toolbar">
          <button disabled={blocked} onClick={() => void controller.list()}>刷新连接</button>
          <button disabled={blocked} onClick={() => startEditor(null)}>新建连接</button>
        </div>
        {!state.profiles.length && !state.busy ? <div className="database-empty">
          <p>这台 SSH 主机还没有 MySQL / MariaDB 连接。添加地址、账号和证书后，即可管理数据库账号口令。</p>
          <button type="button" className="database-primary" disabled={blocked} onClick={() => startEditor(null)}>新建数据库连接</button>
        </div> : null}
        {state.profiles.length ? <div className="database-table" tabIndex={0} role="region" aria-label="数据库连接列表，可横向滚动"><table>
          <thead><tr><th>名称</th><th>地址</th><th>用户名</th><th>数据库</th><th>加密</th><th>口令</th><th>操作</th></tr></thead>
          <tbody>{state.profiles.map(profile => <tr key={profile.profileHandle}>
            <th scope="row">{profile.name}{profile.unassigned ? " · 待关联" : ""}</th>
            <td>{profile.host}:{profile.port}</td><td>{profile.username}</td><td>{profile.database || "未指定"}</td>
            <td>{profile.tlsMode === "verify-full" ? `TLS 校验证书与地址${profile.hasCa ? "（私有 CA）" : ""}` : "仅 SSH 加密（回环）"}</td>
            <td>{profile.hasPassword ? "已保存" : "未保存"}</td>
            <td><button disabled={blocked || !profile.hasPassword || profile.unassigned || passwordProfile !== null} onClick={event => { passwordOpener.current = event.currentTarget; setPasswordProfile(profile); }}>修改口令</button>
              <button disabled={blocked || !profile.hasPassword || profile.unassigned || passwordProfile !== null} onClick={() => void controller.inspect(profile.profileHandle)}>{state.reviewBusy === profile.profileHandle ? "正在检查…" : "检查实例"}</button>
              <button disabled={blocked} onClick={() => startEditor(profile)}>编辑</button>
              <button disabled={blocked} onClick={() => void remove(profile)}>删除</button></td>
          </tr>)}</tbody></table></div> : null}
        {state.profiles.map(item => {
          const review = state.reviews[item.profileHandle];
          return review ? <MysqlReviewPanel key={item.profileHandle} profile={item} review={review} onClose={() => controller.clearReview(item.profileHandle)} /> : null;
        })}
        {state.profiles.some(profile => profile.unassigned) ? <p>标记“待关联”的旧连接需要先编辑并保存，明确关联当前 SSH 主机后才能修改口令。</p> : null}
      </>}
      {state.error && !editor ? <TransientNotice source="数据库" message={state.error ?? ""} severity="error"><p role="alert" className="database-error">{state.error}</p></TransientNotice> : null}
      {state.notice ? <TransientNotice source="数据库" message={state.notice ?? ""} severity="info"><p role="status">{state.notice}</p></TransientNotice> : null}
    </div>
    {editor ? <MysqlProfileEditor editor={editor} saving={saving} error={state.error} nameInput={nameInput} dialogRef={editorDialog}
      onChange={next => { editorRef.current = next; setEditor(next); }}
      onSubmit={() => save()} onCancel={() => void requestEditorClose()} /> : null}
    {passwordProfile && bindingHandle ? <MysqlPasswordDialog api={api} bindingHandle={bindingHandle} profile={passwordProfile} targetLabel={targetLabel}
      onClose={() => { setPasswordProfile(null); if (passwordOpener.current?.isConnected) passwordOpener.current.focus(); else heading.current?.focus(); }}
      onDirty={dirty => { passwordDirty.current = dirty; }}
      onProfile={profile => { setPasswordProfile(profile); controller.clearReview(profile.profileHandle); void controller.list(); }}
      onInvalidate={() => { if (passwordProfile) controller.clearReview(passwordProfile.profileHandle); void controller.list(); }}
      ask={dialog.ask} /> : null}
    {dialog.dialog ? <DialogHost dialog={dialog.dialog} onResolve={dialog.resolve} /> : null}
  </section>;
});
