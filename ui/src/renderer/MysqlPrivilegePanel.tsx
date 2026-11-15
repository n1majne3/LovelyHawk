import { useEffect, useRef, useState } from "react";
import type {
  MySqlAccountInput,
  MySqlPrivilegeAddInput,
  MySqlPrivilegeReceipt,
  MySqlPrivilegeReview,
  MySqlPrivilegeRow,
  MySqlProfileSummary,
  MySqlRevokeInput,
  MySqlRuntimeRequest,
  MySqlRuntimeResponse,
} from "../shared/mysql-runtime-contract";

const PRIVILEGES = [
  "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", "INDEX",
  "CREATE VIEW", "SHOW VIEW", "TRIGGER", "EXECUTE", "REFERENCES", "LOCK TABLES",
  "CREATE TEMPORARY TABLES", "EVENT", "CREATE ROUTINE", "ALTER ROUTINE",
] as const;
const TABLE_PRIVILEGES = new Set([
  "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", "INDEX",
  "CREATE VIEW", "SHOW VIEW", "TRIGGER", "REFERENCES",
]);

type Request = (request: MySqlRuntimeRequest) => Promise<MySqlRuntimeResponse | null>;

function scopeLabel(row: MySqlPrivilegeRow): string {
  switch (row.scope.kind) {
    case "global": return "全局 *.*";
    case "database": return `数据库 ${row.scope.database}.*`;
    case "table": return `表 ${row.scope.database}.${row.scope.table}`;
    default: return "其他";
  }
}

function scopeLabelOf(database: string, table: string | null): string {
  return table === null ? `数据库 ${database}.*` : `表 ${database}.${table}`;
}

export function MysqlPrivilegePanel({ profile, account, binding, request, busy, onClose }: {
  profile: MySqlProfileSummary; account: MySqlAccountInput; binding: string;
  request: Request; busy: boolean; onClose(): void;
}): React.JSX.Element {
  const [review, setReview] = useState<MySqlPrivilegeReview | null>(null);
  const [revokes, setRevokes] = useState<Map<number, Set<string>>>(new Map());
  const [adds, setAdds] = useState<MySqlPrivilegeAddInput[]>([]);
  const [draft, setDraft] = useState<{ database: string; table: string | null; privileges: Set<string> }>({
    database: "", table: null, privileges: new Set(),
  });
  const [plan, setPlan] = useState<{ handle: string; summary: string; statements: string[]; notes: string[] } | null>(null);
  const [receipt, setReceipt] = useState<{ receipt: MySqlPrivilegeReceipt; undoHandle: string | null } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const label = `${account.user}@${account.host}`;
  const headingRef = useRef<HTMLHeadingElement>(null);
  const planRef = useRef<HTMLDivElement>(null);
  const receiptRef = useRef<HTMLDivElement>(null);

  useEffect(() => { headingRef.current?.focus(); }, []);
  useEffect(() => { if (plan !== null) planRef.current?.focus(); }, [plan]);
  useEffect(() => { if (receipt !== null) receiptRef.current?.focus(); }, [receipt]);

  useEffect(() => {
    let alive = true;
    void (async () => {
      const response = await request({
        action: "privileges",
        bindingHandle: binding,
        profileHandle: profile.profileHandle,
        account,
      });
      if (!alive) return;
      if (response !== null && response.kind === "privileges") setReview(response.review);
      else if (response !== null && response.kind === "rejected") setError(response.detail);
    })();
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function toggle(row: number, privilege: string): void {
    setRevokes(current => {
      const next = new Map(current);
      const set = new Set(next.get(row) ?? []);
      if (set.has(privilege)) set.delete(privilege); else set.add(privilege);
      if (set.size === 0) next.delete(row); else next.set(row, set);
      return next;
    });
    setPlan(null);
    setReceipt(null);
  }

  function addDraft(): void {
    if (draft.database === "" || draft.privileges.size === 0) return;
    setAdds(current => [...current, {
      database: draft.database,
      table: draft.table,
      privileges: [...draft.privileges].sort(),
    }]);
    setDraft({ database: "", table: null, privileges: new Set() });
    setPlan(null);
    setReceipt(null);
  }

  async function buildPlan(): Promise<void> {
    setError(null);
    const revokeInput: MySqlRevokeInput[] = [...revokes.entries()].map(([row, set]) => ({
      row, privileges: [...set].sort(),
    }));
    const response = await request({
      action: "plan-privileges",
      bindingHandle: binding,
      profileHandle: profile.profileHandle,
      account,
      revokes: revokeInput,
      grants: adds,
    });
    if (response === null) return;
    if (response.kind === "privilege-plan") {
      setPlan({
        handle: response.planHandle,
        summary: response.plan.summary,
        statements: response.plan.statements,
        notes: response.plan.notes,
      });
    } else if (response.kind === "rejected") {
      setError(response.detail);
    }
  }

  async function execute(): Promise<void> {
    if (plan === null) return;
    setError(null);
    const response = await request({ action: "execute-privileges", bindingHandle: binding, planHandle: plan.handle });
    if (response === null) return;
    if (response.kind === "privilege-result") {
      setReceipt({ receipt: response.receipt, undoHandle: response.undoHandle });
      setPlan(null);
    } else if (response.kind === "rejected") {
      setError(response.detail);
    }
  }

  async function undo(): Promise<void> {
    if (receipt?.undoHandle == null) return;
    setError(null);
    const response = await request({ action: "undo-privileges", bindingHandle: binding, planHandle: receipt.undoHandle });
    if (response === null) return;
    if (response.kind === "privilege-result") {
      setReceipt({ receipt: response.receipt, undoHandle: null });
    } else if (response.kind === "rejected") {
      setError(response.detail);
    }
  }

  const draftTables = review === null || draft.database === ""
    ? []
    : review.tables.filter(item => item.database === draft.database);
  const changes = [...revokes.values()].reduce((total, set) => total + set.size, 0) + adds.length;

  return <section className="database-result" aria-label={`账号权限:${label}`} data-testid="mysql-privilege-panel">
    <h3 ref={headingRef} tabIndex={-1}>账号权限：{label}</h3>
    {review !== null ? <p>{review.product} {review.serverVersion} · 当前连接账号 {review.connecting.user}@{review.connecting.host}</p> : <p>正在读取授权…</p>}
    <p role="note">最小权限以业务矩阵为准；这里只执行勾选出来的收回与新增，不会自动判断哪些权限是多余的。GRANT/REVOKE 立即生效，不需要 FLUSH PRIVILEGES。</p>
    {review === null ? null : <>
      {review.rows.length === 0 ? <p>该账号没有任何授权行。</p> : null}
      {review.rows.map(row => <div key={row.row} className="mysql-priv-row" data-testid={`mysql-priv-row-${row.row}`}>
        <p><strong>{scopeLabel(row)}</strong>{row.allPrivileges ? "（ALL PRIVILEGES）" : ""}{row.grantOption ? " · WITH GRANT OPTION" : ""}</p>
        {!row.parseable ? <p className="database-error" role="note">这一行无法解析，已原样保留；存在不可解析行时不能规划：<code>{row.raw}</code></p> : (
          <div className="mysql-priv-checks" role="group" aria-label={`收回 ${scopeLabel(row)} 的权限`}>
            {(row.allPrivileges ? [...row.members].sort() : row.privileges).map(name =>
              <label key={name} className="database-check">
                <input type="checkbox" checked={revokes.get(row.row)?.has(name) === true} onChange={() => toggle(row.row, name)} />收回 {name}
              </label>)}
            {row.grantOption ? <label className="database-check">
              <input type="checkbox" checked={revokes.get(row.row)?.has("GRANT OPTION") === true} onChange={() => toggle(row.row, "GRANT OPTION")} />收回 GRANT OPTION
            </label> : null}
          </div>)}
      </div>)}
      <h4>新增授权</h4>
      <div className="mysql-priv-add">
        <label>数据库
          <select data-testid="mysql-priv-add-db" value={draft.database} onChange={event => setDraft({ database: event.target.value, table: null, privileges: draft.privileges })}>
            <option value="">选择数据库</option>
            {review.schemas.map(name => <option key={name} value={name}>{name}</option>)}
          </select>
        </label>
        <label>表（留空为整库）
          <select data-testid="mysql-priv-add-table" value={draft.table ?? ""} disabled={draft.database === ""} onChange={event => setDraft({ ...draft, table: event.target.value === "" ? null : event.target.value })}>
            <option value="">整个数据库 {draft.database === "" ? "" : `${draft.database}.*`}</option>
            {draftTables.map(item => <option key={item.table} value={item.table}>{item.table}</option>)}
          </select>
        </label>
        <div className="mysql-priv-checks" role="group" aria-label="新增授权权限">
          {PRIVILEGES.filter(name => draft.table === null || TABLE_PRIVILEGES.has(name)).map(name =>
            <label key={name} className="database-check"><input type="checkbox" checked={draft.privileges.has(name)} onChange={() => {
              const next = new Set(draft.privileges);
              if (next.has(name)) next.delete(name); else next.add(name);
              setDraft({ ...draft, privileges: next });
            }} />{name}</label>)}
        </div>
        <button type="button" data-testid="mysql-priv-add-submit" disabled={draft.database === "" || draft.privileges.size === 0} onClick={addDraft}>加入计划</button>
      </div>
      {adds.length > 0 ? <ul>{adds.map((add, index) => <li key={index}>
        {scopeLabelOf(add.database, add.table)}：{add.privileges.join("、")}
        <button type="button" onClick={() => { setAdds(current => current.filter((_, i) => i !== index)); setPlan(null); }}>移除</button>
      </li>)}</ul> : null}
      <div className="database-toolbar">
        <button type="button" data-testid="mysql-priv-plan" disabled={busy || changes === 0} onClick={() => void buildPlan()}>生成执行计划</button>
        <button type="button" onClick={onClose}>关闭</button>
      </div>
    </>}
    {plan !== null ? <div className="mysql-priv-plan" data-testid="mysql-priv-plan-view" ref={planRef} tabIndex={-1} role="region" aria-label="执行计划">
      <h4>执行计划（不可修改）</h4>
      <p>{plan.summary}</p>
      <ol>{plan.statements.map((statement, index) => <li key={index}><code>{statement}</code></li>)}</ol>
      {plan.notes.map((note, index) => <p key={index} role="note">{note}</p>)}
      <div className="database-toolbar">
        <button type="button" className="is-danger" data-testid="mysql-priv-execute" disabled={busy} onClick={() => void execute()}>确认执行</button>
        <button type="button" onClick={() => setPlan(null)}>放弃</button>
      </div>
    </div> : null}
    {receipt !== null ? <div className="mysql-priv-plan" data-testid="mysql-priv-receipt" ref={receiptRef} tabIndex={-1} role="region" aria-label="执行结果">
      <h4>{receipt.receipt.verified ? "已执行并复核" : "执行结果待人工核对"}</h4>
      <p>{receipt.receipt.detail}</p>
      <div className="database-toolbar">
        {receipt.undoHandle !== null ? <button type="button" data-testid="mysql-priv-undo" disabled={busy} onClick={() => void undo()}>恢复原授权（10 分钟内）</button> : null}
      </div>
    </div> : null}
    {error !== null ? <p className="database-error" role="alert">{error}</p> : null}
  </section>;
}
