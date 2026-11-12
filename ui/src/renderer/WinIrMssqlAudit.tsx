import { useMemo, useState } from "react";

import type { MssqlInstance, WindowsMssqlAuditSnapshot } from "../shared/windows-incident-contract";
import { CollectionWarnings, DataTable, DetailPane, RiskBadge, SearchBox, StatStrip, type Column } from "./WinIrKit";
import { formatBytes, matchesQuery, toCsv } from "./win-ir-helpers";

const STATE_LABEL: Record<string, string> = {
  ok: "已读取", missing: "ERRORLOG 路径不存在", unreadable: "无法读取（权限）",
};

const CLUE_LABEL: Record<string, string> = {
  "xp-cmdshell": "xp_cmdshell 配置变更",
  "ole-automation": "Ole Automation 配置变更",
  "extended-proc-dll": "可疑扩展存储过程 DLL",
  "add-extended-proc": "sp_addextendedproc 注册",
};

export function WinIrMssqlAudit({ snapshot, busy = false, connected = false, onCopy }: {
  snapshot: WindowsMssqlAuditSnapshot | null; busy?: boolean; connected?: boolean;
  onCopy: (text: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const instances = useMemo(() => snapshot?.instances ?? [], [snapshot]);
  const failedLogins = useMemo(() => snapshot?.failedLogins ?? [], [snapshot]);
  const clues = useMemo(() => snapshot?.clues ?? [], [snapshot]);
  const visibleFailed = failedLogins.filter((group) => matchesQuery(query, group.clientIp, group.account));
  const current = instances.find((instance) => instance.name === selected) ?? null;

  const instanceColumns: Column<MssqlInstance>[] = [
    { key: "name", label: "实例", width: "18%", sort: (instance) => instance.name, mono: true, render: (instance) => <div className="wir-cell-stack"><strong>{instance.name}</strong><small>{instance.instanceId}</small></div> },
    { key: "state", label: "ERRORLOG 状态", width: "22%", render: (instance) => instance.errorlogState === "ok" ? <span className="wir-tag">{STATE_LABEL.ok} · {formatBytes(instance.errorlogSize)}</span> : <RiskBadge level="medium" label={STATE_LABEL[instance.errorlogState] ?? instance.errorlogState} /> },
    { key: "path", label: "ERRORLOG 路径", mono: true, render: (instance) => <span className="wir-clip" title={instance.errorlogPath}>{instance.errorlogPath || "未取得"}</span> },
    { key: "trace", label: "默认跟踪", width: "18%", mono: true, render: (instance) => instance.tracePath ? <span className="wir-clip" title={instance.tracePath}>{formatBytes(instance.traceSize)}</span> : <span>未发现</span> },
  ];

  return (
    <div className="wir-module">
      <StatStrip cards={[
        { label: "SQL Server 实例", value: snapshot ? instances.length : "—" },
        { label: "ERRORLOG 可读", value: snapshot ? instances.filter((instance) => instance.errorlogState === "ok").length : "—" },
        { label: "失败登录分组", value: snapshot ? failedLogins.length : "—" },
        { label: "危险配置线索", value: snapshot ? clues.length : "—", tone: clues.length > 0 ? "high" : "normal" },
      ]} />
      <p className="wir-query-scope">从注册表实例名表发现 SQL Server 实例，读取 ERRORLOG 末尾与 Application 日志中的登录失败事件（18454 / 18456）。缺失实例、权限不足与文件不可读分别显示，不互相替代。</p>
      <CollectionWarnings source="MSSQL 审计采集" summary="采集范围与限制" severity="info" announce={false} warnings={["只读注册表实例列表、ERRORLOG 尾部与事件日志，不修改实例配置。ERRORLOG 内容按不可信文本处理，仅展示末尾若干行。"]} />
      {snapshot?.noInstances ? <CollectionWarnings source="SQL Server 发现" summary="未发现实例" severity="info" announce={false} warnings={["注册表中未发现 SQL Server 实例名表。目标可能未安装 SQL Server，也可能当前账户无权读取该注册表项；请结合主机用途判断。"]} /> : null}
      <div className="wir-toolbar">
        <SearchBox value={query} onChange={setQuery} placeholder="搜索客户端地址或账户" />
        <button type="button" className="win-ir-btn" disabled={!visibleFailed.length} onClick={() => onCopy(toCsv(
          ["客户端地址", "账户", "失败次数", "首次", "末次"],
          visibleFailed.map((group) => [group.clientIp, group.account, String(group.count), group.first, group.last]),
        ))}>复制失败登录 CSV</button>
      </div>
      <div className={`wir-master${current ? " is-split" : ""}`}>
        <div>
          <DataTable label="SQL Server 实例" columns={instanceColumns} rows={instances} rowKey={(instance) => instance.name} selectedKey={current?.name ?? null} onSelect={(instance) => setSelected(instance?.name ?? null)} rowRisk={(instance) => instance.errorlogState === "ok" ? "normal" : "medium"} empty={snapshot ? (snapshot.noInstances ? "未发现 SQL Server 实例。" : "没有实例记录。") : "点击「审计 MSSQL 日志」，发现实例并读取日志。"} />
          {failedLogins.length ? <DataTable label="登录失败聚合" columns={[
            { key: "ip", label: "客户端地址", width: "24%", sort: (group) => group.clientIp, mono: true, render: (group) => <span>{group.clientIp || "本机 / 未记录"}</span> },
            { key: "account", label: "账户", width: "24%", sort: (group) => group.account, mono: true, render: (group) => <span className="wir-clip" title={group.account}>{group.account}</span> },
            { key: "count", label: "失败次数", width: "90px", sort: (group) => group.count, render: (group) => <span className={group.count >= 5 ? "wir-tag is-medium" : "wir-tag"}>{group.count}</span> },
            { key: "window", label: "时间范围", mono: true, render: (group) => <div className="wir-cell-stack"><span>{group.first || "未知"}</span><small>至 {group.last || "未知"}</small></div> },
          ] as Column<typeof failedLogins[number]>[]} rows={visibleFailed} rowKey={(group) => `${group.clientIp}|${group.account}`} selectedKey={null} onSelect={() => undefined} empty="没有符合筛选的失败登录记录。" defaultSort={{ key: "count", descending: true }} /> : null}
          {clues.length ? <section className="wir-section" aria-label="危险配置线索">
            <h3>危险配置线索（{clues.length}）</h3>
            <ul className="wir-clue-list">
              {clues.map((clue, index) => <li key={index}>
                <RiskBadge level="high" label={CLUE_LABEL[clue.rule] ?? clue.rule} />
                <span className="wir-tag">{clue.source === "errorlog" ? "ERRORLOG" : "Application 日志"}{clue.instance ? ` · ${clue.instance}` : ""}</span>
                <code className="wir-clip" title={clue.line}>{clue.line}</code>
              </li>)}
            </ul>
          </section> : null}
        </div>
        {current ? <DetailPane title={current.name} subtitle={current.errorlogPath || "ERRORLOG 路径未取得"} {...(current.errorlogState === "ok" ? {} : { risk: "medium" as const })} onClose={() => setSelected(null)} onCopy={onCopy} copyText={current.errorlogTail.join("\n")} fields={[
          { label: "ERRORLOG 状态", value: STATE_LABEL[current.errorlogState] ?? current.errorlogState },
          { label: "ERRORLOG 大小", value: current.errorlogState === "ok" ? formatBytes(current.errorlogSize) : "未取得" },
          { label: "默认跟踪 (log.trc)", value: current.tracePath ? `${current.tracePath} · ${formatBytes(current.traceSize)}` : "未发现；仅报告存在与大小，不解析内容" },
        ]}>
          {current.errorlogTail.length ? <pre className="wir-pre wir-untrusted-text">{current.errorlogTail.join("\n")}</pre> : <p className="wir-footnote">没有可显示的 ERRORLOG 末尾内容。</p>}
        </DetailPane> : null}
      </div>
    </div>
  );
}
