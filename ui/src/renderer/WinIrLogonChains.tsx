import { useMemo, useState } from "react";

import type { WindowsLogonChain, WindowsLogonChainSnapshot } from "../shared/windows-incident-contract";
import { CollectionWarnings, DataTable, DetailPane, FilterChips, RiskBadge, SearchBox, StatStrip, type Column } from "./WinIrKit";
import { matchesQuery, toCsv } from "./win-ir-helpers";

const LOGON_TYPE: Record<number, string> = {
  2: "交互", 3: "网络", 4: "批处理", 5: "服务", 7: "解锁",
  8: "明文网络", 9: "新凭据", 10: "远程交互", 11: "缓存",
};

const FINGERPRINT_LABEL: Record<string, string> = {
  "ipc": "IPC$ 单次连接",
  "psexec": "PsExec 特征",
  "wmic": "WMIC 突发连接",
  "sharp-rdp": "SharpRDP 特征",
  "brute-force": "爆破后成功",
};

const EVENT_ID_LABEL: Record<number, string> = {
  4624: "登录成功", 4625: "登录失败", 4648: "显式凭据", 4672: "特权登录",
  4634: "注销", 4647: "用户注销", 4776: "凭据验证",
};

function chainKey(chain: WindowsLogonChain): string {
  return `${sourceLabel(chain)}|${chain.account}|${chain.first}|${chain.last}|${chain.events.length}`;
}

function sourceLabel(chain: WindowsLogonChain): string {
  return chain.sourceIp && chain.sourceIp !== "-" ? chain.sourceIp : chain.workstation || "未知来源";
}

export function WinIrLogonChains({ snapshot, busy = false, connected = false, onCopy }: {
  snapshot: WindowsLogonChainSnapshot | null; busy?: boolean; connected?: boolean;
  onCopy: (text: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | "clue" | "failed">("all");
  const [selected, setSelected] = useState<number | null>(null);
  const chains = useMemo(() => snapshot?.chains ?? [], [snapshot]);
  const visible = chains.filter((chain) =>
    (filter === "all" || (filter === "clue" ? chain.fingerprint !== null : chain.failedBeforeSuccess > 0)) &&
    matchesQuery(query, sourceLabel(chain), chain.account, chain.workstation, chain.fingerprint?.kind ?? ""));
  const current = selected !== null ? visible[selected] ?? null : null;
  const clueCount = chains.filter((chain) => chain.fingerprint !== null).length;

  const columns: Column<WindowsLogonChain>[] = [
    { key: "source", label: "来源", width: "18%", sort: (chain) => sourceLabel(chain), mono: true, render: (chain) => <div className="wir-cell-stack"><strong>{sourceLabel(chain)}</strong>{chain.sourceIp && chain.workstation ? <small>{chain.workstation}</small> : null}</div> },
    { key: "account", label: "账户", width: "16%", sort: (chain) => chain.account, mono: true, render: (chain) => <span className="wir-clip" title={chain.account}>{chain.account || "未取得"}</span> },
    { key: "window", label: "时间窗", width: "24%", mono: true, render: (chain) => <div className="wir-cell-stack"><span>{chain.first || "未知"}</span><small>至 {chain.last || "未知"}</small></div> },
    { key: "events", label: "事件", width: "70px", sort: (chain) => chain.events.length, render: (chain) => <span>{chain.events.length}</span> },
    { key: "failed", label: "失败后成功", width: "90px", sort: (chain) => chain.failedBeforeSuccess, render: (chain) => chain.failedBeforeSuccess > 0 ? <span className="wir-tag is-medium">{chain.failedBeforeSuccess}</span> : <span>0</span> },
    { key: "clue", label: "线索", width: "140px", render: (chain) => chain.fingerprint ? <RiskBadge level="high" label={FINGERPRINT_LABEL[chain.fingerprint.kind] ?? chain.fingerprint.kind} /> : <span className="wir-tag">无</span> },
  ];

  return (
    <div className="wir-module">
      <StatStrip cards={[
        { label: "登录事件", value: snapshot?.eventCount ?? "—" },
        { label: "登录链", value: chains.length || "—" },
        { label: "可疑线索", value: snapshot ? clueCount : "—", tone: clueCount > 0 ? "high" : "normal", onClick: () => setFilter("clue") },
      ]} />
      <p className="wir-query-scope">按来源地址 / 工作站与账户把最近 7 天的登录事件串成链条（同一链内相邻事件间隔不超过 10 分钟）。线索是启发式标记，需结合事件内容人工复核。</p>
      <CollectionWarnings source="登录链采集" summary="采集范围与限制" severity="info" announce={false} warnings={["只读取 Security 日志事件，不修改目标配置。日志需要相应读取权限；容量达到上限时会保留截断标记。"]} />
      {snapshot?.permissionGap ? <CollectionWarnings source="Security 日志" summary="权限不足" severity="error" announce={false} warnings={["当前账户无法读取 Security 日志，登录链分析不可用。这是权限缺口，不代表目标没有登录活动。请使用有日志读取权限的账户重新连接。"]} /> : null}
      {snapshot?.truncated ? <CollectionWarnings source="登录链采集" summary="结果已截断" severity="warning" announce={false} warnings={["事件数量达到采集上限（20,000 条），窗口最早部分的事件未纳入分析，链条可能不完整。"]} /> : null}
      <div className="wir-toolbar">
        <SearchBox value={query} onChange={setQuery} placeholder="搜索来源、账户或工作站" />
        <FilterChips label="登录链筛选" value={filter} onChange={setFilter} options={[
          { value: "all", label: "全部", count: chains.length },
          { value: "clue", label: "有线索", tone: "high", count: clueCount },
          { value: "failed", label: "失败后成功", tone: "medium", count: chains.filter((chain) => chain.failedBeforeSuccess > 0).length },
        ]} />
        <button type="button" className="win-ir-btn" disabled={!visible.length} onClick={() => onCopy(toCsv(
          ["来源", "工作站", "账户", "首事件", "末事件", "事件数", "失败后成功", "线索"],
          visible.map((chain) => [sourceLabel(chain), chain.workstation, chain.account, chain.first, chain.last, String(chain.events.length), String(chain.failedBeforeSuccess), chain.fingerprint ? (FINGERPRINT_LABEL[chain.fingerprint.kind] ?? chain.fingerprint.kind) : ""]),
        ))}>复制筛选结果 CSV</button>
      </div>
      <div className={`wir-master${current ? " is-split" : ""}`}>
        <DataTable label="登录链" columns={columns} rows={visible} rowKey={chainKey}
          selectedKey={current !== null && selected !== null ? chainKey(current) : null}
          onSelect={(chain) => setSelected(chain ? visible.indexOf(chain) : null)}
          rowRisk={(chain) => chain.fingerprint ? "high" : chain.failedBeforeSuccess > 0 ? "medium" : "normal"}
          empty={snapshot ? (snapshot.permissionGap ? "Security 日志无读取权限，见上方说明。" : "窗口内没有可归入链条的登录事件。") : "点击「分析登录链」，读取 Security 日志并生成登录链。"} />
        {current ? <DetailPane title={`${sourceLabel(current)} → ${current.account || "未知账户"}`} subtitle={`${current.first || "未知"} 至 ${current.last || "未知"} · ${current.events.length} 个事件`} {...(current.fingerprint ? { risk: "high" as const } : {})} onClose={() => setSelected(null)} onCopy={onCopy} copyText={current.events.map((event) => `${event.time}\t${event.id} ${EVENT_ID_LABEL[event.id] ?? ""}\t类型${event.logonType}\t${event.account}\t${event.sourceIp}\t${event.process}`).join("\n")} fields={[
          { label: "线索判定", value: current.fingerprint ? `${FINGERPRINT_LABEL[current.fingerprint.kind] ?? current.fingerprint.kind}：${current.fingerprint.rule}` : "无线索" },
          { label: "失败后成功", value: `${current.failedBeforeSuccess} 次` },
        ]}>
          <ol className="wir-timeline-list">
            {current.events.map((event) => <li key={`${event.recordId}-${event.time}`}>
              <span className="wir-mono">{event.time || "时间未知"}</span>
              <strong>{EVENT_ID_LABEL[event.id] ?? `事件 ${event.id}`}</strong>
              <span className="wir-tag">{LOGON_TYPE[event.logonType] ?? `类型 ${event.logonType}`}</span>
              <span className="wir-mono wir-clip" title={`${event.domain}\\${event.account} · ${event.sourceIp || event.workstation || "-"} · ${event.authPackage} · ${event.process}`}>{event.account || "未知账户"} · {event.sourceIp && event.sourceIp !== "-" ? event.sourceIp : event.workstation || "-"} · {event.process || event.authPackage || ""}</span>
            </li>)}
          </ol>
        </DetailPane> : null}
      </div>
    </div>
  );
}
