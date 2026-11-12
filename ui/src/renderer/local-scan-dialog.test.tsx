import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { EmergencyCommandPathOffer } from "../shared/emergency-command-contract";
import type {
  LocalScanFetchDto,
  LocalScanRequest,
  LocalScanResult,
} from "../shared/local-scan-contract";
import { EmergencyPathMenu } from "./EmergencyPathMenu";
import {
  browserScanTransport, containerScanTransport,
  LocalScanController, pathOfferScanTransport, type LocalScanRun, type LocalScanState,
} from "./local-scan-controller";
import { LocalScanBody, LocalScanDialog, type LocalScanSubject } from "./LocalScanDialog";

const offer: EmergencyCommandPathOffer = { pathHandle: "path-one", path: "/tmp/.cache/.helper", line: 0 };
const engine = { id: "engine-one", name: "D盾网页查杀", kind: "gui" as const, programName: "D_Safe_Manage.exe" };
const cli = { id: "engine-two", name: "clamscan", kind: "cli" as const, programName: "clamscan.exe" };
const fetched: LocalScanFetchDto = {
  fetchId: "fetch-one", path: offer.path, sourceKind: "directory", scope: "directory",
  files: 3, directories: 1, bytes: 2048, skipped: 1, skippedReasons: ["套接字已跳过"],
  truncated: false, archiveSha256: "a".repeat(64), archiveBytes: 4096, transport: "scp",
  stagingDirectory: "C:/scan/fetch-one/content", entries: ["a.sh", "b.conf", "c/"],
  fetchedAt: "2026-08-25T23:31:00+00:00", expiresInSeconds: 1800,
  origin: "host", originLabel: "",
};
const enginesResult: LocalScanResult = { kind: "engines", engines: [engine, cli] };
const fetchResult: LocalScanResult = { kind: "fetch", fetch: fetched };

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function idleView(overrides: Partial<LocalScanState> = {}): LocalScanState {
  return {
    engines: null, enginesFailed: false, fetch: null, run: null, busy: null,
    error: null, notice: null, selectedEngineId: null, discarded: false, ...overrides,
  };
}

const controllers: LocalScanController[] = [];
function fixture() {
  const override: Partial<Record<LocalScanRequest["action"], () => Promise<LocalScanResult | null>>> = {};
  const localScan = vi.fn(async (request: LocalScanRequest): Promise<LocalScanResult | null> => {
    if (override[request.action]) return override[request.action]!();
    switch (request.action) {
      case "engines": return enginesResult;
      case "fetch": return fetchResult;
      case "run": return { kind: "run", state: "finished", engineName: "clamscan", exitCode: 0, output: "OK\n", hits: [], detail: "已退出" };
      case "reveal": case "discard": return { kind: "done", detail: "已处理" };
      default: return enginesResult;
    }
  });
  const controller = new LocalScanController(pathOfferScanTransport({ localScan }, "binding-one", offer));
  controllers.push(controller);
  return { controller, localScan, override };
}

afterEach(() => {
  controllers.forEach((controller) => controller.dispose());
  controllers.length = 0;
});

describe("local scan menu entry", () => {
  it("offers 取回本机扫描 between 下载留证 and 查看属性 only where wired", () => {
    const html = renderToStaticMarkup(
      <EmergencyPathMenu position={{ x: 10, y: 20 }} offer={offer} busy={false} localScan
        onAction={() => undefined} onDismiss={() => undefined} />,
    );
    expect(html).toContain("取回本机扫描");
    expect(html.indexOf("下载留证")).toBeLessThan(html.indexOf("取回本机扫描"));
    expect(html.indexOf("取回本机扫描")).toBeLessThan(html.indexOf("查看属性"));
    // It is a read action, never painted dangerous.
    const open = html.lastIndexOf("<button", html.indexOf("取回本机扫描"));
    const tag = html.slice(open, html.indexOf(">", open) + 1);
    expect(tag).not.toContain("is-dangerous");

    const without = renderToStaticMarkup(
      <EmergencyPathMenu position={{ x: 10, y: 20 }} offer={offer} busy={false}
        onAction={() => undefined} onDismiss={() => undefined} />,
    );
    expect(without).not.toContain("取回本机扫描");
  });
});

describe("local scan dialog", () => {
  const api = { localScan: async () => enginesResult };
  const subject: LocalScanSubject = { path: offer.path, entryKind: "file" };

  it("opens on the scope choice with the isolation warning already visible", () => {
    const html = renderToStaticMarkup(
      <LocalScanDialog transport={pathOfferScanTransport(api, "binding-one", offer)} subject={subject}
        returnFocus={null} onClose={() => undefined} />,
    );
    expect(html).toContain('data-testid="local-scan-dialog"');
    expect(html).toContain("取回本机扫描");
    expect(html).toContain("/tmp/.cache/.helper");
    expect(html).toContain("该文件");
    expect(html).toContain("所在目录（取回整层，有大小上限）");
    expect(html).toContain("开始取回");
    expect(html).toContain("正在读取已配置的本机引擎");
    // The warning is not a post-scan nicety; it is said before anything moves.
    expect(html).toContain("取回内容按不可信来源隔离存放");
    expect(html).toContain("取回不代表文件安全");
    expect(html).not.toContain("path-one");
  });

  it("reports the fetched copy plainly, scp fallback included", () => {
    const controller = fixture().controller;
    const html = renderToStaticMarkup(<LocalScanBody controller={controller} subject={{ path: offer.path, entryKind: "file" }} onClose={() => undefined}
      view={idleView({ engines: [engine, cli], selectedEngineId: cli.id, fetch: fetched })} />);
    expect(html).toContain('data-testid="local-scan-summary"');
    expect(html).toContain("目录");
    expect(html).toContain("3 个文件、1 个目录");
    expect(html).toContain("2.0 KB（2048 字节）");
    expect(html).toContain("跳过");
    expect(html).toContain("套接字已跳过");
    expect(html).toContain("目标缺少 SFTP 子系统");
    expect(html).toContain("C:/scan/fetch-one/content");
    expect(html).toContain("a".repeat(64));
    expect(html).toContain("约 30 分钟");
    expect(html).toContain("a.sh");
    // An engine is picked, so the run may start.
    const run = html.match(/<button[^>]*data-testid="local-scan-run"[^>]*>/u)?.[0] ?? "";
    expect(run).not.toContain("disabled");
    expect(html).toContain("clamscan");
    expect(html).toContain("打开取回目录");
    expect(html).toContain("删除取回内容");
  });

  it("keeps 启动扫描 down until both a copy and an engine exist", () => {
    const controller = fixture().controller;
    const waiting = renderToStaticMarkup(<LocalScanBody controller={controller} subject={{ path: offer.path, entryKind: "file" }} onClose={() => undefined}
      view={idleView({ engines: [], fetch: fetched })} />);
    const run = waiting.match(/<button[^>]*data-testid="local-scan-run"[^>]*>/u)?.[0] ?? "";
    expect(run).toContain('disabled=""');
    expect(waiting).toContain("还没有配置本机引擎");
    expect(waiting).toContain("选择一个本机引擎后才能启动扫描");
  });

  it("shows a launched engine and a finished command line run differently", () => {
    const controller = fixture().controller;
    const launched = renderToStaticMarkup(<LocalScanBody controller={controller} subject={{ path: offer.path, entryKind: "file" }} onClose={() => undefined}
      view={idleView({
        engines: [engine], selectedEngineId: engine.id, fetch: fetched,
        run: { kind: "run", state: "launched", engineName: "D盾网页查杀", exitCode: null, output: null, hits: [], detail: "已启动 D盾网页查杀" },
      })} />);
    expect(launched).toContain("已启动 D盾网页查杀");
    expect(launched).toContain("本页不跟踪它的进度");
    expect(launched).not.toContain("退出码");

    const finished = renderToStaticMarkup(<LocalScanBody controller={controller} subject={{ path: offer.path, entryKind: "file" }} onClose={() => undefined}
      view={idleView({
        engines: [cli], selectedEngineId: cli.id, fetch: fetched,
        run: { kind: "run", state: "finished", engineName: "clamscan", exitCode: 1, output: "<img src=x> FOUND", hits: [], detail: "clamscan 已退出" },
      })} />);
    expect(finished).toContain("退出码 1");
    expect(finished).toContain("local-scan-output");
    // Engine output is hostile text; it is quoted, never markup.
    expect(finished).toContain("&lt;img src=x&gt; FOUND");
    expect(finished).not.toContain("<img");
  });

  it("lists engine-named members with remote paths, and locates only handled hits", () => {
    const controller = fixture().controller;
    const run: LocalScanRun = {
      kind: "run", state: "finished", engineName: "fixture-cli", exitCode: 0,
      output: "HIT ...", detail: "fixture-cli 已退出",
      hits: [
        { remotePath: "/var/www/html/shell.php", member: "html/shell.php", line: "HIT C:/scan/fetch-one/content/html/shell.php", pathHandle: "hit-handle-1" },
        { remotePath: "/var/www/html/pic.php", member: "html/images/pic.php", line: "REL html/images/pic.php", pathHandle: null },
      ],
    };
    const html = renderToStaticMarkup(<LocalScanBody controller={controller}
      subject={{ path: offer.path, entryKind: "file" }} onClose={() => undefined}
      onLocate={() => undefined}
      view={idleView({ engines: [cli], selectedEngineId: cli.id, fetch: fetched, run })} />);
    expect(html).toContain('data-testid="local-scan-hits"');
    expect(html).toContain("/var/www/html/shell.php");
    expect(html).toContain("/var/www/html/pic.php");
    expect(html).toContain("HIT C:/scan/fetch-one/content/html/shell.php");
    // Only the handled hit gets a locate button; the container-only row stays
    // display-only.
    expect(html.match(/data-testid="local-scan-hit-locate"/gu)?.length).toBe(1);
    expect(html).toContain("在远端定位");
    expect(html).toContain("经取回清单核对");
  });

  it("shows no locate buttons at all where the page never wired a path menu", () => {
    const controller = fixture().controller;
    const run: LocalScanRun = {
      kind: "run", state: "finished", engineName: "fixture-cli", exitCode: 0,
      output: "HIT ...", detail: "fixture-cli 已退出",
      hits: [
        { remotePath: "/var/www/html/shell.php", member: "html/shell.php", line: "HIT ...", pathHandle: "hit-handle-1" },
      ],
    };
    const html = renderToStaticMarkup(<LocalScanBody controller={controller}
      subject={{ path: offer.path, entryKind: "file" }} onClose={() => undefined}
      view={idleView({ engines: [cli], selectedEngineId: cli.id, fetch: fetched, run })} />);
    expect(html).toContain("/var/www/html/shell.php");
    expect(html).not.toContain("local-scan-hit-locate");
  });

  it("renders the backend's error verbatim in its own area", () => {
    const controller = fixture().controller;
    const html = renderToStaticMarkup(<LocalScanBody controller={controller} subject={{ path: offer.path, entryKind: "file" }} onClose={() => undefined}
      view={idleView({ error: "目标机缺少 tar 或 find，无法打包取回内容。 (local-scan-tools)" })} />);
    expect(html).toContain('role="alert"');
    expect(html).toContain("目标机缺少 tar 或 find，无法打包取回内容。 (local-scan-tools)");
  });
});

describe("local scan controller", () => {
  it("walks engines → fetch → run in order and keeps the request handles it was given", async () => {
    const f = fixture();
    f.controller.attach();
    await vi.waitFor(() => expect(f.controller.getSnapshot().engines).toEqual([engine, cli]));
    await f.controller.fetch("directory");
    expect(f.controller.getSnapshot().fetch?.fetchId).toBe("fetch-one");
    f.controller.selectEngine(cli.id);
    await f.controller.run(cli.id);
    expect(f.controller.getSnapshot().run?.exitCode).toBe(0);
    const calls = f.localScan.mock.calls.map(([request]) => request);
    expect(calls.map((request) => request.action)).toEqual(["engines", "fetch", "run"]);
    expect(calls[1]).toEqual({
      action: "fetch", bindingHandle: "binding-one", pathHandle: "path-one", scope: "directory",
    });
    expect(calls[2]).toEqual({
      action: "run", bindingHandle: "binding-one", fetchId: "fetch-one", engineId: "engine-two",
    });
  });

  it("does not fetch twice at once and does not run without a fetched copy", async () => {
    const f = fixture();
    f.controller.attach();
    await vi.waitFor(() => expect(f.controller.getSnapshot().busy).toBeNull());
    const pending = deferred<LocalScanResult | null>();
    f.override.fetch = () => pending.promise;
    const first = f.controller.fetch("file");
    await f.controller.fetch("directory");
    await f.controller.run("engine-two");
    expect(f.localScan.mock.calls.map(([request]) => request.action)).toEqual(["engines", "fetch"]);
    pending.resolve(fetchResult);
    await first;
    expect(f.controller.getSnapshot().fetch?.fetchId).toBe("fetch-one");
  });

  it("drops a fetch finishing after close and tells the backend to delete the copy nobody saw", async () => {
    const f = fixture();
    f.controller.attach();
    await vi.waitFor(() => expect(f.controller.getSnapshot().busy).toBeNull());
    const pending = deferred<LocalScanResult | null>();
    f.override.fetch = () => pending.promise;
    const request = f.controller.fetch("file");
    f.controller.dispose();
    pending.resolve(fetchResult);
    await request;
    expect(f.controller.getSnapshot().fetch).toBeNull();
    expect(f.localScan.mock.calls.at(-1)?.[0]).toEqual({
      action: "discard", bindingHandle: "binding-one", fetchId: "fetch-one",
    });
  });

  it("shows the backend's refusal text and keeps the scope choice usable", async () => {
    const f = fixture();
    f.controller.attach();
    await vi.waitFor(() => expect(f.controller.getSnapshot().busy).toBeNull());
    f.override.fetch = async () => { throw new Error("目标机缺少 tar 或 find，无法打包取回内容。 (local-scan-tools)"); };
    await f.controller.fetch("file");
    expect(f.controller.getSnapshot().error).toBe("目标机缺少 tar 或 find，无法打包取回内容。 (local-scan-tools)");
    expect(f.controller.getSnapshot().fetch).toBeNull();
    expect(f.controller.getSnapshot().busy).toBeNull();
  });

  it("keeps a cancelled engine pick as a no-op and selects an added engine", async () => {
    const f = fixture();
    f.controller.attach();
    await vi.waitFor(() => expect(f.controller.getSnapshot().engines).toEqual([engine, cli]));
    f.override.configure = async () => null;
    expect(await f.controller.configure("x", "gui", [])).toBe("cancelled");
    expect(f.controller.getSnapshot().engines).toEqual([engine, cli]);

    const added = { id: "engine-three", name: "huorong", kind: "cli" as const, programName: "hipsscan.exe" };
    f.override.configure = async () => ({ kind: "engines", engines: [engine, cli, added] });
    expect(await f.controller.configure("huorong", "cli", ["{dir}"])).toBe("configured");
    expect(f.controller.getSnapshot().selectedEngineId).toBe("engine-three");
  });

  it("rejects an answer to a different action instead of showing it", async () => {
    const f = fixture();
    f.override.engines = async () => ({ kind: "done", detail: "unexpected" });
    f.controller.attach();
    await vi.waitFor(() => expect(f.controller.getSnapshot().enginesFailed).toBe(true));
    expect(f.controller.getSnapshot().error).toContain("不一致");
    expect(f.controller.getSnapshot().engines).toBeNull();
  });

  it("deletes the copy on request and reports the folder open", async () => {
    const f = fixture();
    f.controller.attach();
    await vi.waitFor(() => expect(f.controller.getSnapshot().busy).toBeNull());
    await f.controller.fetch("file");
    await f.controller.reveal();
    expect(f.controller.getSnapshot().notice).toBe("已处理");
    expect(await f.controller.discard()).toBe(true);
    expect(f.controller.getSnapshot().discarded).toBe(true);
    await f.controller.fetch("file");
    expect(f.localScan.mock.calls.filter(([request]) => request.action === "fetch")).toHaveLength(1);
  });
});

describe("local scan transports", () => {
  it("container transport sends fetch-container with the handles it was given", async () => {
    const localScan = vi.fn(async (request: { action: string }) =>
      request.action === "fetch-container" ? fetchResult : { kind: "done", detail: "已处理" } as LocalScanResult);
    const transport = containerScanTransport({ localScan }, "binding-one", "snap-1", "ctr-9", "/etc/nginx");
    await transport.fetch("directory");
    expect(localScan).toHaveBeenCalledWith({
      action: "fetch-container", bindingHandle: "binding-one",
      snapshotHandle: "snap-1", containerHandle: "ctr-9", path: "/etc/nginx", scope: "directory",
    });
    // The container path never carries a binding the page invented on run/discard either.
    await transport.discard("fetch-one");
    expect(localScan).toHaveBeenLastCalledWith({
      action: "discard", bindingHandle: "binding-one", fetchId: "fetch-one",
    });
  });

  it("browser transport sends fetch-browser without any binding the page supplied", async () => {
    const localScan = vi.fn(async (request: { action: string }) => {
      if (request.action === "fetch-browser") return fetchResult;
      if (request.action === "run") {
        return { kind: "run", state: "finished", engineName: "clamscan", exitCode: 0, output: null, hits: [], detail: "已退出" } as LocalScanResult;
      }
      return { kind: "done", detail: "已处理" } as LocalScanResult;
    });
    const transport = browserScanTransport({ localScan }, "browser-1", "entry-7");
    await transport.fetch("file");
    expect(localScan).toHaveBeenCalledWith({
      action: "fetch-browser", browserHandle: "browser-1", entryHandle: "entry-7", scope: "file",
    });
    await transport.run("fetch-one", "engine-one");
    expect(localScan).toHaveBeenLastCalledWith({ action: "run", fetchId: "fetch-one", engineId: "engine-one" });
    await transport.discard("fetch-one");
    expect(localScan).toHaveBeenLastCalledWith({ action: "discard", fetchId: "fetch-one" });
    const sent = localScan.mock.calls.map(([request]) => request as Record<string, unknown>);
    for (const request of sent) expect(request).not.toHaveProperty("bindingHandle");
  });

  it("controller over the browser transport keeps the late-fetch discard guarantee", async () => {
    const pending = deferred<LocalScanResult | null>();
    const localScan = vi.fn(async (request: { action: string }) => {
      if (request.action === "fetch-browser") return pending.promise;
      if (request.action === "discard") return { kind: "done", detail: "已删除" } as LocalScanResult;
      return enginesResult;
    });
    const controller = new LocalScanController(browserScanTransport({ localScan }, "browser-1", "entry-7"));
    controllers.push(controller);
    controller.attach();
    await vi.waitFor(() => expect(controller.getSnapshot().busy).toBeNull());
    const request = controller.fetch("file");
    controller.dispose();
    pending.resolve(fetchResult);
    await request;
    expect(controller.getSnapshot().fetch).toBeNull();
    expect(localScan).toHaveBeenLastCalledWith({ action: "discard", fetchId: "fetch-one" });
  });

  it("a mismatched answer is refused instead of shown", async () => {
    const localScan = vi.fn(async () => ({ kind: "done", detail: "x" } as LocalScanResult));
    const transport = containerScanTransport({ localScan }, "b", "s", "c", "/etc");
    await expect(transport.fetch("file")).rejects.toThrow("不一致");
  });
});
