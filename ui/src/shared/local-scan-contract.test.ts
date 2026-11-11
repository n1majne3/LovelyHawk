import { describe, expect, it } from "vitest";
import {
  isLocalScanChildRequest,
  isLocalScanRequest,
  isLocalScanResult,
  matchesLocalScanResult,
  type LocalScanChildRequest,
  type LocalScanFetchDto,
  type LocalScanRequest,
} from "./local-scan-contract";

const engine = { id: "engine-one", name: "D盾网页查杀", kind: "gui", programName: "D_Safe_Manage.exe" };
const cliEngine = { id: "engine-two", name: "clamscan", kind: "cli", programName: "clamscan.exe" };
const fetched: LocalScanFetchDto = {
  fetchId: "fetch-one",
  path: "/tmp/.cache/.helper",
  sourceKind: "file",
  scope: "file",
  files: 1,
  directories: 0,
  bytes: 42,
  skipped: 0,
  skippedReasons: [],
  truncated: false,
  archiveSha256: "a".repeat(64),
  archiveBytes: 4096,
  transport: "sftp",
  stagingDirectory: "C:/scan/fetch-one/content",
  entries: [".helper"],
  fetchedAt: "2026-08-25T23:31:00+00:00",
  expiresInSeconds: 1800,
  origin: "host",
  originLabel: "",
};
const enginesResult = { kind: "engines", engines: [engine, cliEngine] };
const fetchResult = { kind: "fetch", fetch: fetched };
const runResult = { kind: "run", state: "finished", engineName: "clamscan", exitCode: 1, output: "FOUND\n", detail: "已退出" };
const launchedResult = { kind: "run", state: "launched", engineName: "D盾网页查杀", exitCode: null, output: null, detail: "已启动" };
const doneResult = { kind: "done", detail: "已删除本次取回的本地副本。" };

describe("local scan boundary", () => {
  it("accepts only exact requests: closed actions, bounded fields, no local paths", () => {
    const valid = [
      { action: "engines" },
      { action: "configure", name: "D盾", kind: "gui", arguments: [] },
      { action: "configure", name: "clam", kind: "cli", arguments: ["--scan", "{dir}"] },
      { action: "remove-engine", engineId: "engine-one" },
      { action: "fetch", bindingHandle: "binding", pathHandle: "path", scope: "file" },
      { action: "fetch", bindingHandle: "binding", pathHandle: "path", scope: "directory" },
      { action: "inspect", bindingHandle: "binding", fetchId: "fetch-one" },
      { action: "reveal", bindingHandle: "binding", fetchId: "fetch-one" },
      { action: "discard", bindingHandle: "binding", fetchId: "fetch-one" },
      { action: "run", bindingHandle: "binding", fetchId: "fetch-one", engineId: "engine-one" },
      { action: "fetch-container", bindingHandle: "b", snapshotHandle: "s", containerHandle: "c",
        path: "/var/www", scope: "file" },
      { action: "fetch-container", bindingHandle: "b", snapshotHandle: "s", containerHandle: "c",
        path: "/var/www", scope: "directory" },
    ];
    for (const request of valid) expect(isLocalScanRequest(request), JSON.stringify(request)).toBe(true);

    for (const bad of [
      null, "fetch", [], { action: "shell" }, { action: "fetch" },
      // Key counts are exact: a local path or extra field is not a request.
      { action: "engines", bindingHandle: "binding" },
      { action: "configure", name: "x", kind: "gui" },
      { action: "configure", name: "x", kind: "gui", arguments: [], program: "C:/evil.exe" },
      { action: "remove-engine" },
      { action: "remove-engine", engineId: "x", extra: 1 },
      { action: "fetch", bindingHandle: "b", pathHandle: "p", scope: "file", stagingDirectory: "C:/x" },
      { action: "inspect", bindingHandle: "b", fetchId: "f", run: true },
      { action: "run", bindingHandle: "b", fetchId: "f" },
      // Closed sets only: no invented scope, kind or action.
      { action: "fetch", bindingHandle: "b", pathHandle: "p", scope: "host" },
      { action: "configure", name: "x", kind: "service", arguments: [] },
      { action: "fetch", bindingHandle: "b", pathHandle: "p", scope: "FILE" },
      // Control characters and empty or oversized fields stay out.
      { action: "fetch", bindingHandle: "b\u0007", pathHandle: "p", scope: "file" },
      { action: "fetch", bindingHandle: "b", pathHandle: "p\nq", scope: "file" },
      { action: "remove-engine", engineId: "" },
      { action: "configure", name: "", kind: "gui", arguments: [] },
      { action: "configure", name: "汉".repeat(22), kind: "gui", arguments: [] },
      { action: "configure", name: "x", kind: "gui", arguments: Array(17).fill("a") },
      { action: "configure", name: "x", kind: "gui", arguments: ["x".repeat(513)] },
      { action: "configure", name: "x", kind: "gui", arguments: "not-array" },
      { action: "run", bindingHandle: "b", fetchId: "f", engineId: "e\u0085" },
      { action: "run", bindingHandle: "b", fetchId: "汉".repeat(43), engineId: "e" },
    ]) expect(isLocalScanRequest(bad), JSON.stringify(bad)).toBe(false);
  });

  it("validates each result kind with exact keys and bounded fields", () => {
    expect(isLocalScanResult(enginesResult)).toBe(true);
    expect(isLocalScanResult({ kind: "engines", engines: [] })).toBe(true);
    expect(isLocalScanResult(fetchResult)).toBe(true);
    expect(isLocalScanResult(runResult)).toBe(true);
    expect(isLocalScanResult(launchedResult)).toBe(true);
    expect(isLocalScanResult(doneResult)).toBe(true);

    for (const bad of [
      null, "engines", [], { kind: "other" },
      { kind: "engines", engines: [engine], extra: true },
      { kind: "engines", engines: Array(9).fill(engine) },
      { kind: "engines", engines: [{ ...engine, kind: "service" }] },
      { kind: "engines", engines: [{ ...engine, programPath: "C:/evil.exe" }] },
      { kind: "engines", engines: [{ ...engine, name: "" }] },
      { kind: "fetch", fetch: { ...fetched, path: "relative/path" } },
      { kind: "fetch", fetch: { ...fetched, sourceKind: "symlink" } },
      { kind: "fetch", fetch: { ...fetched, archiveSha256: "not-hex" } },
      { kind: "fetch", fetch: { ...fetched, bytes: -1 } },
      { kind: "fetch", fetch: { ...fetched, stagingDirectory: "" } },
      { kind: "fetch", fetch: { ...fetched, origin: "container", originLabel: "x".repeat(257) } },
      { kind: "fetch", fetch: { ...fetched, origin: "container", originLabel: 0 } },
      { kind: "fetch", fetch: { ...fetched, origin: "host", originLabel: "web（a1b2，docker）" } },
      { kind: "fetch", fetch: { ...fetched, origin: "runtime" } },
      { kind: "fetch", fetch: { ...fetched, extra: true } },
      { kind: "run", state: "running", engineName: "x", exitCode: null, output: null, detail: "" },
      { kind: "run", state: "finished", engineName: "", exitCode: 0, output: null, detail: "" },
      { kind: "run", state: "finished", engineName: "x", exitCode: 0, output: null, detail: "", extra: 1 },
      { kind: "done", detail: "x".repeat(2049) },
      { kind: "done" },
      { kind: "done", detail: "x", extra: true },
    ]) expect(isLocalScanResult(bad), JSON.stringify(bad)).toBe(false);
  });

  it("pairs each request with only its own result kind", () => {
    // The engine list answers all three engine questions.
    for (const request of [
      { action: "engines" },
      { action: "configure", name: "x", kind: "gui", arguments: [] },
      { action: "remove-engine", engineId: "engine-one" },
    ] as const satisfies readonly LocalScanRequest[]) {
      expect(matchesLocalScanResult(request, enginesResult)).toBe(true);
      expect(matchesLocalScanResult(request, fetchResult)).toBe(false);
      expect(matchesLocalScanResult(request, doneResult)).toBe(false);
    }
    // Only configure may come back empty: the system dialog was cancelled.
    expect(matchesLocalScanResult({ action: "configure", name: "x", kind: "gui", arguments: [] }, null)).toBe(true);
    expect(matchesLocalScanResult({ action: "engines" }, null)).toBe(false);
    expect(matchesLocalScanResult({ action: "fetch", bindingHandle: "b", pathHandle: "p", scope: "file" }, null)).toBe(false);
    expect(matchesLocalScanResult({ action: "discard", bindingHandle: "b", fetchId: "f" }, null)).toBe(false);

    const fetchRequest: LocalScanRequest = { action: "fetch", bindingHandle: "b", pathHandle: "p", scope: "file" };
    expect(matchesLocalScanResult(fetchRequest, fetchResult)).toBe(true);
    expect(matchesLocalScanResult(fetchRequest, enginesResult)).toBe(false);
    // inspect answers with the same fetch record, for this fetch only.
    const inspect: LocalScanRequest = { action: "inspect", bindingHandle: "b", fetchId: "fetch-one" };
    expect(matchesLocalScanResult(inspect, fetchResult)).toBe(true);
    expect(matchesLocalScanResult(inspect, { kind: "fetch", fetch: { ...fetched, fetchId: "other" } })).toBe(false);
    // A fetch does not have to name its id back, but the record still has to parse.
    expect(matchesLocalScanResult(fetchRequest, { kind: "fetch", fetch: { ...fetched, path: "relative" } })).toBe(false);

    const runRequest: LocalScanRequest = { action: "run", bindingHandle: "b", fetchId: "fetch-one", engineId: "engine-one" };
    expect(matchesLocalScanResult(runRequest, runResult)).toBe(true);
    expect(matchesLocalScanResult(runRequest, launchedResult)).toBe(true);
    expect(matchesLocalScanResult(runRequest, doneResult)).toBe(false);

    for (const request of [
      { action: "reveal", bindingHandle: "b", fetchId: "fetch-one" },
      { action: "discard", bindingHandle: "b", fetchId: "fetch-one" },
    ] as const satisfies readonly LocalScanRequest[]) {
      expect(matchesLocalScanResult(request, doneResult)).toBe(true);
      expect(matchesLocalScanResult(request, fetchResult)).toBe(false);
      expect(matchesLocalScanResult(request, runResult)).toBe(false);
    }

    // Every fetch source pairs with a fetch result; the container and
    // browser variants share the pairing rules.
    for (const request of [
      { action: "fetch-container", bindingHandle: "b", snapshotHandle: "s", containerHandle: "c",
        path: "/x", scope: "file" },
      { action: "fetch-browser", browserHandle: "w", entryHandle: "e", scope: "directory" },
    ] as const satisfies readonly (LocalScanRequest | LocalScanChildRequest)[]) {
      expect(matchesLocalScanResult(request, fetchResult)).toBe(true);
      expect(matchesLocalScanResult(request, doneResult)).toBe(false);
      expect(matchesLocalScanResult(request, null)).toBe(false);
    }
    // Child requests pair the same way for the shared actions.
    expect(matchesLocalScanResult({ action: "run", fetchId: "f", engineId: "e" }, runResult)).toBe(true);
    expect(matchesLocalScanResult({ action: "discard", fetchId: "f" }, doneResult)).toBe(true);
    expect(matchesLocalScanResult({ action: "inspect", fetchId: "fetch-one" }, fetchResult)).toBe(true);
    expect(matchesLocalScanResult(
      { action: "inspect", fetchId: "other" }, fetchResult,
    )).toBe(false);
  });
});
