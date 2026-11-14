import { describe, expect, it } from "vitest";

import {
  isProcessWatchAccounting,
  isProcessWatchSourceList,
  isProcessWatchPoll,
  isProcessWatchProbe,
  isProcessWatchResidueCleaned,
  isProcessWatchResidueList,
  isProcessWatchTool,
  isProcessWatchUploadInput,
  isProcessWatchUploadPlan,
  isProcessWatchStartInput,
  isProcessWatchStarted,
  isProcessWatchStopped,
} from "./process-watch-contract";

const HANDLE = "17f79994-72dc-4fa8-9132-c17dcb55210c";

const probe = {
  procReadable: true,
  gaps: ["container", "polling-misses-short-lived"],
  fractionalSleep: true,
  account: "root",
  isRoot: true,
};

const event = {
  kind: "process", seq: 1, atMs: 1_794_649_210_000, uid: 0, pid: 4526, ppid: 1, startTicks: 99,
  command: "sleep 10", clipped: false, origin: "observed", own: false, raw: "E|N|…",
};

const poll = {
  watchHandle: HANDLE, state: "running", elapsedSeconds: 12, observedCount: 1,
  baselineCount: 0, ownCount: 0, unparsedCount: 0, truncated: false,
  gaps: ["container", "polling-misses-short-lived"], stopVerified: null,
  selfEndsAtMs: 1_794_649_360_000, nextCursor: 1, cleanup: null, events: [event], unparsed: [],
};

describe("process watch contract", () => {
  it("accepts the probe a readable target returns", () => {
    expect(isProcessWatchProbe(probe)).toBe(true);
    expect(isProcessWatchProbe({ ...probe, procReadable: false, gaps: ["proc-unreadable"] })).toBe(true);
  });

  it("rejects a probe whose readable flag contradicts its gaps", () => {
    expect(isProcessWatchProbe({ ...probe, gaps: ["proc-unreadable"] })).toBe(false);
    expect(isProcessWatchProbe({ ...probe, procReadable: false })).toBe(false);
  });

  it("rejects unknown gaps, extra fields and missing fields in a probe", () => {
    expect(isProcessWatchProbe({ ...probe, gaps: ["made-up"] })).toBe(false);
    expect(isProcessWatchProbe({ ...probe, path: "/tmp/x" })).toBe(false);
    const { account: _account, ...withoutAccount } = probe;
    expect(isProcessWatchProbe(withoutAccount)).toBe(false);
  });

  it("only lets the offered durations and intervals start a watch", () => {
    expect(isProcessWatchStartInput({ durationSeconds: 180, intervalMs: 500 })).toBe(true);
    expect(isProcessWatchStartInput({ durationSeconds: 30, intervalMs: 500 })).toBe(false);
    expect(isProcessWatchStartInput({ durationSeconds: 180, intervalMs: 50 })).toBe(false);
    expect(isProcessWatchStartInput({ durationSeconds: 180, intervalMs: 500, args: "-f" })).toBe(false);
  });

  it("accepts a started watch and refuses another method name", () => {
    const started = { watchHandle: HANDLE, method: "proc-poll", startedAtMs: 0, deadlineAtMs: 0, gaps: [] };
    expect(isProcessWatchStarted(started)).toBe(true);
    expect(isProcessWatchStarted({ ...started, method: "pspy" })).toBe(true);
    expect(isProcessWatchStarted({ ...started, method: "auditd" })).toBe(false);
  });

  it("accepts a running poll and rejects out-of-order or over-claimed ones", () => {
    expect(isProcessWatchPoll(poll)).toBe(true);
    expect(isProcessWatchPoll({ ...poll, stopVerified: true })).toBe(false);
    expect(isProcessWatchPoll({ ...poll, nextCursor: 0 })).toBe(false);
    expect(isProcessWatchPoll({ ...poll, events: [event, event] })).toBe(false);
    expect(isProcessWatchPoll({ ...poll, events: [{ ...event, origin: "guessed" }] })).toBe(false);
  });

  it("keeps an unverifiable stop distinct from a verified one", () => {
    expect(isProcessWatchStopped({ state: "cancelled", stopVerified: true, cleanup: null })).toBe(true);
    expect(isProcessWatchStopped({ state: "cancelled", stopVerified: true, cleanup: "clean" })).toBe(true);
    expect(isProcessWatchStopped({ state: "disconnected", stopVerified: null, cleanup: "unverified" })).toBe(true);
    expect(isProcessWatchStopped({ state: "cancelled", stopVerified: true, cleanup: "done" })).toBe(false);
    expect(isProcessWatchStopped({ state: "stopped", stopVerified: true, cleanup: null })).toBe(false);
  });

  it("never lets a running watch claim its upload was cleaned", () => {
    expect(isProcessWatchPoll({ ...poll, cleanup: "clean" })).toBe(false);
    expect(isProcessWatchPoll({ ...poll, state: "finished", cleanup: "clean" })).toBe(true);
    expect(isProcessWatchPoll({ ...poll, events: [{ ...event, kind: "file", pid: 0, uid: -1 }] })).toBe(true);
    expect(isProcessWatchPoll({ ...poll, events: [{ ...event, kind: "socket" }] })).toBe(false);
  });

  it("accepts a picked program and refuses one that carries a path or a bad digest", () => {
    const tool = {
      toolHandle: HANDLE, fileName: "pspy64", size: 3_104_768, sha256: "c".repeat(64),
      recognized: "pspy64 v1.2.1", arch: "x86_64",
    };
    expect(isProcessWatchTool(tool)).toBe(true);
    expect(isProcessWatchTool({ ...tool, recognized: null })).toBe(true);
    expect(isProcessWatchTool({ ...tool, localPath: "C:/tools/pspy64" })).toBe(false);
    expect(isProcessWatchTool({ ...tool, sha256: "C".repeat(64) })).toBe(false);
    expect(isProcessWatchTool({ ...tool, size: 0 })).toBe(false);
    expect(isProcessWatchTool({ ...tool, arch: "arm64" })).toBe(false);
  });

  it("lets the page ask for an upload only by handle, duration and one switch", () => {
    const input = { toolHandle: HANDLE, durationSeconds: 180, fileEvents: false };
    expect(isProcessWatchUploadInput(input)).toBe(true);
    expect(isProcessWatchUploadInput({ ...input, durationSeconds: 30 })).toBe(false);
    expect(isProcessWatchUploadInput({ ...input, directory: "/tmp" })).toBe(false);
    expect(isProcessWatchUploadInput({ ...input, args: "-r /" })).toBe(false);
    expect(isProcessWatchUploadInput({ ...input, toolHandle: "/tmp/pspy" })).toBe(false);
  });

  it("accepts a plan that lands in a landing directory and nothing else", () => {
    const plan = {
      planHandle: HANDLE, directory: "/root/.lovelyhawk-watch-0123456789abcdef", size: 3_104_768,
      sha256: "c".repeat(64), recognized: null, account: "root", isRoot: true, machine: "x86_64",
      durationSeconds: 180, fileEvents: false, fileEventDirs: [],
      gaps: ["container", "tool-may-miss-short-lived"], expiresInSeconds: 300,
    };
    expect(isProcessWatchUploadPlan(plan)).toBe(true);
    expect(isProcessWatchUploadPlan({ ...plan, fileEvents: true, fileEventDirs: ["/etc", "/tmp"] })).toBe(true);
    expect(isProcessWatchUploadPlan({ ...plan, directory: "/etc" })).toBe(false);
    expect(isProcessWatchUploadPlan({ ...plan, directory: "/tmp/../etc/.lovelyhawk-watch-0123456789abcdef; id" })).toBe(false);
    expect(isProcessWatchUploadPlan({ ...plan, fileEvents: true, fileEventDirs: ["/usr"] })).toBe(false);
    expect(isProcessWatchUploadPlan({ ...plan, fileEventDirs: ["/etc"] })).toBe(false);
    expect(isProcessWatchUploadPlan({ ...plan, gaps: ["made-up"] })).toBe(false);
  });

  it("keeps a source that cannot be read apart from one that is absent", () => {
    expect(isProcessWatchSourceList([
      { source: "accounting", state: "unreadable" }, { source: "bpftrace", state: "present" },
    ])).toBe(true);
    expect(isProcessWatchSourceList([{ source: "accounting", state: "on" }])).toBe(false);
    expect(isProcessWatchSourceList([{ source: "strace", state: "present" }])).toBe(false);
    const group = {
      command: "lh-beacon", count: 3, uids: [0], firstAtMs: 1, lastAtMs: 3, cadence: "periodic", periodMs: 60_000,
    };
    const accounting = { minutes: 15, records: 3, unparsed: 0, truncated: false, groups: [group] };
    expect(isProcessWatchAccounting(accounting)).toBe(true);
    expect(isProcessWatchAccounting({ ...accounting, minutes: 0 })).toBe(false);
    expect(isProcessWatchAccounting({ ...accounting, groups: [{ ...group, periodMs: null }] })).toBe(false);
    expect(isProcessWatchAccounting({ ...accounting, groups: [{ ...group, args: "-c id" }] })).toBe(false);
  });

  it("reads a residue list and a cleanup answer strictly", () => {
    const residue = {
      residueHandle: HANDLE, directory: "/home/a/.lovelyhawk-watch-0123456789abcdef", size: 3_104_768,
      sha256: "c".repeat(64), recognized: "pspy64 v1.2.1", running: false,
    };
    expect(isProcessWatchResidueList([residue, { ...residue, sha256: "", size: 0, recognized: null }])).toBe(true);
    expect(isProcessWatchResidueList([{ ...residue, directory: "/home/a" }])).toBe(false);
    expect(isProcessWatchResidueCleaned({ cleanup: "clean" })).toBe(true);
    expect(isProcessWatchResidueCleaned({ cleanup: "ok" })).toBe(false);
  });
});
