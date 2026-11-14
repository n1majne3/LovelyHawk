import { describe, expect, it } from "vitest";

import type { ProcessWatchEvent, ProcessWatchPoll } from "../shared/process-watch-contract";
import {
  createProcessWatchState,
  processWatchConclusion,
  processWatchReducer,
  canConfirmUpload,
  visibleWatchEvents,
} from "./process-watch-state";

function event(partial: Partial<ProcessWatchEvent> & { seq: number }): ProcessWatchEvent {
  return {
    kind: "process",
    atMs: 1_000 + partial.seq,
    uid: 0,
    pid: 100 + partial.seq,
    ppid: 1,
    startTicks: 7_777,
    command: "lh-marker",
    clipped: false,
    origin: "observed",
    own: false,
    raw: "E|N|1000|0|100|1|7777|0|aa|bb",
    ...partial,
  };
}

function poll(partial: Partial<ProcessWatchPoll> = {}): ProcessWatchPoll {
  return {
    watchHandle: "550e8400-e29b-41d4-a716-446655440000",
    state: "running",
    elapsedSeconds: 10,
    observedCount: 0,
    baselineCount: 0,
    ownCount: 0,
    unparsedCount: 0,
    truncated: false,
    gaps: [],
    stopVerified: null,
    selfEndsAtMs: 0,
    nextCursor: 0,
    cleanup: null,
    events: [],
    unparsed: [],
    ...partial,
  };
}

function running() {
  let state = createProcessWatchState("scope-a");
  state = processWatchReducer(state, {
    type: "probe-loaded",
    probe: {
      procReadable: true, gaps: [], fractionalSleep: true,
      account: "root", isRoot: true,
    },
  });
  state = processWatchReducer(state, { type: "start-started" });
  return processWatchReducer(state, {
    type: "start-loaded",
    watchHandle: "550e8400-e29b-41d4-a716-446655440000",
    gaps: ["container"],
  });
}

describe("processWatchReducer", () => {
  it("walks the machine in order and only in order", () => {
    let state = createProcessWatchState("scope-a");
    expect(state.status).toBe("probing");
    // A start press before the probe lands is ignored, not queued.
    state = processWatchReducer(state, { type: "start-started" });
    expect(state.status).toBe("probing");
    state = processWatchReducer(state, {
      type: "probe-loaded",
      probe: {
        procReadable: true, gaps: ["container"], fractionalSleep: true,
        account: "root", isRoot: true,
      },
    });
    expect(state.status).toBe("ready");
    state = processWatchReducer(state, { type: "start-started" });
    expect(state.status).toBe("starting");
    // A second press while the request is in flight cannot start two.
    state = processWatchReducer(state, { type: "start-started" });
    expect(state.status).toBe("starting");
    state = processWatchReducer(state, {
      type: "start-loaded",
      watchHandle: "550e8400-e29b-41d4-a716-446655440000",
      gaps: ["container"],
    });
    expect(state.status).toBe("running");
    expect(state.gaps).toEqual(["container"]);
  });

  it("drops poll answers for a different handle or a stale run", () => {
    const state = running();
    const foreign = processWatchReducer(state, {
      type: "poll-loaded",
      result: poll({ watchHandle: "660e8400-e29b-41d4-a716-446655440000", events: [event({ seq: 1 })] }),
    });
    expect(foreign.events).toHaveLength(0);
    const mine = processWatchReducer(state, {
      type: "poll-loaded",
      result: poll({ nextCursor: 1, observedCount: 1, events: [event({ seq: 1 })] }),
    });
    expect(mine.events).toHaveLength(1);
    expect(mine.cursor).toBe(1);
  });

  it("moves to the terminal state the stream reports", () => {
    let state = running();
    state = processWatchReducer(state, {
      type: "poll-loaded",
      result: poll({ state: "finished", nextCursor: 0 }),
    });
    expect(state.status).toBe("finished");
    // A cancelled watch stays cancelled even if more polls land.
    state = running();
    state = processWatchReducer(state, { type: "stop-started" });
    expect(state.status).toBe("stopping");
    expect(processWatchReducer(state, { type: "poll-failed", error: "lost" }).failure).toBe("lost");
    state = processWatchReducer(state, {
      type: "poll-loaded",
      result: poll({ state: "cancelled", stopVerified: true }),
    });
    expect(state.status).toBe("cancelled");
    expect(state.stopVerified).toBe(true);
  });

  it("rejects out-of-range duration and interval picks", () => {
    const state = createProcessWatchState("scope-a");
    expect(processWatchReducer(state, { type: "duration-changed", value: 30 }).durationSeconds)
      .toBe(180);
    expect(processWatchReducer(state, { type: "interval-changed", value: 100 }).intervalMs)
      .toBe(500);
    expect(processWatchReducer(state, { type: "duration-changed", value: 600 }).durationSeconds)
      .toBe(600);
  });
});

describe("visibleWatchEvents", () => {
  it("hides baseline and own rows by default, behind counted toggles", () => {
    let state = running();
    state = {
      ...state,
      events: [
        event({ seq: 1, origin: "baseline", command: "sshd" }),
        event({ seq: 2, own: true, command: "sh watcher" }),
        event({ seq: 3, command: "lh-marker-4" }),
      ],
      baselineCount: 1,
      ownCount: 1,
      observedCount: 1,
    };
    expect(visibleWatchEvents(state).map((item) => item.command)).toEqual(["lh-marker-4"]);
    const withBaseline = processWatchReducer(state, { type: "baseline-toggled" });
    expect(visibleWatchEvents(withBaseline).map((item) => item.command))
      .toEqual(["sshd", "lh-marker-4"]);
    const withOwn = processWatchReducer(state, { type: "own-toggled" });
    expect(visibleWatchEvents(withOwn).map((item) => item.command))
      .toEqual(["sh watcher", "lh-marker-4"]);
  });

  it("filters by text and uid", () => {
    let state = running();
    state = {
      ...state,
      events: [
        event({ seq: 1, command: "lh-marker-1", uid: 0 }),
        event({ seq: 2, command: "cron", uid: 100 }),
      ],
    };
    state = processWatchReducer(state, { type: "filter-changed", value: "cron" });
    expect(visibleWatchEvents(state)).toHaveLength(1);
    state = processWatchReducer(state, { type: "filter-changed", value: "" });
    state = processWatchReducer(state, { type: "uid-filter-changed", value: "100" });
    expect(visibleWatchEvents(state).map((item) => item.command)).toEqual(["cron"]);
  });
});

describe("processWatchConclusion", () => {
  it("never claims quiet when the run had gaps", () => {
    let state = running();
    state = { ...state, status: "finished", elapsedSeconds: 180, gaps: ["container"] };
    expect(processWatchConclusion(state)).toContain("采集有缺口");
    state = { ...state, gaps: [], observedCount: 5 };
    expect(processWatchConclusion(state)).toContain("观察到 5 个新进程");
    state = { ...state, status: "cancelled" };
    expect(processWatchConclusion(state)).toContain("不完整");
    state = { ...state, status: "disconnected" };
    expect(processWatchConclusion(state)).toContain("断开");
  });
});

describe("upload run", () => {
  const tool = {
    toolHandle: "550e8400-e29b-41d4-a716-446655440001", fileName: "pspy64", size: 3_104_768,
    sha256: "c".repeat(64), recognized: null as string | null, arch: "x86_64" as const,
  };
  const plan = {
    planHandle: "550e8400-e29b-41d4-a716-446655440002",
    directory: "/root/.lovelyhawk-watch-0123456789abcdef", size: 3_104_768, sha256: "c".repeat(64),
    recognized: null as string | null, account: "root", isRoot: true, machine: "x86_64",
    durationSeconds: 180, fileEvents: false, fileEventDirs: [],
    gaps: ["tool-may-miss-short-lived" as const], expiresInSeconds: 300,
  };
  function ready() {
    return processWatchReducer(createProcessWatchState("scope-a"), {
      type: "probe-loaded",
      probe: { procReadable: true, gaps: [], fractionalSleep: true, account: "root", isRoot: true },
    });
  }

  it("cannot be planned without a picked program, nor started without a plan", () => {
    let state = processWatchReducer(ready(), { type: "method-changed", value: "pspy" });
    expect(processWatchReducer(state, { type: "plan-started" }).status).toBe("ready");
    // The no-upload start button does nothing while the upload method is chosen.
    expect(processWatchReducer(state, { type: "start-started" }).status).toBe("ready");
    state = processWatchReducer(state, { type: "tool-picked", tool });
    state = processWatchReducer(state, { type: "plan-started" });
    expect(state.status).toBe("planning");
    expect(processWatchReducer(state, { type: "start-started" }).status).toBe("planning");
  });

  it("asks again before running a file no release digest matches", () => {
    let state = processWatchReducer(ready(), { type: "method-changed", value: "pspy" });
    state = processWatchReducer(state, { type: "tool-picked", tool });
    state = processWatchReducer(state, { type: "plan-started" });
    state = processWatchReducer(state, { type: "plan-loaded", plan });
    expect(state.status).toBe("confirming");
    expect(canConfirmUpload(state)).toBe(false);
    expect(processWatchReducer(state, { type: "start-started" }).status).toBe("confirming");
    state = processWatchReducer(state, { type: "unknown-accepted-toggled" });
    expect(canConfirmUpload(state)).toBe(true);
    expect(processWatchReducer(state, { type: "start-started" }).status).toBe("starting");
    const known = processWatchReducer(
      processWatchReducer(ready(), { type: "method-changed", value: "pspy" }),
      { type: "tool-picked", tool: { ...tool, recognized: "pspy64 v1.2.1" } },
    );
    const planned = processWatchReducer(
      processWatchReducer(known, { type: "plan-started" }),
      { type: "plan-loaded", plan: { ...plan, recognized: "pspy64 v1.2.1" } },
    );
    expect(canConfirmUpload(planned)).toBe(true);
  });

  it("spends the plan on its one start and forgets the extra confirmation with it", () => {
    let state = processWatchReducer(ready(), { type: "method-changed", value: "pspy" });
    state = processWatchReducer(state, { type: "tool-picked", tool });
    state = processWatchReducer(state, { type: "plan-started" });
    state = processWatchReducer(state, { type: "plan-loaded", plan });
    state = processWatchReducer(state, { type: "unknown-accepted-toggled" });
    state = processWatchReducer(state, { type: "start-started" });
    state = processWatchReducer(state, { type: "start-failed", error: "上传后不一致" });
    expect(state.status).toBe("ready");
    expect(state.plan).toBeNull();
    expect(state.unknownAccepted).toBe(false);
    expect(state.failure).toBe("上传后不一致");
    // Picking another file also clears an earlier "run it anyway".
    state = processWatchReducer(state, { type: "plan-started" });
    state = processWatchReducer(state, { type: "plan-loaded", plan });
    state = processWatchReducer(state, { type: "unknown-accepted-toggled" });
    state = processWatchReducer(state, { type: "plan-dismissed" });
    expect(state.status).toBe("ready");
    expect(state.unknownAccepted).toBe(false);
  });

  it("keeps a verified cleanup and says so when it could not be verified", () => {
    let state = running();
    state = processWatchReducer(state, {
      type: "poll-loaded",
      result: poll({ state: "finished", cleanup: "unverified", observedCount: 3 }),
    });
    expect(state.cleanup).toBe("unverified");
    expect(processWatchConclusion(state)).toContain("采集有缺口");
    state = processWatchReducer(state, { type: "cleanup-known", cleanup: "clean" });
    expect(state.cleanup).toBe("clean");
    state = processWatchReducer(state, { type: "cleanup-known", cleanup: "residue" });
    expect(state.cleanup).toBe("clean");
  });

  it("hides file rows on request and never groups them with processes", () => {
    let state = running();
    state = {
      ...state,
      events: [
        event({ seq: 1, command: "cat /etc/crontab" }),
        event({ seq: 2, kind: "file", pid: 0, uid: -1, command: "OPEN /etc/crontab" }),
      ],
    };
    expect(visibleWatchEvents(state)).toHaveLength(2);
    state = processWatchReducer(state, { type: "files-toggled" });
    expect(visibleWatchEvents(state).map((item) => item.kind)).toEqual(["process"]);
  });

  it("leaves a finished run behind for a new one, and never a running one", () => {
    const live = running();
    expect(processWatchReducer(live, { type: "restarted" })).toBe(live);
    let state = processWatchReducer(live, {
      type: "poll-loaded",
      result: poll({ state: "finished", nextCursor: 1, observedCount: 1, events: [event({ seq: 1 })] }),
    });
    state = processWatchReducer(state, { type: "restarted" });
    expect(state.status).toBe("ready");
    expect(state.watchHandle).toBeNull();
    expect(state.events).toHaveLength(0);
    expect(state.probe).not.toBeNull();
  });

  it("returns to the start screen when there is nothing to come back to", () => {
    let state = processWatchReducer(ready(), { type: "resumed", watchHandle: plan.planHandle });
    expect(state.status).toBe("running");
    state = processWatchReducer(state, { type: "resume-failed" });
    expect(state.status).toBe("ready");
    expect(state.watchHandle).toBeNull();
    // A watch that already delivered rows is not thrown away by one lost poll.
    let live = running();
    live = { ...live, events: [event({ seq: 1 })] };
    expect(processWatchReducer(live, { type: "resume-failed" }).status).toBe("running");
  });
});
