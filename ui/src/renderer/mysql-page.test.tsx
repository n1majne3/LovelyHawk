import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";
import { describe, expect, it, vi } from "vitest";
import { isMySqlRuntimeRequest, isMySqlRuntimeResponse, matchesMySqlRuntimeResponse, type MySqlInstanceReview, type MySqlProfileSummary } from "../shared/mysql-runtime-contract";
import { MysqlPage, MysqlReviewPanel } from "./MysqlPage";
import { MysqlRuntimeController } from "./mysql-runtime-controller";
import { closeNeedsConfirm, MysqlPasswordDialog, passwordRules, planPasswordRequest, rejectionTarget, restoreAvailable, savedUpdateText, unverifiableReasonText } from "./MysqlPasswordDialog";

const profile: MySqlProfileSummary = { profileHandle: "p", name: "audit", host: "127.0.0.1", port: 3306, username: "root", database: "", tlsMode: "verify-full", hasPassword: true, hasCa: false, unassigned: false };
const good = "Aa1!password9";
const secret = "secret-canary";
const noop = (): void => undefined;
const review: MySqlInstanceReview = {
  product: "MySQL", serverVersion: "8.0.36", connecting: "'root'@'localhost'",
  accounts: [
    { user: "root", host: "localhost", plugin: "caching_sha2_password", emptySecret: false, superuser: true, filePriv: true, grantPriv: true, locked: false },
    { user: "app", host: "%", plugin: "mysql_native_password", emptySecret: true, superuser: false, filePriv: false, grantPriv: false, locked: null },
  ],
  accountTotal: 5,
  udfs: [{ name: "sys_exec", library: "libevil.so" }],
  udfTotal: 1,
  variables: { general_log: "OFF", general_log_file: "/var/log/mysql/general.log", log_output: "FILE", local_infile: "0", secure_file_priv: "" },
  findings: [
    { level: "high", code: "empty-password", detail: "app@% 使用空口令" },
    { level: "review", code: "native-plugin", detail: "存在旧版认证插件" },
    { level: "info", code: "version-ok", detail: "版本可识别" },
  ],
  gaps: ["mysql.user 部分列不可读"],
  log: { path: "/var/log/mysql/error.log", tailBytes: 65536, denied: [{ user: "root", host: "192.0.2.10", count: 3 }], hits: [{ kind: "access-denied", excerpt: "Access denied for user 'root'@'192.0.2.10'" }] },
};

describe("MySQL page", () => {
  it("has an honest disconnected state and does not call the backend without a target", () => {
    const api = { mysqlRuntime: vi.fn() };
    const html = renderToStaticMarkup(<MysqlPage api={api} bindingHandle={null} targetLabel="未连接主机" />);
    expect(html).toContain("请先连接 SSH 主机"); expect(html).not.toContain("已删除");
    expect(api.mysqlRuntime).not.toHaveBeenCalled();
  });
  it("escapes target text", () => {
    const html = renderToStaticMarkup(<MysqlPage api={{ mysqlRuntime: vi.fn() }} bindingHandle={null} targetLabel={'<img src=x onerror="bad">'} />);
    expect(html).toContain("&lt;img"); expect(html).not.toContain("<img");
  });
});

describe("MysqlRuntimeController", () => {
  it("lists profiles into the snapshot and stays silent after dispose", async () => {
    const api = { mysqlRuntime: vi.fn().mockResolvedValue({ kind: "profiles", profiles: [profile] }) };
    const controller = new MysqlRuntimeController(api, "b");
    await controller.list();
    expect(api.mysqlRuntime).toHaveBeenCalledWith({ action: "list", bindingHandle: "b" });
    expect(controller.getSnapshot().profiles).toEqual([profile]);
    controller.dispose();
    const later = new MysqlRuntimeController(api, "b");
    later.dispose();
    expect(await later.list()).toBeNull();
  });
  it("sends the save request with the profile input and password change, then replaces the old row", async () => {
    const api = { mysqlRuntime: vi.fn().mockResolvedValue({ kind: "saved", profile: { ...profile, profileHandle: "p2", hasPassword: false } }) };
    const controller = new MysqlRuntimeController(api, "b");
    const input = { name: "audit", host: "127.0.0.1", port: 3306, username: "root", database: "", tlsMode: "verify-full" as const, caPem: null };
    const response = await controller.request({ action: "save", bindingHandle: "b", profileHandle: "p", profile: input, password: { action: "remove" } });
    expect(response?.kind).toBe("saved");
    expect(api.mysqlRuntime).toHaveBeenCalledWith({ action: "save", bindingHandle: "b", profileHandle: "p", profile: input, password: { action: "remove" } });
    expect(controller.getSnapshot().profiles).toEqual([{ ...profile, profileHandle: "p2", hasPassword: false }]);
    expect(controller.getSnapshot().notice).toContain("已加密保存");
    controller.dispose();
  });
  it("shows expected domain failures as Chinese error text", async () => {
    const api = { mysqlRuntime: vi.fn().mockResolvedValue({ kind: "rejected", action: "list", code: "stale", detail: "profile expired, refresh." }) };
    const controller = new MysqlRuntimeController(api, "b");
    expect(await controller.list()).toBeNull();
    expect(controller.getSnapshot().error).toBe("profile expired, refresh.");
    expect(controller.getSnapshot().profiles).toEqual([]);
    controller.dispose();
  });
  it("removes the deleted row and surfaces the delete outcome detail", async () => {
    const api = { mysqlRuntime: vi.fn().mockResolvedValueOnce({ kind: "profiles", profiles: [profile] })
      .mockResolvedValueOnce({ kind: "deleted", planHandle: "d", profileHandle: "p", verified: true, detail: "profile deleted and verified." }) };
    const controller = new MysqlRuntimeController(api, "b");
    await controller.list();
    await controller.request({ action: "delete", bindingHandle: "b", planHandle: "d" });
    expect(controller.getSnapshot().profiles).toEqual([]);
    expect(controller.getSnapshot().notice).toContain("deleted");
    controller.dispose();
  });
});

describe("instance inspect", () => {
  it("validates the inspect request and review response, including the null locked state", () => {
    const request = { action: "inspect" as const, bindingHandle: "b", profileHandle: "p" };
    expect(isMySqlRuntimeRequest(request)).toBe(true);
    expect(isMySqlRuntimeRequest({ action: "inspect", bindingHandle: "b" })).toBe(false);
    expect(isMySqlRuntimeResponse({ kind: "review", review })).toBe(true);
    expect(matchesMySqlRuntimeResponse(request, { kind: "review", review })).toBe(true);
    expect(matchesMySqlRuntimeResponse(request, { kind: "rejected", action: "inspect", code: "stale", detail: "expired" })).toBe(true);
    expect(isMySqlRuntimeResponse({ kind: "review", review: { ...review, product: "OtherDB" } })).toBe(false);
    expect(isMySqlRuntimeResponse({ kind: "review", review: { ...review, accounts: review.accounts.map(a => ({ ...a, locked: "yes" })) } })).toBe(false);
    expect(isMySqlRuntimeResponse({ kind: "review", review: { ...review, accounts: Array(513).fill(review.accounts[0]) } })).toBe(false);
    expect(isMySqlRuntimeResponse({ kind: "review", review: { ...review, accountTotal: 1 } })).toBe(false);
  });
  it("sends the inspect request and stores the review keyed by profile handle", async () => {
    const api = { mysqlRuntime: vi.fn().mockResolvedValue({ kind: "review", review }) };
    const controller = new MysqlRuntimeController(api, "b");
    const response = await controller.inspect("p");
    expect(response?.kind).toBe("review");
    expect(api.mysqlRuntime).toHaveBeenCalledWith({ action: "inspect", bindingHandle: "b", profileHandle: "p" });
    expect(controller.reviewFor("p")).toEqual(review);
    expect(controller.getSnapshot().reviews).toEqual({ p: review });
    expect(controller.getSnapshot().reviewBusy).toBeNull();
    controller.dispose();
  });
  it("marks the profile busy while inspecting and blocks a second inspect", async () => {
    let release: ((value: unknown) => void) | null = null;
    const api = { mysqlRuntime: vi.fn().mockImplementation(() => new Promise(resolve => { release = resolve; })) };
    const controller = new MysqlRuntimeController(api, "b");
    const pending = controller.inspect("p");
    expect(controller.getSnapshot().reviewBusy).toBe("p");
    expect(controller.getSnapshot().busy).toBe(true);
    expect(await controller.inspect("p")).toBeNull();
    release!({ kind: "review", review });
    expect((await pending)?.kind).toBe("review");
    expect(controller.getSnapshot().reviewBusy).toBeNull();
    expect(controller.getSnapshot().busy).toBe(false);
    controller.dispose();
  });
  it("surfaces the inspect rejection detail and keeps no review", async () => {
    const api = { mysqlRuntime: vi.fn().mockResolvedValue({ kind: "rejected", action: "inspect", code: "stale", detail: "connection expired, refresh." }) };
    const controller = new MysqlRuntimeController(api, "b");
    expect(await controller.inspect("p")).toBeNull();
    expect(controller.getSnapshot().error).toBe("connection expired, refresh.");
    expect(controller.reviewFor("p")).toBeNull();
    expect(controller.getSnapshot().reviewBusy).toBeNull();
    controller.dispose();
  });
  it("drops reviews for profiles that disappear and clears them on save or explicit close", async () => {
    const api = { mysqlRuntime: vi.fn().mockResolvedValue({ kind: "review", review }) };
    const controller = new MysqlRuntimeController(api, "b");
    await controller.inspect("p");
    expect(controller.reviewFor("p")).toEqual(review);
    controller.clearReview("p");
    expect(controller.reviewFor("p")).toBeNull();
    await controller.inspect("p");
    api.mysqlRuntime.mockResolvedValue({ kind: "profiles", profiles: [] });
    await controller.list();
    expect(controller.getSnapshot().reviews).toEqual({});
    controller.dispose();
  });
});

describe("MysqlReviewPanel", () => {
  it("renders the summary, disclaimer, level badges, accounts, gaps and log clues without handles", () => {
    const html = renderToStaticMarkup(<MysqlReviewPanel profile={profile} review={review} onClose={noop} />);
    expect(html).toContain("MySQL 8.0.36"); expect(html).toContain("&#x27;root&#x27;@&#x27;localhost&#x27;");
    expect(html).toContain("均为需人工核对的线索"); expect(html).toContain("高风险"); expect(html).toContain("需人工核对"); expect(html).toContain("参考");
    expect(html).toContain("app@%"); expect(html).toContain("空口令"); expect(html).toContain("锁定状态未知");
    expect(html).toContain("SUPER、FILE、GRANT"); expect(html).toContain("sys_exec"); expect(html).toContain("libevil.so");
    expect(html).toContain("general_log_file"); expect(html).toContain("/var/log/mysql/general.log"); expect(html).toContain("空值");
    expect(html).toContain("无法读取：mysql.user 部分列不可读");
    expect(html).toContain("/var/log/mysql/error.log"); expect(html).toContain("65536");
    expect(html).toContain("root@192.0.2.10 × 3"); expect(html).toContain("Access denied for user &#x27;root&#x27;@&#x27;192.0.2.10&#x27;");
    expect(html).not.toContain("profileHandle"); expect(html).not.toContain("bindingHandle");
  });
  it("escapes hostile text inside findings and accounts", () => {
    const hostile: MySqlInstanceReview = { ...review, findings: [{ level: "info", code: "x", detail: '<img src=x onerror="bad">' }], accounts: [{ user: '<svg onload="x">', host: "localhost", plugin: "caching_sha2_password", emptySecret: false, superuser: true, filePriv: false, grantPriv: false, locked: false }] };
    const html = renderToStaticMarkup(<MysqlReviewPanel profile={profile} review={hostile} onClose={noop} />);
    expect(html).toContain("&lt;img"); expect(html).not.toContain("<img");
    expect(html).toContain("&lt;svg"); expect(html).not.toContain("<svg");
  });
  it("renders an empty review honestly", () => {
    const empty: MySqlInstanceReview = { ...review, accounts: [], accountTotal: 0, udfs: [], udfTotal: 0, findings: [], gaps: ["无法连接日志"], log: null, variables: {} };
    const html = renderToStaticMarkup(<MysqlReviewPanel profile={profile} review={empty} onClose={noop} />);
    expect(html).toContain("未返回线索条目"); expect(html).toContain("未取得账号列表");
    expect(html).toContain("未提供"); expect(html).toContain("无法读取：无法连接日志");
    expect(html).not.toContain("错误日志线索");
  });
});

describe("passwordRules", () => {
  it("accepts a compliant password and rejects each closed rule without echoing it", () => {
    expect(passwordRules(good, good, "app")).toEqual([]);
    for (const [password, confirm, user] of [
      ["short", "short", "app"], [good, "different-mismatch", "app"], ["aaaaaaaaaaaa", "aaaaaaaaaaaa", "app"],
      ["lowercase1!pw", "lowercase1!pw", "lowercase1"], ["Aa1!pw\u0007test9", "Aa1!pw\u0007test9", "app"],
    ] as const) {
      const rules = passwordRules(password, confirm, user);
      expect(rules.length).toBeGreaterThan(0); expect(rules.join()).not.toContain(secret);
    }
  });
});

describe("MysqlPasswordDialog static input step", () => {
  const dialog = (username = "root") => createElement(MysqlPasswordDialog, {
    api: { mysqlRuntime: vi.fn() }, bindingHandle: "b", profile: { ...profile, username }, targetLabel: "lab",
    onClose: noop, onDirty: noop, onProfile: noop, onInvalidate: noop, ask: vi.fn(async () => true),
  });
  it("renders the account fields, rules hint and connection-account checkbox without the password value", () => {
    const html = renderToStaticMarkup(dialog());
    expect(html).toContain("修改数据库账号口令"); expect(html).toContain("账号来源主机"); expect(html).toContain("检查并生成计划");
    expect(html).toContain("同时更新已保存的连接口令"); expect(html).toContain('autoComplete="new-password"');
    expect(html).toContain('value="localhost"'); expect(html).not.toContain(secret);
  });
});

describe("dialog step decisions", () => {
  const result = { verification: { state: "passed" as const, reason: null }, savedPassword: "updated" as const, restorable: true, journalRecorded: true, restoreHandle: "r", restoreUnavailable: false, profile: null };
  const held = { result, restoreUsed: false, restoreDeadline: Date.now() + 600_000 };
  it("maps unknown-state to the unconfirmed result step and anything else to input", () => {
    expect(rejectionTarget("unknown-state")).toBe("unknown");
    expect(rejectionTarget("stale")).toBe("input"); expect(rejectionTarget(null)).toBe("input");
  });
  it("builds a valid plan-password request and gates saved-password update on the connection account", () => {
    const request = planPasswordRequest("b", profile, { user: "root", host: "localhost" }, good, true);
    expect(request).toEqual({ action: "plan-password", bindingHandle: "b", profileHandle: "p", account: { user: "root", host: "localhost" }, password: good, updateSavedPassword: true });
    expect(isMySqlRuntimeRequest(request)).toBe(true);
    const other = planPasswordRequest("b", profile, { user: "app", host: "%" }, good, true);
    expect(other).toMatchObject({ updateSavedPassword: false });
  });
  it("offers restore only with a live handle inside the ten-minute window", () => {
    expect(restoreAvailable(held, 1000)).toBe(true);
    expect(restoreAvailable({ ...held, restoreUsed: true }, 1000)).toBe(false);
    expect(restoreAvailable(held, 0)).toBe(false);
    expect(restoreAvailable({ ...held, result: { ...result, restoreHandle: null } }, 1000)).toBe(false);
  });
  it("asks before closing only while a live restore remains", () => {
    const now = Date.now();
    expect(closeNeedsConfirm({ kind: "result", held }, now)).toBe(true);
    expect(closeNeedsConfirm({ kind: "result", held: { ...held, restoreUsed: true } }, now)).toBe(false);
    expect(closeNeedsConfirm({ kind: "result", held: { ...held, restoreDeadline: now - 1 } }, now)).toBe(false);
    expect(closeNeedsConfirm({ kind: "input" }, now)).toBe(false);
  });
  it("names the unverifiable path and every saved-password update in Chinese", () => {
    expect(unverifiableReasonText.path).toBe("该账号的来源限制使当前连接无法复核新口令");
    for (const value of Object.values(savedUpdateText)) expect(value).toMatch(/[一-鿿]/u);
  });
});
