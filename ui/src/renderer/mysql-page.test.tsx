import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";
import { describe, expect, it, vi } from "vitest";
import { isMySqlRuntimeRequest, type MySqlProfileSummary } from "../shared/mysql-runtime-contract";
import { MysqlPage } from "./MysqlPage";
import { MysqlRuntimeController } from "./mysql-runtime-controller";
import { closeNeedsConfirm, MysqlPasswordDialog, passwordRules, planPasswordRequest, rejectionTarget, restoreAvailable, savedUpdateText, unverifiableReasonText } from "./MysqlPasswordDialog";

const profile: MySqlProfileSummary = { profileHandle: "p", name: "audit", host: "127.0.0.1", port: 3306, username: "root", database: "", tlsMode: "verify-full", hasPassword: true, hasCa: false, unassigned: false };
const good = "Aa1!password9";
const secret = "secret-canary";
const noop = (): void => undefined;

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
