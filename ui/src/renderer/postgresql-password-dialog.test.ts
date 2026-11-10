import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";
import { describe, expect, it, vi } from "vitest";
import { closeNeedsConfirm, passwordRules, PostgresqlPasswordDialog, rejectionTarget, restoreAvailable } from "./PostgresqlPasswordDialog";
import type { PostgresqlPasswordRole } from "../shared/postgresql-runtime-contract";

const good = "Aa1!中password9";
const secret = "secret-canary";
const profile = { profileHandle: "p", name: "audit", host: "127.0.0.1", port: 5432, username: "audit", database: "postgres", tlsMode: "verify-full" as const, hasPassword: true, hasCa: false, unassigned: false };
const result = { verification: { state: "passed" as const, reason: null }, savedPassword: "updated" as const, restorable: true, journalRecorded: true, restoreHandle: "r", restoreUnavailable: false, profile: null };
const held = { result, restoreUsed: false, restoreDeadline: Date.now() + 600_000 };
const noop = (): void => undefined;
const dialog = (roleName = "audit", role: PostgresqlPasswordRole = { kind: "current" }) => createElement(PostgresqlPasswordDialog, {
  api: { postgresqlRuntime: vi.fn() }, bindingHandle: "b", profile, role, roleName, targetLabel: "lab",
  onClose: noop, onDirty: noop, onProfile: noop, onInvalidate: noop, ask: vi.fn(async () => true),
});
describe("passwordRules", () => {
  it("accepts a compliant password and rejects each closed rule", () => {
    expect(passwordRules(good, good, "app")).toEqual([]);
    for (const [password, confirm, role] of [
      ["short", "short", "app"], [good, "different-mismatch", "app"], ["aaaaaaaaaaaa", "aaaaaaaaaaaa", "app"],
      ["lowercase1!pw", "lowercase1!pw", "lowercase1"], ["Aa1!pw\u0007test9", "Aa1!pw\u0007test9", "app"],
    ] as const) {
      const rules = passwordRules(password, confirm, role);
      expect(rules.length).toBeGreaterThan(0); expect(rules.join()).not.toContain(secret);
    }
  });
});
describe("PostgresqlPasswordDialog static input step", () => {
  it("renders the role, rules hint and connection-account checkbox without the password value", () => {
    const html = renderToStaticMarkup(dialog());
    expect(html).toContain("修改数据库账号口令"); expect(html).toContain("检查并生成计划"); expect(html).toContain("同时更新已保存的连接口令");
    expect(html).toContain('autoComplete="new-password"'); expect(html).not.toContain(secret);
    const other = renderToStaticMarkup(dialog("other-role", { kind: "oid", oid: 16384 }));
    expect(other).not.toContain("同时更新已保存的连接口令");
  });
});
describe("dialog step decisions", () => {
  it("maps unknown-state to the unconfirmed result step and anything else to input", () => {
    expect(rejectionTarget("unknown-state")).toBe("unknown");
    expect(rejectionTarget("stale")).toBe("input"); expect(rejectionTarget(null)).toBe("input");
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
});
