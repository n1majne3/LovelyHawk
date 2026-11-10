import { describe, expect, it } from "vitest";

import type { BaselineCatalogItem, BaselineScan } from "../shared/baseline-read-contract";
import {
  baselineCategoryLabel,
  baselineComplianceLabel,
  baselineHistoryStateLabel,
  baselineObservedLabel,
  baselineRecommendationLabel,
  baselineRiskLabel,
  baselineScope,
  baselineNeedsReview,
  baselineCandidateScope,
  baselineValueSummary,
  groupBaselineChecks,
  baselineValueKindLabel,
  filterBaselineItems,
  formatBaselineTime,
} from "./baseline-read-helpers";

const hostile = "</div><script>plain()</script>";
const items: BaselineCatalogItem[] = [{
  itemHandle: "item-ssh",
  category: "ssh",
  component: "ssh",
  risk: "critical",
  valueKind: { kind: "choice", options: ["yes", "no"] },
  title: "关闭密码认证",
  description: hostile,
  recommendation: "no",
  writable: true,
}, {
  itemHandle: "item-kernel",
  category: "kernel",
  component: "system",
  risk: "high",
  valueKind: { kind: "integer", minimum: 0, maximum: 2 },
  title: "启用 ASLR",
  description: "内核地址随机化",
  recommendation: "2",
  writable: true,
}];

const scan: BaselineScan = {
  scanHandle: "scan-a",
  capturedAt: "2026-08-24T01:02:03Z",
  expiresInSeconds: 300,
  statuses: [{
    itemHandle: "item-ssh",
    observedKind: "value",
    observed: hostile,
    compliant: false,
    redacted: false,
    textTruncated: false,
    fix: { file: "/etc/ssh/sshd_config", lines: ["PasswordAuthentication no"], reload: "systemctl reload sshd", manualReason: null },
  }],
  displayed: 1,
  compliantCount: 0,
  nonCompliantCount: 1,
  redactedFieldCount: 0,
  truncated: false,
};

describe("baseline read helpers", () => {
  it("describes a Redis wildcard as a candidate finding that needs instance verification", () => {
    const item = { ...items[0]!, component: "redis" as const };
    const status = { ...scan.statuses[0]!, observed: "0.0.0.0" };
    expect(baselineValueSummary(item, status)).toContain("候选配置中发现 0.0.0.0");
    expect(baselineComplianceLabel(status, "redis")).toBe("风险线索");
    expect(baselineCandidateScope("redis")).toContain("ACL 和运行时设置");
    expect(baselineCandidateScope("postgresql")).toContain("postgresql.auto.conf");
    expect(baselineCandidateScope("postgresql")).toContain("候选值不能证明运行状态");
    expect(baselineCandidateScope("mysql")).toBeNull();
  });
  it("separates unresolved configuration from failures and absent software", () => {
    const pending = { ...scan.statuses[0]!, observedKind: "unverified" as const,
      observed: "无法判断（尚未核实配置）" };
    const unresolved = { ...scan, statuses: [pending] };
    expect(baselineNeedsReview(pending)).toBe(true);
    expect(baselineComplianceLabel(pending)).toBe("待复核");
    expect(filterBaselineItems(items, unresolved, "", "all", "unverified")).toHaveLength(1);
    expect(filterBaselineItems(items, unresolved, "", "all", "non-compliant")).toHaveLength(0);
    expect(groupBaselineChecks(filterBaselineItems(items, unresolved, "", "all", "all"))
      .find((group) => group.component === "ssh"))
      .toMatchObject({ failing: 0, review: 1 });
    const absent = { ...scan, statuses: [{ ...pending, observedKind: "not-installed" as const }] };
    expect(filterBaselineItems(items, absent, "", "all", "non-compliant")).toHaveLength(0);
  });
  it("filters by category, compliance and hostile search text without interpreting it", () => {
    expect(filterBaselineItems(items, scan, "script", "all", "all").map(({ item }) => item.itemHandle))
      .toEqual(["item-ssh"]);
    expect(filterBaselineItems(items, scan, "", "ssh", "non-compliant").length).toBe(1);
    expect(filterBaselineItems(items, scan, "", "kernel", "unscanned").length).toBe(1);
    expect(filterBaselineItems(items, scan, "", "kernel", "compliant").length).toBe(0);
  });

  it("uses only the opaque binding handle as lifecycle scope", () => {
    expect(baselineScope("binding-a")).toBe("binding-a");
    expect(baselineScope("binding-a")).not.toBe(baselineScope("binding-b"));
  });

  it("provides only closed display labels and value descriptions", () => {
    expect(baselineCategoryLabel("file-permissions")).toBe("文件权限");
    expect(baselineRiskLabel("critical")).toBe("严重");
    expect(baselineHistoryStateLabel("restored")).toBe("已撤销");
    // History times carry nanoseconds; they read as a local time, and an
    // unreadable one is shown as it came rather than invented.
    const shown = formatBaselineTime("2026-10-12T00:02:35.262966200+00:00");
    expect(shown).toMatch(/2026/u);
    expect(shown).not.toContain("T00:02");
    expect(formatBaselineTime("not a time")).toBe("not a time");
    expect(baselineComplianceLabel(null)).toBe("尚未扫描");
    expect(baselineComplianceLabel(scan.statuses[0]!)).toBe("不符合");
    expect(baselineValueKindLabel(items[0]!.valueKind)).toBe("选项：yes / no");
    expect(baselineValueKindLabel(items[1]!.valueKind)).toBe("整数范围：0–2");
  });

  it("translates the read-only checks' inert tokens without touching real values", () => {
    const tokenItem = (component: string, recommendation: string): BaselineCatalogItem => ({
      ...items[0]!,
      component: component as BaselineCatalogItem["component"],
      recommendation,
    });
    expect(baselineObservedLabel(tokenItem("ssh", "none"), "none")).toBe("未发现弱算法");
    expect(baselineObservedLabel(tokenItem("ssh", "enabled"), "absent")).toBe("未配置");
    expect(baselineObservedLabel(tokenItem("ssh", "restricted"), "unrestricted")).toBe("未限制");
    expect(baselineObservedLabel(tokenItem("system", "within-900"), "within-900")).toBe("不超过 900 秒");
    expect(baselineObservedLabel(tokenItem("system", "within-900"), "1200")).toBe("1200 秒");
    expect(baselineObservedLabel(tokenItem("system", "ge-5"), "ge-5")).toBe("至少 5 次");
    expect(baselineObservedLabel(tokenItem("system", "ge-5"), "3")).toBe("3 次");
    expect(baselineObservedLabel(tokenItem("system", "required"), "required")).toBe("已要求 wheel 组");
    expect(baselineObservedLabel(tokenItem("system", "none"), "none")).toBe("无");
    // Real values and unknown checks pass through untouched.
    expect(baselineObservedLabel(tokenItem("system", "none"), "admin,svc(+2)")).toBe("admin,svc(+2)");
    expect(baselineObservedLabel(items[0]!, "enabled")).toBe("enabled");
    expect(baselineRecommendationLabel(tokenItem("system", "within-900"))).toBe("不超过 900 秒");
  });
});
