import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import {
  isSystemInfoFirewallAddress,
  isSystemInfoFirewallPlan,
  isSystemInfoFirewallRestorePlan,
  isSystemInfoFirewallResult,
  type SystemInfoApi,
} from "../shared/system-info-contract";
import { FirewallBlockDialog, firewallDialogBusy } from "./FirewallBlockDialog";
import { firewallBlockAddress } from "./system-info-helpers";
import { rowActionFailureText } from "./system-info-row-actions";

const row = (cells: string[]) => ({ id: "r1", cells, risk: "normal" as const, detail: false });
const plan = {
  planHandle: "0b8c6f3e-1111-4222-8333-944444444444", backend: "iptables", address: "203.0.113.7", direction: "both",
  commands: ["iptables -I INPUT 1 -s 203.0.113.7 -m comment --comment lovelyhawk-block-1a2b3c4d -j DROP"],
  warnings: ["重启、防火墙重载或服务重启后失效；尚不写入持久配置。"], expiresInMs: 120000,
};

describe("firewall block address and contract", () => {
  it("accepts single host addresses only", () => {
    for (const ok of ["203.0.113.7", "10.0.0.1", "2001:db8::7", "::ffff:1.2.3.4"]) expect(isSystemInfoFirewallAddress(ok)).toBe(true);
    for (const bad of ["", "1.2.3", "300.1.1.1", "10.0.0.0/8", "evil;rm", "a".repeat(46), "1.2.3.4 "]) expect(isSystemInfoFirewallAddress(bad)).toBe(false);
  });

  it("extracts the remote host from connection rows and skips wildcards and loopback", () => {
    expect(firewallBlockAddress("network", row(["tcp", "10.0.0.5:22", "203.0.113.7:51000", "ESTAB", "1", "sshd"]))).toBe("203.0.113.7");
    expect(firewallBlockAddress("network", row(["tcp", "[::]:22", "[2001:db8::7]:443", "ESTAB", "1", "x"]))).toBe("2001:db8::7");
    expect(firewallBlockAddress("network", row(["tcp", "0.0.0.0:22", "0.0.0.0:*", "LISTEN", "1", "sshd"]))).toBeNull();
    expect(firewallBlockAddress("network", row(["tcp", "127.0.0.1:5432", "127.0.0.1:40000", "ESTAB", "1", "pg"]))).toBeNull();
    expect(firewallBlockAddress("established", row(["10.0.0.5:22", "198.51.100.9", "4444", "1", "bash", "root"]))).toBe("198.51.100.9");
    expect(firewallBlockAddress("processes", row(["x"]))).toBeNull();
  });

  it("validates plan, result and restore plan shapes exactly", () => {
    expect(isSystemInfoFirewallPlan(plan)).toBe(true);
    expect(isSystemInfoFirewallPlan({ ...plan, extra: 1 })).toBe(false);
    expect(isSystemInfoFirewallPlan({ ...plan, backend: "ufw" })).toBe(false);
    expect(isSystemInfoFirewallPlan({ ...plan, commands: [] })).toBe(false);
    expect(isSystemInfoFirewallResult({ verified: true, detail: "ok", restoreHandle: null })).toBe(true);
    expect(isSystemInfoFirewallResult({ verified: true, detail: "ok", restoreHandle: "lovelyhawk-block|tag" })).toBe(false);
    expect(isSystemInfoFirewallRestorePlan({ planHandle: plan.planHandle, backend: "nftables", address: "2001:db8::7", direction: "inbound", expiresInMs: 1 })).toBe(true);
  });

  it("explains each refusal in plain Chinese", () => {
    for (const code of ["system-info-firewall-privilege", "system-info-firewall-ufw", "system-info-firewall-backend", "system-info-firewall-session"]) {
      const text = rowActionFailureText(new Error(`refused (${code})`));
      expect(text).toMatch(/[\u4e00-\u9fff]/u);
      expect(text).not.toContain("具体原因见应用日志");
    }
  });
});

describe("firewall block dialog", () => {
  const api = {
    planSystemInfoFirewallBlock: vi.fn(), executeSystemInfoFirewallBlock: vi.fn(),
    planSystemInfoFirewallRestore: vi.fn(), executeSystemInfoFirewallRestore: vi.fn(),
  } as unknown as SystemInfoApi;

  it("starts at the input step with the prefilled address and runtime-only notice", () => {
    const markup = renderToStaticMarkup(
      <FirewallBlockDialog api={api} bindingHandle="b" initialAddress="203.0.113.7" initialDirection="both" onChanged={() => {}} onClose={() => {}} />,
    );
    expect(markup).toContain('value="203.0.113.7"');
    expect(markup).toContain("只加运行时规则");
    expect(markup).toContain("检查并生成计划");
    expect(markup).toMatch(/value="both"[^>]*checked|checked[^>]*value="both"/u);
  });

  it("treats planning and changes in flight as not closable", () => {
    expect(firewallDialogBusy("planning")).toBe(true);
    expect(firewallDialogBusy("executing")).toBe(true);
    expect(firewallDialogBusy("restoring")).toBe(true);
    expect(firewallDialogBusy("confirm")).toBe(false);
    expect(firewallDialogBusy("result")).toBe(false);
  });
});
