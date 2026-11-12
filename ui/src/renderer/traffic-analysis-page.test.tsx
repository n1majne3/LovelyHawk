import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  PcapAnalysisResult,
  PcapOfflineRequest,
  PcapOfflineResult,
  PcapOfflineStatus,
} from "../shared/pcap-offline-contract";
import { alertLevelLabel, formatBytes, TrafficAnalysisPage } from "./TrafficAnalysisPage";

const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";

function sampleResult(): PcapAnalysisResult {
  return {
    summary: {
      format: "pcap", linkTypes: [1], packetCount: 40, parsedCount: 40,
      malformedCount: 2, fragmentCount: 1,
      flowCapHit: false, streamCapHit: true, packetCapHit: false,
      warnings: ["部分分片未重组"],
    },
    flows: [{
      id: 0, proto: "TCP", endpointA: "10.0.0.1:40000", endpointB: `10.0.0.5:80 ${hostile}`,
      packets: 12, bytes: 9000, firstMs: 0, lastMs: 1200, tcpGaps: 1, streamTruncated: true,
    }],
    http: [{
      id: 0, flowId: 0, method: "POST", uri: `/up.php${hostile}`, host: "10.0.0.5", status: 200,
      reqContentType: "application/octet-stream", respContentType: "text/plain",
      reqBodySize: 16, respBodySize: 64, reqObjectId: "obj-0", respObjectId: "obj-1",
      reqHeaders: [`POST /up.php ${hostile}`], respHeaders: ["HTTP/1.1 200 OK"], incomplete: true,
    }],
    objects: [{
      id: "obj-1", sha256: "a".repeat(64), size: 64, contentType: "text/plain",
      uri: "/up.php", kind: "response", stored: true,
    }],
    alerts: [{
      rule: "菜刀 z0/z1 参数", level: "lead", message: `请求参数含 z0/z1。${hostile}`,
      flowId: 0, txId: 0,
    }],
    echoes: [{ txId: 0, flowId: 0, marker: "x@y", text: `dir c:\\ ${hostile}` }],
  };
}

function statusWith(result: PcapAnalysisResult | null, state = "done"): PcapOfflineStatus {
  return { state: state as PcapOfflineStatus["state"], source: "import", bytesRead: 100, totalBytes: 100, detail: "", result };
}

function apiReturning(status: PcapOfflineStatus) {
  const calls: PcapOfflineRequest[] = [];
  return {
    calls,
    api: {
      pcapOffline: vi.fn(async (request: PcapOfflineRequest): Promise<PcapOfflineResult | null> => {
        calls.push(request);
        if (request.action === "status") return { kind: "status", status };
        return { kind: "started", started: true };
      }),
    },
  };
}

describe("TrafficAnalysisPage", () => {
  it("renders the empty state with the import entry", () => {
    const { api } = apiReturning(statusWith(null, "idle"));
    const html = renderToStaticMarkup(<TrafficAnalysisPage api={api} />);
    expect(html).toContain("导入抓包文件");
    expect(html).toContain("pcap-empty");
  });

  it("renders all six tabs with untrusted content escaped", () => {
    const html = renderToStaticMarkup(
      <TrafficAnalysisPage api={apiReturning(statusWith(sampleResult())).api} initialStatus={statusWith(sampleResult())} initialTab="flows" />);
    for (const tab of ["概要", "会话", "HTTP", "对象", "告警", "菜刀回显"]) {
      expect(html).toContain(tab);
    }
    // Hostile strings from the capture are escaped, never live markup.
    expect(html).not.toContain("<script>steal()");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;script&gt;");
  });

  it("shows truncation flags instead of an empty/no-risk state", () => {
    const html = renderToStaticMarkup(
      <TrafficAnalysisPage api={apiReturning(statusWith(sampleResult())).api} initialStatus={statusWith(sampleResult())} />);
    expect(html).toContain("pcap-truncated");
    expect(html).toContain("结果不完整");
    expect(html).toContain("部分分片未重组");
  });

  it("shows alert level labels as leads, never verdicts", () => {
    expect(alertLevelLabel("lead")).toBe("线索");
    expect(alertLevelLabel("strong")).toBe("强线索");
    expect(alertLevelLabel("weak")).toBe("弱线索");
    const html = renderToStaticMarkup(
      <TrafficAnalysisPage api={apiReturning(statusWith(sampleResult())).api} initialStatus={statusWith(sampleResult())} initialTab="alerts" />);
    expect(html).toContain("线索");
    expect(html).toContain("不是定论");
  });

  it("formats byte counts", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.0 KiB");
    expect(formatBytes(3 * 1024 * 1024)).toBe("3.0 MiB");
  });
});
