import { describe, expect, it } from "vitest";

import {
  isPcapAnalysisResult,
  isPcapOfflineRequest,
  isPcapOfflineStatus,
  matchesPcapOfflineResult,
  type PcapAnalysisResult,
  type PcapOfflineStatus,
} from "./pcap-offline-contract";

function sampleResult(): PcapAnalysisResult {
  return {
    summary: {
      format: "pcap", linkTypes: [1], packetCount: 40, parsedCount: 40,
      malformedCount: 0, fragmentCount: 0,
      flowCapHit: false, streamCapHit: false, packetCapHit: false, warnings: [],
    },
    flows: [{
      id: 0, proto: "TCP", endpointA: "10.0.0.1:40000", endpointB: "10.0.0.5:80",
      packets: 12, bytes: 9000, firstMs: 0, lastMs: 1200, tcpGaps: 0, streamTruncated: false,
    }],
    http: [{
      id: 0, flowId: 0, method: "POST", uri: "/up.php", host: "10.0.0.5", status: 200,
      reqContentType: "application/octet-stream", respContentType: "text/plain",
      reqBodySize: 16, respBodySize: 64, reqObjectId: "obj-0", respObjectId: "obj-1",
      reqHeaders: ["POST /up.php HTTP/1.1"], respHeaders: ["HTTP/1.1 200 OK"], incomplete: false,
    }],
    objects: [{
      id: "obj-1", sha256: "a".repeat(64), size: 64, contentType: "text/plain",
      uri: "/up.php", kind: "response", stored: true,
    }],
    alerts: [{
      rule: "菜刀 z0/z1 参数", level: "lead", message: "请求参数出现 base64 z0/z1。",
      flowId: 0, txId: 0,
    }],
    echoes: [{ txId: 0, flowId: 0, marker: "x@y", text: "dir c:\\" }],
  };
}

function sampleStatus(result: PcapAnalysisResult | null): PcapOfflineStatus {
  return { state: "done", source: "import", bytesRead: 100, totalBytes: 100, detail: "完成", result };
}

describe("isPcapOfflineRequest", () => {
  it("accepts every action shape", () => {
    expect(isPcapOfflineRequest({ action: "import" })).toBe(true);
    expect(isPcapOfflineRequest({ action: "begin-evidence", jobHandle: "job-abc_1" })).toBe(true);
    expect(isPcapOfflineRequest({ action: "status" })).toBe(true);
    expect(isPcapOfflineRequest({ action: "cancel" })).toBe(true);
    expect(isPcapOfflineRequest({ action: "export-object", objectId: "obj-2" })).toBe(true);
    expect(isPcapOfflineRequest({ action: "export-object", objectId: "obj-2", fileName: "x.bin" })).toBe(true);
  });

  it("rejects wrong shapes, local paths, and invented fields", () => {
    expect(isPcapOfflineRequest({ action: "import", localPath: "c:/x.pcap" })).toBe(false);
    expect(isPcapOfflineRequest({ action: "begin-evidence", jobHandle: "a b" })).toBe(false);
    expect(isPcapOfflineRequest({ action: "begin-evidence", jobHandle: "ok", localPath: "/x" })).toBe(false);
    expect(isPcapOfflineRequest({ action: "status", jobHandle: "x" })).toBe(false);
    expect(isPcapOfflineRequest({ action: "export-object", objectId: "not-an-id" })).toBe(false);
    expect(isPcapOfflineRequest({ action: "export-object", objectId: "obj-1", localPath: "/x" })).toBe(false);
    expect(isPcapOfflineRequest({ action: "import-all" })).toBe(false);
    expect(isPcapOfflineRequest("import")).toBe(false);
    expect(isPcapOfflineRequest(null)).toBe(false);
  });
});

describe("isPcapOfflineStatus / isPcapAnalysisResult", () => {
  it("accepts a well-formed status with and without a result", () => {
    expect(isPcapOfflineStatus(sampleStatus(sampleResult()))).toBe(true);
    expect(isPcapOfflineStatus(sampleStatus(null))).toBe(true);
  });

  it("rejects extra, missing, or wrong-typed fields anywhere in the tree", () => {
    expect(isPcapOfflineStatus({ ...sampleStatus(null), localPath: "c:/x" })).toBe(false);
    expect(isPcapOfflineStatus({ ...sampleStatus(null), state: "hacked" })).toBe(false);
    expect(isPcapOfflineStatus({ ...sampleStatus(null), bytesRead: "100" })).toBe(false);
    expect(isPcapOfflineStatus({ ...sampleStatus(null), source: "page" })).toBe(false);

    const withExtra = sampleResult() as unknown as Record<string, unknown>;
    withExtra.localPath = "c:/x";
    expect(isPcapOfflineStatus(sampleStatus(withExtra as unknown as PcapAnalysisResult))).toBe(false);

    const missingKey = { ...sampleResult() };
    delete (missingKey as Record<string, unknown>).flows;
    expect(isPcapAnalysisResult(missingKey)).toBe(false);

    const badFlow = sampleResult();
    badFlow.flows = [{ ...badFlow.flows[0], endpointA: 5 } as never];
    expect(isPcapAnalysisResult(badFlow)).toBe(false);

    const badAlert = sampleResult();
    badAlert.alerts = [{ rule: "x", level: "verdict", message: "y", flowId: null, txId: null } as never];
    expect(isPcapAnalysisResult(badAlert)).toBe(false);

    const badObject = sampleResult();
    badObject.objects = [{ ...badObject.objects[0], id: "evil-1" } as never];
    expect(isPcapAnalysisResult(badObject)).toBe(false);
    badObject.objects = [{ ...sampleResult().objects[0], sha256: "nothex" } as never];
    expect(isPcapAnalysisResult(badObject)).toBe(false);

    const badEcho = sampleResult();
    badEcho.echoes = [{ txId: null, flowId: 0, marker: "other", text: "x" } as never];
    expect(isPcapAnalysisResult(badEcho)).toBe(false);
  });

  it("rejects over-cap lists", () => {
    const r = sampleResult();
    const firstFlow = r.flows[0];
    if (!firstFlow) throw new Error("fixture needs a flow");
    r.flows = Array.from({ length: 2001 }, (_, i) => ({ ...firstFlow, id: i }));
    expect(isPcapAnalysisResult(r)).toBe(false);
  });
});

describe("matchesPcapOfflineResult", () => {
  it("binds response kinds to the request that produced them", () => {
    expect(matchesPcapOfflineResult({ action: "import" }, { kind: "started", started: true })).toBe(true);
    expect(matchesPcapOfflineResult({ action: "import" }, { kind: "status", status: sampleStatus(null) })).toBe(false);
    expect(matchesPcapOfflineResult({ action: "status" }, { kind: "status", status: sampleStatus(sampleResult()) })).toBe(true);
    expect(matchesPcapOfflineResult({ action: "status" }, { kind: "status", status: { ...sampleStatus(null), extra: 1 } })).toBe(false);
    expect(matchesPcapOfflineResult({ action: "cancel" }, { kind: "cancelled" })).toBe(true);
    expect(matchesPcapOfflineResult({ action: "cancel" }, { kind: "cancelled", extra: 1 })).toBe(false);
    expect(matchesPcapOfflineResult({ action: "export-object", objectId: "obj-0" }, { kind: "exported", exported: true, bytes: 42 })).toBe(true);
    expect(matchesPcapOfflineResult({ action: "export-object", objectId: "obj-0" }, { kind: "exported", exported: true })).toBe(false);
  });
});
