import { describe, expect, it } from "vitest";
import { isPortForward, isPortForwardList, isPortForwardRequest } from "./port-forward-contract";

const forward = {
  forwardHandle: "h-1",
  localAddress: "127.0.0.1:15432",
  destination: "127.0.0.1:8080",
  connections: 0,
  bytesIn: "0",
  bytesOut: "0",
  lastError: null,
};

describe("port-forward contract", () => {
  it("accepts the three request shapes", () => {
    expect(isPortForwardRequest({ action: "list", bindingHandle: "b" })).toBe(true);
    expect(isPortForwardRequest({
      action: "start", bindingHandle: "b", localPort: 0,
      destinationHost: "127.0.0.1", destinationPort: 8080,
    })).toBe(true);
    expect(isPortForwardRequest({ action: "stop", bindingHandle: "b", forwardHandle: "f" })).toBe(true);
  });

  it("rejects malformed requests", () => {
    expect(isPortForwardRequest(null)).toBe(false);
    expect(isPortForwardRequest({ action: "poke", bindingHandle: "b" })).toBe(false);
    expect(isPortForwardRequest({ action: "list" })).toBe(false);
    expect(isPortForwardRequest({ action: "list", bindingHandle: "b", extra: 1 })).toBe(false);
    expect(isPortForwardRequest({
      action: "start", bindingHandle: "b", localPort: 80,
      destinationHost: "127.0.0.1", destinationPort: 8080,
    })).toBe(false);
    expect(isPortForwardRequest({
      action: "start", bindingHandle: "b", localPort: 8080,
      destinationHost: "127.0.0.1", destinationPort: 0,
    })).toBe(false);
    expect(isPortForwardRequest({
      action: "start", bindingHandle: "b", localPort: 8080,
      destinationHost: "a".repeat(80) + "坏".repeat(80), destinationPort: 8080,
    })).toBe(false);
    expect(isPortForwardRequest({
      action: "start", bindingHandle: "b", localPort: "8080",
      destinationHost: "127.0.0.1", destinationPort: 8080,
    })).toBe(false);
    expect(isPortForwardRequest({ action: "stop", bindingHandle: "b" })).toBe(false);
    expect(isPortForwardRequest({ action: "stop", bindingHandle: "b", forwardHandle: "" })).toBe(false);
  });

  it("accepts a forward DTO and a bounded list", () => {
    expect(isPortForward(forward)).toBe(true);
    expect(isPortForward({ ...forward, lastError: "目标拒绝了这次通道" })).toBe(true);
    expect(isPortForwardList([forward])).toBe(true);
    expect(isPortForwardList([])).toBe(true);
  });

  it("rejects malformed DTOs", () => {
    expect(isPortForward(null)).toBe(false);
    expect(isPortForward({ ...forward, extra: 1 })).toBe(false);
    expect(isPortForward({ ...forward, bytesIn: 12 })).toBe(false);
    expect(isPortForward({ ...forward, bytesIn: "-1" })).toBe(false);
    expect(isPortForward({ ...forward, connections: 33 })).toBe(false);
    expect(isPortForward({ ...forward, connections: 1.5 })).toBe(false);
    expect(isPortForward({ ...forward, localAddress: "0.0.0.0\u0000:80" })).toBe(false);
    expect(isPortForward({ ...forward, lastError: "x".repeat(513) })).toBe(false);
    expect(isPortForwardList("no")).toBe(false);
    expect(isPortForwardList([forward, { ...forward, bytesOut: [] }])).toBe(false);
    // Cap is eight forwards per binding.
    expect(isPortForwardList(Array.from({ length: 9 }, () => forward))).toBe(false);
  });
});
