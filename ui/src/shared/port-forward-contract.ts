// Local port forwarding over SSH. The backend owns every listener; the page
// sees only handles, addresses, counters and the last error.

/** One running or just-stopped forward. */
export interface PortForward {
  forwardHandle: string;
  /** `127.0.0.1:<port>` — reachable by any local process on this workstation. */
  localAddress: string;
  /** `<addr>:<port>` on the target. */
  destination: string;
  connections: number;
  bytesIn: string;
  bytesOut: string;
  lastError: string | null;
}

/** The methods this surface needs; the main API widens it. */
export interface PortForwardApi {
  portForward(request: PortForwardRequest): Promise<PortForward | PortForward[] | null>;
}

export type PortForwardRequest =
  | { action: "list"; bindingHandle: string }
  | {
      action: "start";
      bindingHandle: string;
      localPort: number;
      destinationHost: string;
      destinationPort: number;
    }
  | { action: "stop"; bindingHandle: string; forwardHandle: string };

const encoder = new TextEncoder();

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const present = Object.keys(value);
  return present.length === keys.length && keys.every((key) => present.includes(key));
}

function text(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === "string" &&
    encoder.encode(value).length <= maximumBytes &&
    !value.split("").some((char) => char.charCodeAt(0) < 0x20 && char !== " ")
  );
}

function u64String(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^\d{1,20}$/u.test(value) &&
    BigInt(value) <= 18_446_744_073_709_551_615n
  );
}

function handle(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 128;
}

export function isPortForwardRequest(value: unknown): value is PortForwardRequest {
  if (!record(value)) return false;
  if (value.action === "list") {
    return exact(value, ["action", "bindingHandle"]) && handle(value.bindingHandle);
  }
  if (value.action === "start") {
    return (
      exact(value, ["action", "bindingHandle", "localPort", "destinationHost", "destinationPort"]) &&
      handle(value.bindingHandle) &&
      typeof value.localPort === "number" && Number.isInteger(value.localPort) &&
      value.localPort >= 0 && value.localPort <= 65_535 &&
      (value.localPort === 0 || value.localPort >= 1024) &&
      text(value.destinationHost, 64) &&
      typeof value.destinationPort === "number" && Number.isInteger(value.destinationPort) &&
      value.destinationPort >= 1 && value.destinationPort <= 65_535
    );
  }
  if (value.action === "stop") {
    return (
      exact(value, ["action", "bindingHandle", "forwardHandle"]) &&
      handle(value.bindingHandle) && handle(value.forwardHandle)
    );
  }
  return false;
}

export function isPortForward(value: unknown): value is PortForward {
  return record(value) && exact(value, [
    "forwardHandle", "localAddress", "destination", "connections",
    "bytesIn", "bytesOut", "lastError",
  ]) && handle(value.forwardHandle) &&
    text(value.localAddress, 64) && text(value.destination, 128) &&
    typeof value.connections === "number" && Number.isInteger(value.connections) &&
    value.connections >= 0 && value.connections <= 32 &&
    u64String(value.bytesIn) && u64String(value.bytesOut) &&
    (value.lastError === null || text(value.lastError, 512));
}

export function isPortForwardList(value: unknown): value is PortForward[] {
  return Array.isArray(value) && value.length <= 8 && value.every(isPortForward);
}
