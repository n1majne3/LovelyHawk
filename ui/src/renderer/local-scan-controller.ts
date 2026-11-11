import type { EmergencyCommandPathOffer } from "../shared/emergency-command-contract";
import {
  matchesLocalScanResult,
  type LocalScanApi,
  type LocalScanChildApi,
  type LocalScanEngineDto,
  type LocalScanFetchDto,
  type LocalScanRequest,
  type LocalScanChildRequest,
  type LocalScanResult,
} from "../shared/local-scan-contract";

/** The one run answer the dialog shows: launched in its own window, or a finished command line run. */
export type LocalScanRun = Extract<LocalScanResult, { kind: "run" }>;

/** Which request is in flight; the buttons it came from stay down until it returns. */
export type LocalScanBusy = "engines" | "fetch" | "configure" | "remove" | "run" | "reveal" | "discard";

export interface LocalScanState {
  /** Configured engines; null while the first read has not come back, or after it failed. */
  engines: LocalScanEngineDto[] | null;
  /** The last engine read failed; null engines plus this is "unreadable", never "none configured". */
  enginesFailed: boolean;
  /** The fetched copy's own report; null until a fetch completes. */
  fetch: LocalScanFetchDto | null;
  /** What the last launch reported; null until a scan is started. */
  run: LocalScanRun | null;
  busy: LocalScanBusy | null;
  /** Backend refusal or request failure, verbatim: its text is written for this surface. */
  error: string | null;
  /** Small result of a secondary action (the folder opened in the file manager). */
  notice: string | null;
  selectedEngineId: string | null;
  /** The fetched copy was deleted on request; the dialog closes on it. */
  discarded: boolean;
}

const IDLE: LocalScanState = {
  engines: null,
  enginesFailed: false,
  fetch: null,
  run: null,
  busy: null,
  error: null,
  notice: null,
  selectedEngineId: null,
  discarded: false,
};

function message(error: unknown): string {
  return error instanceof Error && error.message.length > 0 ? error.message : "本机扫描没有完成，请重试。";
}

/**
 * What the dialog asks of its caller. Each transport knows which fetch
 * request shape its source takes (path offer, SFTP browser entry or a
 * container path); the dialog never builds one itself.
 */
export interface LocalScanTransport {
  engines(): Promise<LocalScanResult | null>;
  configure(name: string, kind: "gui" | "cli", args: string[]): Promise<LocalScanResult | null>;
  removeEngine(engineId: string): Promise<LocalScanResult | null>;
  fetch(scope: "file" | "directory"): Promise<LocalScanResult | null>;
  run(fetchId: string, engineId: string): Promise<LocalScanResult | null>;
  reveal(fetchId: string): Promise<LocalScanResult | null>;
  discard(fetchId: string): Promise<LocalScanResult | null>;
}

type AnyRequest = LocalScanRequest | LocalScanChildRequest;

function checked(
  api: Pick<LocalScanApi, "localScan"> | Pick<LocalScanChildApi, "localScan">,
): (request: AnyRequest) => Promise<LocalScanResult | null> {
  return async (request) => {
    const result = await api.localScan(request as never);
    // The bridge checks the pairing too; a fake in a test still has to answer
    // the action it was asked, or nothing it says is shown.
    if (!matchesLocalScanResult(request as LocalScanRequest, result)) {
      throw new Error("本机扫描结果与本次请求不一致，请重试。");
    }
    return result;
  };
}

/** Emergency-command path offer: the main window's fetch action. */
export function pathOfferScanTransport(
  api: LocalScanApi, binding: string, offer: EmergencyCommandPathOffer,
): LocalScanTransport {
  const send = checked(api);
  return {
    engines: () => send({ action: "engines" }),
    configure: (name, kind, args) => send({ action: "configure", name, kind, arguments: args }),
    removeEngine: (engineId) => send({ action: "remove-engine", engineId }),
    fetch: (scope) => send({ action: "fetch", bindingHandle: binding, pathHandle: offer.pathHandle, scope }),
    run: (fetchId, engineId) => send({ action: "run", bindingHandle: binding, fetchId, engineId }),
    reveal: (fetchId) => send({ action: "reveal", bindingHandle: binding, fetchId }),
    discard: (fetchId) => send({ action: "discard", bindingHandle: binding, fetchId }),
  };
}

/** A path inside a Docker/Podman container on the connected target. */
export function containerScanTransport(
  api: LocalScanApi, binding: string, snapshotHandle: string, containerHandle: string, path: string,
): LocalScanTransport {
  const send = checked(api);
  return {
    engines: () => send({ action: "engines" }),
    configure: (name, kind, args) => send({ action: "configure", name, kind, arguments: args }),
    removeEngine: (engineId) => send({ action: "remove-engine", engineId }),
    fetch: (scope) => send({
      action: "fetch-container", bindingHandle: binding, snapshotHandle, containerHandle, path, scope,
    }),
    run: (fetchId, engineId) => send({ action: "run", bindingHandle: binding, fetchId, engineId }),
    reveal: (fetchId) => send({ action: "reveal", bindingHandle: binding, fetchId }),
    discard: (fetchId) => send({ action: "discard", bindingHandle: binding, fetchId }),
  };
}

/** An entry the SFTP file manager listed; a null entry handle is the listed directory itself. */
export function browserScanTransport(
  api: LocalScanChildApi, browserHandle: string, entryHandle: string,
): LocalScanTransport {
  const send = checked(api);
  return {
    engines: () => send({ action: "engines" }),
    configure: (name, kind, args) => send({ action: "configure", name, kind, arguments: args }),
    removeEngine: (engineId) => send({ action: "remove-engine", engineId }),
    fetch: (scope) => send({ action: "fetch-browser", browserHandle, entryHandle, scope }),
    run: (fetchId, engineId) => send({ action: "run", fetchId, engineId }),
    reveal: (fetchId) => send({ action: "reveal", fetchId }),
    discard: (fetchId) => send({ action: "discard", fetchId }),
  };
}

/**
 * Drives the fetch-to-local-scan dialog for one offered path.
 *
 * Every request is a closed action plus handles the page was handed; the
 * window never names a local program or a local path of its own — engine
 * programs come from the host's file dialog, and a fetch's staging directory
 * comes back with the result. Anything returning after the dialog was closed
 * or superseded is dropped against a revision counter, and a fetch that
 * finishes too late is told to delete the copy nobody saw.
 */
export class LocalScanController {
  private state: LocalScanState = IDLE;
  private listeners = new Set<() => void>();
  private disposed = false;
  private revision = 0;

  constructor(private transport: LocalScanTransport) {}

  /** The dialog opened (or came back after a strict-mode remount): start over and read the engines. */
  attach = (): void => {
    this.disposed = false;
    const revision = ++this.revision;
    this.set({ ...IDLE });
    void this.loadEngines(revision);
  };

  getSnapshot = (): LocalScanState => this.state;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };

  private set(state: LocalScanState): void {
    if (this.disposed) return;
    this.state = state;
    this.listeners.forEach((fn) => fn());
  }

  private keepSelection(engines: LocalScanEngineDto[], prefer: string | null): string | null {
    if (prefer !== null && engines.some((engine) => engine.id === prefer)) return prefer;
    if (this.state.selectedEngineId !== null && engines.some((engine) => engine.id === this.state.selectedEngineId)) {
      return this.state.selectedEngineId;
    }
    return engines[0]?.id ?? null;
  }

  private async loadEngines(revision: number): Promise<void> {
    this.set({ ...this.state, busy: "engines", error: null });
    try {
      const result = await this.transport.engines();
      if (this.disposed || revision !== this.revision) return;
      if (result === null || result.kind !== "engines") throw new Error("本机扫描结果与本次请求不一致，请重试。");
      this.set({
        ...this.state, engines: result.engines, enginesFailed: false,
        busy: null, selectedEngineId: this.keepSelection(result.engines, null),
      });
    } catch (error) {
      if (revision === this.revision) {
        // An unreadable list is not an empty list; the empty text would say
        // nothing is configured, which may not be true.
        this.set({ ...this.state, engines: null, enginesFailed: true, busy: null, error: message(error) });
      }
    }
  }

  /** Re-read the engine list after a load failure. */
  reloadEngines = async (): Promise<void> => {
    if (this.disposed || this.state.busy !== null) return;
    await this.loadEngines(++this.revision);
  };

  selectEngine = (engineId: string): void => {
    if (this.disposed) return;
    this.set({ ...this.state, selectedEngineId: engineId });
  };

  /** Add an engine: opens the system program picker on the way, so cancelling it keeps the form. */
  configure = async (name: string, kind: "gui" | "cli", args: string[]): Promise<"configured" | "cancelled" | "failed"> => {
    if (this.disposed || this.state.busy !== null) return "failed";
    const revision = ++this.revision;
    this.set({ ...this.state, busy: "configure", error: null });
    try {
      const before = new Set((this.state.engines ?? []).map((engine) => engine.id));
      const result = await this.transport.configure(name, kind, args);
      if (this.disposed || revision !== this.revision) return "failed";
      if (result === null) {
        // The system dialog was cancelled: nothing was added, keep the form.
        this.set({ ...this.state, busy: null });
        return "cancelled";
      }
      if (result.kind !== "engines") throw new Error("本机扫描结果与本次请求不一致，请重试。");
      const added = result.engines.find((engine) => !before.has(engine.id))?.id ?? null;
      this.set({
        ...this.state,
        engines: result.engines,
        busy: null,
        selectedEngineId: this.keepSelection(result.engines, added),
      });
      return "configured";
    } catch (error) {
      if (revision === this.revision) this.set({ ...this.state, busy: null, error: message(error) });
      return "failed";
    }
  };

  removeEngine = async (engineId: string): Promise<void> => {
    if (this.disposed || this.state.busy !== null) return;
    const revision = ++this.revision;
    this.set({ ...this.state, busy: "remove", error: null });
    try {
      const result = await this.transport.removeEngine(engineId);
      if (this.disposed || revision !== this.revision) return;
      if (result === null || result.kind !== "engines") throw new Error("本机扫描结果与本次请求不一致，请重试。");
      this.set({ ...this.state, engines: result.engines, busy: null, selectedEngineId: this.keepSelection(result.engines, null) });
    } catch (error) {
      if (revision === this.revision) this.set({ ...this.state, busy: null, error: message(error) });
    }
  };

  /** Fetch the offered file or its directory into the local isolation area. */
  fetch = async (scope: "file" | "directory"): Promise<void> => {
    if (this.disposed || this.state.busy !== null || this.state.fetch !== null || this.state.discarded) return;
    const revision = ++this.revision;
    this.set({ ...this.state, busy: "fetch", error: null, notice: null });
    try {
      const result = await this.transport.fetch(scope);
      if (result === null || result.kind !== "fetch") throw new Error("本机扫描结果与本次请求不一致，请重试。");
      if (this.disposed || revision !== this.revision) {
        // The dialog is gone or superseded: the copy nobody will see should
        // not linger, so tell the backend to delete it and keep nothing.
        void this.transport.discard(result.fetch.fetchId).catch(() => undefined);
        return;
      }
      this.set({ ...this.state, fetch: result.fetch, busy: null, error: null });
    } catch (error) {
      if (revision === this.revision) this.set({ ...this.state, busy: null, error: message(error) });
    }
  };

  /** Launch the selected engine against the fetched copy. */
  run = async (engineId: string): Promise<void> => {
    const fetched = this.state.fetch;
    if (this.disposed || this.state.busy !== null || fetched === null || this.state.discarded) return;
    const revision = ++this.revision;
    this.set({ ...this.state, busy: "run", error: null });
    try {
      const result = await this.transport.run(fetched.fetchId, engineId);
      if (this.disposed || revision !== this.revision) return;
      if (result === null || result.kind !== "run") throw new Error("本机扫描结果与本次请求不一致，请重试。");
      this.set({ ...this.state, run: result, busy: null, error: null });
    } catch (error) {
      if (revision === this.revision) this.set({ ...this.state, busy: null, error: message(error) });
    }
  };

  /** Open the isolation folder in the file manager. */
  reveal = async (): Promise<void> => {
    const fetched = this.state.fetch;
    if (this.disposed || this.state.busy !== null || fetched === null || this.state.discarded) return;
    const revision = ++this.revision;
    this.set({ ...this.state, busy: "reveal", error: null });
    try {
      const result = await this.transport.reveal(fetched.fetchId);
      if (this.disposed || revision !== this.revision) return;
      if (result === null || result.kind !== "done") throw new Error("本机扫描结果与本次请求不一致，请重试。");
      this.set({ ...this.state, busy: null, notice: result.detail });
    } catch (error) {
      if (revision === this.revision) this.set({ ...this.state, busy: null, error: message(error) });
    }
  };

  /** Delete the fetched copy. Resolves true once it is gone and the dialog may close. */
  discard = async (): Promise<boolean> => {
    const fetched = this.state.fetch;
    if (this.disposed || this.state.busy !== null || fetched === null || this.state.discarded) return false;
    const revision = ++this.revision;
    this.set({ ...this.state, busy: "discard", error: null });
    try {
      const result = await this.transport.discard(fetched.fetchId);
      if (this.disposed || revision !== this.revision) return false;
      if (result === null || result.kind !== "done") throw new Error("本机扫描结果与本次请求不一致，请重试。");
      this.set({ ...this.state, busy: null, discarded: true });
      return true;
    } catch (error) {
      if (revision === this.revision) this.set({ ...this.state, busy: null, error: message(error) });
      return false;
    }
  };

  dispose = (): void => {
    this.disposed = true;
    this.revision++;
    this.listeners.clear();
  };
}
