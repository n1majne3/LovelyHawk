import { isMySqlRuntimeRequest, matchesMySqlRuntimeResponse, type MySqlProfileSummary, type MySqlRuntimeApi, type MySqlRuntimeRequest, type MySqlRuntimeResponse } from "../shared/mysql-runtime-contract";

export interface MySqlState {
  profiles: MySqlProfileSummary[]; busy: boolean; error: string | null; notice: string | null;
}
export class MysqlRuntimeController {
  private state: MySqlState = { profiles: [], busy: false, error: null, notice: null };
  private listeners = new Set<() => void>();
  private pending: Promise<unknown> | null = null;
  private disposed = false;
  constructor(private api: MySqlRuntimeApi, readonly binding: string) {}
  getSnapshot = (): MySqlState => this.state;
  subscribe = (fn: () => void): (() => void) => { this.listeners.add(fn); return () => { this.listeners.delete(fn); }; };
  private set(next: Partial<MySqlState>): void { if (!this.disposed) { this.state = { ...this.state, ...next }; this.listeners.forEach(fn => fn()); } }
  private async exchange(request: MySqlRuntimeRequest): Promise<MySqlRuntimeResponse> {
    if (!isMySqlRuntimeRequest(request)) throw new Error("请求内容无效，请检查输入长度、地址、端口和证书。");
    const response = await this.api.mysqlRuntime(request);
    if (!matchesMySqlRuntimeResponse(request, response)) throw new Error("返回的数据库结果无法核实，请刷新后重试。");
    return response;
  }
  request = async (request: MySqlRuntimeRequest): Promise<MySqlRuntimeResponse | null> => {
    if (this.disposed || this.pending || request.bindingHandle !== this.binding) return null;
    this.set({ busy: true, error: null });
    const pending = this.exchange(request); this.pending = pending;
    try {
      const response = await pending;
      if (this.disposed) return null;
      if (response.kind === "rejected") throw new Error(response.detail);
      switch (response.kind) {
        case "profiles": this.set({ profiles: response.profiles }); break;
        case "saved": this.set({ profiles: [...this.state.profiles.filter(profile => request.action !== "save" || profile.profileHandle !== request.profileHandle), response.profile], notice: "连接已加密保存并关联当前 SSH 主机。" }); break;
        case "deleted": this.set({ profiles: this.state.profiles.filter(profile => profile.profileHandle !== response.profileHandle), notice: response.detail }); break;
        default: break;
      }
      return response;
    } catch (error) {
      // Only the bounded main/core error channel supplies these messages; remote SQL errors are never echoed.
      const message = error instanceof Error && error.message.length <= 2048 ? error.message : "无法完成数据库操作，请刷新连接后重试。";
      this.set({ error: message });
      return null;
    } finally { if (this.pending === pending) this.pending = null; this.set({ busy: false }); }
  };
  list = (): Promise<MySqlRuntimeResponse | null> => this.request({ action: "list", bindingHandle: this.binding });
  settle = async (): Promise<void> => { await this.pending?.catch(() => undefined); };
  dispose = (): void => { this.disposed = true; this.listeners.clear(); };
}
