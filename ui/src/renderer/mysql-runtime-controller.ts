import { isMySqlRuntimeRequest, matchesMySqlRuntimeResponse, type MySqlInstanceReview, type MySqlProfileSummary, type MySqlRuntimeApi, type MySqlRuntimeRequest, type MySqlRuntimeResponse } from "../shared/mysql-runtime-contract";

export interface MySqlState {
  profiles: MySqlProfileSummary[]; busy: boolean; error: string | null; notice: string | null;
  reviews: Record<string, MySqlInstanceReview>; reviewBusy: string | null;
}
export class MysqlRuntimeController {
  private state: MySqlState = { profiles: [], busy: false, error: null, notice: null, reviews: {}, reviewBusy: null };
  private listeners = new Set<() => void>();
  private pending: Promise<unknown> | null = null;
  private disposed = false;
  constructor(private api: MySqlRuntimeApi, readonly binding: string) {}
  getSnapshot = (): MySqlState => this.state;
  subscribe = (fn: () => void): (() => void) => { this.listeners.add(fn); return () => { this.listeners.delete(fn); }; };
  private set(next: Partial<MySqlState>): void { if (!this.disposed) { this.state = { ...this.state, ...next }; this.listeners.forEach(fn => fn()); } }
  private withoutReview(profiles: MySqlProfileSummary[]): Record<string, MySqlInstanceReview> {
    const handles = new Set(profiles.map(profile => profile.profileHandle));
    return Object.fromEntries(Object.entries(this.state.reviews).filter(([handle]) => handles.has(handle)));
  }
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
        case "profiles": this.set({ profiles: response.profiles, reviews: this.withoutReview(response.profiles) }); break;
        case "saved": {
          const reviews = { ...this.state.reviews };
          delete reviews[response.profile.profileHandle];
          this.set({ profiles: [...this.state.profiles.filter(profile => request.action !== "save" || profile.profileHandle !== request.profileHandle), response.profile], reviews, notice: "连接已加密保存并关联当前 SSH 主机。" });
          break;
        }
        case "deleted": {
          const reviews = { ...this.state.reviews };
          delete reviews[response.profileHandle];
          this.set({ profiles: this.state.profiles.filter(profile => profile.profileHandle !== response.profileHandle), reviews, notice: response.detail });
          break;
        }
        case "review": if (request.action === "inspect") this.set({ reviews: { ...this.state.reviews, [request.profileHandle]: response.review } }); break;
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
  inspect = async (profileHandle: string): Promise<MySqlRuntimeResponse | null> => {
    if (this.state.reviewBusy !== null) return null;
    this.set({ reviewBusy: profileHandle });
    try { return await this.request({ action: "inspect", bindingHandle: this.binding, profileHandle }); }
    finally { if (!this.disposed) this.set({ reviewBusy: null }); }
  };
  reviewFor = (profileHandle: string): MySqlInstanceReview | null => this.state.reviews[profileHandle] ?? null;
  clearReview = (profileHandle: string): void => {
    if (!(profileHandle in this.state.reviews)) return;
    const reviews = { ...this.state.reviews };
    delete reviews[profileHandle];
    this.set({ reviews });
  };
  settle = async (): Promise<void> => { await this.pending?.catch(() => undefined); };
  dispose = (): void => { this.disposed = true; this.listeners.clear(); };
}
