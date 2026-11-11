export type MySqlTlsMode = "verify-full" | "ssh-loopback";
export interface MySqlProfileInput {
  name: string; host: string; port: number; username: string; database: string;
  tlsMode: MySqlTlsMode; caPem: string | null;
}
export interface MySqlAccountInput { user: string; host: string; }
export type MySqlPasswordChange = { action: "keep" | "remove" } | { action: "replace"; value: string };
export type MySqlRuntimeRequest =
  | { action: "list"; bindingHandle: string }
  | { action: "save"; bindingHandle: string; profileHandle: string | null; profile: MySqlProfileInput; password: MySqlPasswordChange }
  | { action: "plan-delete"; bindingHandle: string; profileHandle: string }
  | { action: "delete"; bindingHandle: string; planHandle: string }
  | { action: "plan-password"; bindingHandle: string; profileHandle: string; account: MySqlAccountInput; password: string; updateSavedPassword: boolean }
  | { action: "execute-password"; bindingHandle: string; planHandle: string }
  | { action: "plan-password-restore"; bindingHandle: string; restoreHandle: string; profileHandle: string }
  | { action: "execute-password-restore"; bindingHandle: string; planHandle: string }
  | { action: "inspect"; bindingHandle: string; profileHandle: string };
export interface MySqlPasswordPlanView {
  account: string; plugin: string; product: string; isConnectionAccount: boolean;
  restorable: boolean; updateSavedPassword: boolean; warnings: string[];
}
export interface MySqlPasswordRestorePlanView { account: string; savedPasswordWasUpdated: boolean; }
export type MySqlPasswordVerification =
  | { state: "passed" | "rejected"; reason: null }
  | { state: "unverifiable"; reason: "path" };
export type SavedPasswordUpdate = "not-requested" | "updated" | "profile-changed" | "skipped-verification-not-passed" | "failed";
export interface MySqlPasswordResult {
  verification: MySqlPasswordVerification; savedPassword: SavedPasswordUpdate; restorable: boolean;
  journalRecorded: boolean; restoreHandle: string | null; restoreUnavailable: boolean; profile: MySqlProfileSummary | null;
}
export interface MySqlPasswordRestoreResult {
  verified: boolean; savedPasswordRestored: boolean;
  journalRecorded: boolean; profile: MySqlProfileSummary | null;
}
export interface MySqlProfileSummary {
  profileHandle: string; name: string; host: string; port: number; username: string; database: string;
  tlsMode: MySqlTlsMode; hasPassword: boolean; hasCa: boolean; unassigned: boolean;
}
export interface MySqlReviewAccount {
  user: string; host: string; plugin: string;
  emptySecret: boolean; superuser: boolean; filePriv: boolean; grantPriv: boolean; locked: boolean | null;
}
export interface MySqlReviewUdf { name: string; library: string; }
export type MySqlReviewLevel = "info" | "review" | "high";
export interface MySqlReviewFinding { level: MySqlReviewLevel; code: string; detail: string; }
export interface MySqlReviewDenied { user: string; host: string; count: number; }
export interface MySqlReviewHit { kind: string; excerpt: string; }
export interface MySqlReviewLog { path: string; tailBytes: number; denied: MySqlReviewDenied[]; hits: MySqlReviewHit[]; }
export interface MySqlInstanceReview {
  product: "MySQL" | "MariaDB"; serverVersion: string; connecting: string;
  accounts: MySqlReviewAccount[]; accountTotal: number;
  udfs: MySqlReviewUdf[]; udfTotal: number;
  variables: Record<string, string>;
  findings: MySqlReviewFinding[]; gaps: string[]; log: MySqlReviewLog | null;
}
export type MySqlRuntimeResponse =
  | { kind: "rejected"; action: MySqlRuntimeRequest["action"]; code: "invalid-params" | "invalid" | "stale" | "busy" | "capacity" | "store" | "unknown-state" | "rejected"; detail: string }
  | { kind: "profiles"; profiles: MySqlProfileSummary[] }
  | { kind: "saved"; profile: MySqlProfileSummary }
  | { kind: "delete-plan"; planHandle: string; profile: MySqlProfileSummary; expiresInMs: number }
  | { kind: "deleted"; planHandle: string; profileHandle: string; verified: boolean; detail: string }
  | { kind: "password-plan"; planHandle: string; expiresInMs: number; plan: MySqlPasswordPlanView }
  | { kind: "password-result"; result: MySqlPasswordResult }
  | { kind: "password-restore-plan"; planHandle: string; expiresInMs: number; plan: MySqlPasswordRestorePlanView }
  | { kind: "password-restore-result"; result: MySqlPasswordRestoreResult }
  | { kind: "review"; review: MySqlInstanceReview };
export interface MySqlRuntimeApi {
  mysqlRuntime(request: MySqlRuntimeRequest): Promise<MySqlRuntimeResponse>;
}

const encoder = new TextEncoder();
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function keys(value: Record<string, unknown>, expected: string[]): boolean {
  return Object.keys(value).length === expected.length && expected.every(key => Object.hasOwn(value, key));
}
function string(value: unknown, maximum: number, empty = false, multiline = false): value is string {
  return typeof value === "string" && (empty || value.trim().length > 0) && encoder.encode(value).length <= maximum &&
    !/[\uD800-\uDFFF]/u.test(value) && ![...value].some(char => {
      const code = char.codePointAt(0)!;
      return code < 0x20 && !(multiline && [9, 10, 13].includes(code)) || code >= 0x7f && code <= 0x9f;
    });
}
function integer(value: unknown, max: number, min = 0): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;
}
function mode(value: unknown): value is MySqlTlsMode { return value === "verify-full" || value === "ssh-loopback"; }
function certificate(value: unknown): boolean { return value === null || string(value, 65536, false, true); }
function host(value: unknown): value is string { return string(value, 253) && /^[A-Za-z0-9._:[\]-]+$/u.test(value); }
function oneOf(value: unknown, values: readonly string[]): boolean { return typeof value === "string" && values.includes(value); }
function profileInput(value: unknown): value is MySqlProfileInput {
  return record(value) && keys(value, ["name", "host", "port", "username", "database", "tlsMode", "caPem"]) &&
    string(value.name, 256) && host(value.host) && integer(value.port, 65535, 1) && string(value.username, 128) &&
    string(value.database, 128, true) && mode(value.tlsMode) && certificate(value.caPem) && (value.tlsMode !== "ssh-loopback" || value.caPem === null);
}
function accountInput(value: unknown): value is MySqlAccountInput {
  return record(value) && keys(value, ["user", "host"]) && string(value.user, 128) && string(value.host, 255);
}
function passwordChange(value: unknown): value is MySqlPasswordChange {
  if (!record(value)) return false;
  if (value.action === "keep" || value.action === "remove") return keys(value, ["action"]);
  return value.action === "replace" && keys(value, ["action", "value"]) && typeof value.value === "string" &&
    value.value.length > 0 && encoder.encode(value.value).length <= 16384 && !value.value.includes("\0") && !/[\uD800-\uDFFF]/u.test(value.value);
}
function passwordText(value: unknown): boolean {
  return typeof value === "string" && encoder.encode(value).length <= 1024 && !value.includes("\0") && !/[\uD800-\uDFFF]/u.test(value);
}
export function isMySqlRuntimeRequest(value: unknown): value is MySqlRuntimeRequest {
  if (!record(value) || !string(value.bindingHandle, 128)) return false;
  const basic = ["action", "bindingHandle"];
  switch (value.action) {
    case "list": return keys(value, basic);
    case "save": return keys(value, [...basic, "profileHandle", "profile", "password"]) &&
      (value.profileHandle === null || string(value.profileHandle, 128)) && profileInput(value.profile) && passwordChange(value.password);
    case "plan-delete": return keys(value, [...basic, "profileHandle"]) && string(value.profileHandle, 128);
    case "delete": return keys(value, [...basic, "planHandle"]) && string(value.planHandle, 128);
    case "plan-password": return keys(value, [...basic, "profileHandle", "account", "password", "updateSavedPassword"]) && string(value.profileHandle, 128) &&
      accountInput(value.account) && passwordText(value.password) && typeof value.updateSavedPassword === "boolean";
    case "execute-password": return keys(value, [...basic, "planHandle"]) && string(value.planHandle, 128);
    case "plan-password-restore": return keys(value, [...basic, "restoreHandle", "profileHandle"]) && string(value.restoreHandle, 128) && string(value.profileHandle, 128);
    case "execute-password-restore": return keys(value, [...basic, "planHandle"]) && string(value.planHandle, 128);
    case "inspect": return keys(value, [...basic, "profileHandle"]) && string(value.profileHandle, 128);
    default: return false;
  }
}
function passwordPlanView(value: unknown): value is MySqlPasswordPlanView {
  return record(value) && keys(value, ["account", "plugin", "product", "isConnectionAccount", "restorable", "updateSavedPassword", "warnings"]) &&
    string(value.account, 300) && string(value.plugin, 128) && string(value.product, 32) &&
    typeof value.isConnectionAccount === "boolean" && typeof value.restorable === "boolean" && typeof value.updateSavedPassword === "boolean" &&
    Array.isArray(value.warnings) && value.warnings.length <= 8 && value.warnings.every(warning => string(warning, 512));
}
function restorePlanView(value: unknown): value is MySqlPasswordRestorePlanView {
  return record(value) && keys(value, ["account", "savedPasswordWasUpdated"]) && string(value.account, 300) && typeof value.savedPasswordWasUpdated === "boolean";
}
function passwordVerification(value: unknown): value is MySqlPasswordVerification {
  return record(value) && keys(value, ["state", "reason"]) &&
    (oneOf(value.state, ["passed", "rejected"]) && value.reason === null || value.state === "unverifiable" && value.reason === "path");
}
function savedUpdate(value: unknown): value is SavedPasswordUpdate {
  return oneOf(value, ["not-requested", "updated", "profile-changed", "skipped-verification-not-passed", "failed"]);
}
function reviewAccount(value: unknown): value is MySqlReviewAccount {
  return record(value) && keys(value, ["user", "host", "plugin", "emptySecret", "superuser", "filePriv", "grantPriv", "locked"]) &&
    string(value.user, 128) && string(value.host, 255) && string(value.plugin, 128) &&
    typeof value.emptySecret === "boolean" && typeof value.superuser === "boolean" && typeof value.filePriv === "boolean" &&
    typeof value.grantPriv === "boolean" && (value.locked === null || typeof value.locked === "boolean");
}
function reviewUdf(value: unknown): value is MySqlReviewUdf {
  return record(value) && keys(value, ["name", "library"]) && string(value.name, 128) && string(value.library, 512);
}
function reviewFinding(value: unknown): value is MySqlReviewFinding {
  return record(value) && keys(value, ["level", "code", "detail"]) &&
    oneOf(value.level, ["info", "review", "high"]) && string(value.code, 64) && string(value.detail, 1024);
}
function reviewDenied(value: unknown): value is MySqlReviewDenied {
  return record(value) && keys(value, ["user", "host", "count"]) &&
    string(value.user, 128) && string(value.host, 255) && integer(value.count, 2147483647, 1);
}
function reviewHit(value: unknown): value is MySqlReviewHit {
  return record(value) && keys(value, ["kind", "excerpt"]) && string(value.kind, 64) && string(value.excerpt, 1024);
}
function reviewLog(value: unknown): value is MySqlReviewLog {
  return record(value) && keys(value, ["path", "tailBytes", "denied", "hits"]) &&
    string(value.path, 1024) && integer(value.tailBytes, 16777216) &&
    Array.isArray(value.denied) && value.denied.length <= 8 && value.denied.every(reviewDenied) &&
    Array.isArray(value.hits) && value.hits.length <= 40 && value.hits.every(reviewHit);
}
function instanceReview(value: unknown): value is MySqlInstanceReview {
  return record(value) && keys(value, ["product", "serverVersion", "connecting", "accounts", "accountTotal", "udfs", "udfTotal", "variables", "findings", "gaps", "log"]) &&
    oneOf(value.product, ["MySQL", "MariaDB"]) && string(value.serverVersion, 128) && string(value.connecting, 300) &&
    Array.isArray(value.accounts) && value.accounts.length <= 512 && value.accounts.every(reviewAccount) &&
    integer(value.accountTotal, 1000000) && value.accountTotal >= value.accounts.length &&
    Array.isArray(value.udfs) && value.udfs.length <= 64 && value.udfs.every(reviewUdf) &&
    integer(value.udfTotal, 1000000) && value.udfTotal >= value.udfs.length &&
    record(value.variables) && Object.keys(value.variables).length <= 64 &&
    Object.entries(value.variables).every(([name, item]) => string(name, 128) && string(item, 1024, true)) &&
    Array.isArray(value.findings) && value.findings.length <= 64 && value.findings.every(reviewFinding) &&
    Array.isArray(value.gaps) && value.gaps.length <= 24 && value.gaps.every(gap => string(gap, 256)) &&
    (value.log === null || reviewLog(value.log));
}
function profileSummary(value: unknown): value is MySqlProfileSummary {
  return record(value) && keys(value, ["profileHandle", "name", "host", "port", "username", "database", "tlsMode", "hasPassword", "hasCa", "unassigned"]) &&
    string(value.profileHandle, 128) && string(value.name, 256) && host(value.host) && integer(value.port, 65535, 1) &&
    string(value.username, 128) && string(value.database, 128, true) && mode(value.tlsMode) && typeof value.hasPassword === "boolean" &&
    typeof value.hasCa === "boolean" && typeof value.unassigned === "boolean" && (value.tlsMode !== "ssh-loopback" || value.hasCa === false);
}
export function isMySqlRuntimeResponse(value: unknown): value is MySqlRuntimeResponse {
  if (!record(value)) return false;
  switch (value.kind) {
    case "rejected": return keys(value, ["kind", "action", "code", "detail"]) && oneOf(value.action, ["list", "save", "plan-delete", "delete", "plan-password", "execute-password", "plan-password-restore", "execute-password-restore", "inspect"]) && oneOf(value.code, ["invalid-params", "invalid", "stale", "busy", "capacity", "store", "unknown-state", "rejected"]) && string(value.detail, 2048);
    case "profiles": return keys(value, ["kind", "profiles"]) && Array.isArray(value.profiles) && value.profiles.length <= 256 &&
      value.profiles.every(profileSummary) && new Set(value.profiles.map(item => item.profileHandle)).size === value.profiles.length;
    case "saved": return keys(value, ["kind", "profile"]) && profileSummary(value.profile) && !value.profile.unassigned;
    case "delete-plan": return keys(value, ["kind", "planHandle", "profile", "expiresInMs"]) && string(value.planHandle, 128) && profileSummary(value.profile) && integer(value.expiresInMs, 120000, 1);
    case "deleted": return keys(value, ["kind", "planHandle", "profileHandle", "verified", "detail"]) && string(value.planHandle, 128) && string(value.profileHandle, 128) && typeof value.verified === "boolean" && string(value.detail, 2048);
    case "password-plan": return keys(value, ["kind", "planHandle", "expiresInMs", "plan"]) && string(value.planHandle, 128) && integer(value.expiresInMs, 120000, 1) && passwordPlanView(value.plan);
    case "password-result": return keys(value, ["kind", "result"]) && record(value.result) && keys(value.result, ["verification", "savedPassword", "restorable", "journalRecorded", "restoreHandle", "restoreUnavailable", "profile"]) &&
      passwordVerification(value.result.verification) && savedUpdate(value.result.savedPassword) && typeof value.result.restorable === "boolean" && typeof value.result.journalRecorded === "boolean" && typeof value.result.restoreUnavailable === "boolean" &&
      (value.result.restoreHandle === null || string(value.result.restoreHandle, 128)) && (value.result.profile === null || profileSummary(value.result.profile));
    case "password-restore-plan": return keys(value, ["kind", "planHandle", "expiresInMs", "plan"]) && string(value.planHandle, 128) && integer(value.expiresInMs, 120000, 1) && restorePlanView(value.plan);
    case "password-restore-result": return keys(value, ["kind", "result"]) && record(value.result) && keys(value.result, ["verified", "savedPasswordRestored", "journalRecorded", "profile"]) &&
      typeof value.result.verified === "boolean" && typeof value.result.savedPasswordRestored === "boolean" && typeof value.result.journalRecorded === "boolean" &&
      (value.result.profile === null || profileSummary(value.result.profile));
    case "review": return keys(value, ["kind", "review"]) && instanceReview(value.review);
    default: return false;
  }
}
export function matchesMySqlRuntimeResponse(request: MySqlRuntimeRequest, response: unknown): response is MySqlRuntimeResponse {
  if (!isMySqlRuntimeResponse(response)) return false;
  if (response.kind === "rejected") return response.action === request.action;
  switch (request.action) {
    case "list": return response.kind === "profiles";
    case "save": return response.kind === "saved" && ["name", "host", "port", "username", "database", "tlsMode"].every(key =>
      response.profile[key as keyof MySqlProfileSummary] === request.profile[key as keyof MySqlProfileInput]) &&
      response.profile.hasCa === (request.profile.caPem !== null) &&
      (request.password.action === "keep" || response.profile.hasPassword === (request.password.action === "replace"));
    case "plan-delete": return response.kind === "delete-plan" && response.profile.profileHandle === request.profileHandle;
    case "delete": return response.kind === "deleted" && response.planHandle === request.planHandle;
    case "plan-password": return response.kind === "password-plan";
    case "execute-password": return response.kind === "password-result";
    case "plan-password-restore": return response.kind === "password-restore-plan";
    case "execute-password-restore": return response.kind === "password-restore-result";
    case "inspect": return response.kind === "review";
  }
}
