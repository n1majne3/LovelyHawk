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
  | { action: "execute-password-restore"; bindingHandle: string; planHandle: string };
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
export type MySqlRuntimeResponse =
  | { kind: "rejected"; action: MySqlRuntimeRequest["action"]; code: "invalid-params" | "invalid" | "stale" | "busy" | "capacity" | "store" | "unknown-state" | "rejected"; detail: string }
  | { kind: "profiles"; profiles: MySqlProfileSummary[] }
  | { kind: "saved"; profile: MySqlProfileSummary }
  | { kind: "delete-plan"; planHandle: string; profile: MySqlProfileSummary; expiresInMs: number }
  | { kind: "deleted"; planHandle: string; profileHandle: string; verified: boolean; detail: string }
  | { kind: "password-plan"; planHandle: string; expiresInMs: number; plan: MySqlPasswordPlanView }
  | { kind: "password-result"; result: MySqlPasswordResult }
  | { kind: "password-restore-plan"; planHandle: string; expiresInMs: number; plan: MySqlPasswordRestorePlanView }
  | { kind: "password-restore-result"; result: MySqlPasswordRestoreResult };
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
    !/[-￿]/u.test(value) && ![...value].some(char => {
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
    value.value.length > 0 && encoder.encode(value.value).length <= 16384 && !value.value.includes("\0") && !/[-￿]/u.test(value.value);
}
function passwordText(value: unknown): boolean {
  return typeof value === "string" && encoder.encode(value).length <= 1024 && !value.includes("\0") && !/[-￿]/u.test(value);
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
function profileSummary(value: unknown): value is MySqlProfileSummary {
  return record(value) && keys(value, ["profileHandle", "name", "host", "port", "username", "database", "tlsMode", "hasPassword", "hasCa", "unassigned"]) &&
    string(value.profileHandle, 128) && string(value.name, 256) && host(value.host) && integer(value.port, 65535, 1) &&
    string(value.username, 128) && string(value.database, 128, true) && mode(value.tlsMode) && typeof value.hasPassword === "boolean" &&
    typeof value.hasCa === "boolean" && typeof value.unassigned === "boolean" && (value.tlsMode !== "ssh-loopback" || value.hasCa === false);
}
export function isMySqlRuntimeResponse(value: unknown): value is MySqlRuntimeResponse {
  if (!record(value)) return false;
  switch (value.kind) {
    case "rejected": return keys(value, ["kind", "action", "code", "detail"]) && oneOf(value.action, ["list", "save", "plan-delete", "delete", "plan-password", "execute-password", "plan-password-restore", "execute-password-restore"]) && oneOf(value.code, ["invalid-params", "invalid", "stale", "busy", "capacity", "store", "unknown-state", "rejected"]) && string(value.detail, 2048);
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
  }
}
