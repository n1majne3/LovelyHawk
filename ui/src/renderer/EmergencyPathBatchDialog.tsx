import { useRef, useState } from "react";

import { targetFailureMessage } from "./target-lost";
import {
  isEmergencyPathBatchPlan,
  isEmergencyPathBatchStep,
  isEmergencyPathUndoResult,
  type EmergencyPathAction,
  type EmergencyPathBatchItem,
  type EmergencyPathBatchPlan,
  type EmergencyPathReceipt,
} from "../shared/emergency-command-contract";
import { useModalScrim } from "./modal-scrim";
import "./emergency-path.css";

/** The narrow surface a batch needs out of the page's API bridge. */
export interface EmergencyPathBatchApi {
  planEmergencyPathBatch(
    bindingHandle: string,
    pathHandles: readonly string[],
    action: EmergencyPathAction,
  ): Promise<unknown>;
  confirmEmergencyPathBatch(bindingHandle: string, batchHandle: string): Promise<unknown>;
  stepEmergencyPathBatch(bindingHandle: string, batchHandle: string): Promise<unknown>;
  cancelEmergencyPathBatch(bindingHandle: string, batchHandle: string): Promise<void>;
  undoEmergencyPathAction(bindingHandle: string, planHandle: string): Promise<unknown>;
}

type BatchPhase = "choose" | "planning" | "preview" | "running" | "done" | "stopped" | "error";

const BATCH_REFUSAL_LABELS: Record<string, string> = {
  "path-stale": "条目已过期，请重新提取文件条目后再试。",
  "inspect-failed": "无法读取该文件当前状态，未纳入处置。",
  "not-executable": "该文件当前没有执行位，没有可去除的内容。",
  "tools": "目标机缺少安全操作所需的工具。",
  "privilege": "需要 root 或可免密 sudo 的权限。",
  "kind": "只有普通文件可以这样处置。",
  "empty": "该文件没有可处置的内容。",
  "unavailable": "无法为该文件制定处置计划。",
  "confirm-failed": "该文件的计划未能确认，未执行。",
};

const BATCH_ACTION_LABELS: Record<"disarm" | "quarantine", string> = {
  quarantine: "批量隔离",
  disarm: "批量去执行位",
};

function refusalLabel(key: string): string {
  return BATCH_REFUSAL_LABELS[key] ?? "该项被安全规则拒绝。";
}

function itemKindLabel(kind: string): string {
  switch (kind) {
    case "file": return "文件";
    case "directory": return "目录";
    case "symlink": return "符号链接";
    case "other": return "其他";
    default: return "未知";
  }
}

/** The action-pick stage: the two containment actions and what each does. */
export function EmergencyPathBatchChoose({ count, onPick }: {
  count: number;
  onPick: (action: "disarm" | "quarantine") => void;
}) {
  return (
    <div className="emergency-path-batch-choose">
      <p role="note">对选中的 {count} 个文件条目执行同一种处置。</p>
      <span />
      <button type="button" className="is-primary" onClick={() => onPick("quarantine")}>
        批量隔离
      </button>
      <p>移入留档区，之后可以按原位置恢复。</p>
      <button type="button" className="is-primary" onClick={() => onPick("disarm")}>
        批量去执行位
      </button>
      <p>清除可执行与提权位，文件保留可读以便检查。</p>
    </div>
  );
}

/**
 * The item rows: preview facts and plan-or-refusal first, then each item's
 * own receipt and undo once steps have run.
 */
export function EmergencyPathBatchItems({ items, receipts, undone, onUndo }: {
  items: readonly EmergencyPathBatchItem[];
  receipts: readonly EmergencyPathReceipt[];
  undone: ReadonlyMap<string, string>;
  onUndo: (planHandle: string) => void;
}) {
  return (
    <ul className="emergency-path-batch-items">
      {items.map((item) => {
        const receipt = receipts.find((row) => row.planHandle === item.planHandle);
        return (
          <li key={item.pathHandle} data-testid="emergency-path-batch-item"
            className={receipt !== undefined
              ? receipt.passed ? "is-done" : "is-failed"
              : item.refusal !== null ? "is-refused" : undefined}>
            <code>{item.path || item.pathHandle}</code>
            <span className="emergency-path-batch-facts">
              {item.kind === "" ? null : itemKindLabel(item.kind)}
              {item.mode !== null ? ` ${item.mode}` : ""}{item.executable ? " 可执行" : ""}
              {item.size === "" ? "" : ` · ${item.size} 字节`}
            </span>
            {item.refusal !== null ? (
              <span className="emergency-path-batch-refusal">{refusalLabel(item.refusal)}</span>
            ) : receipt === undefined ? (
              <span>{item.summary}{item.restoreDescription !== null ? `（${item.restoreDescription}）` : ""}</span>
            ) : (
              <span className={receipt.passed ? "" : "is-dangerous"}>
                {receipt.passed ? "已完成并核对" :
                  receipt.untouched ? "被拒绝，文件未改动" : "未通过核对"}
                {` · ${receipt.detail}`}
                {receipt.restored ? " 已放回改动。" : ""}
                {undone.has(receipt.planHandle) ? ` 撤销：${undone.get(receipt.planHandle)}` : null}
                {receipt.undoable && !undone.has(receipt.planHandle) ? (
                  <button type="button" className="is-link" onClick={() => onUndo(receipt.planHandle)}>
                    撤销
                  </button>
                ) : null}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * One dialog for acting on several named files at once: pick the action,
 * read what each file would get (or why it is refused), confirm once, then
 * watch the items run one by one. Each finished item keeps its own undo.
 */
export function EmergencyPathBatchDialog({ api, bindingHandle, pathHandles, onClose }: {
  api: EmergencyPathBatchApi;
  bindingHandle: string;
  pathHandles: readonly string[];
  onClose: () => void;
}) {
  useModalScrim();
  const [phase, setPhase] = useState<BatchPhase>("choose");
  const [plan, setPlan] = useState<EmergencyPathBatchPlan | null>(null);
  const [receipts, setReceipts] = useState<EmergencyPathReceipt[]>([]);
  const [undone, setUndone] = useState<Map<string, string>>(new Map());
  const [error, setError] = useState<string | null>(null);
  const stopRef = useRef(false);

  const beginPlan = (action: EmergencyPathAction) => {
    setPhase("planning");
    void api.planEmergencyPathBatch(bindingHandle, pathHandles, action).then((value) => {
      if (!isEmergencyPathBatchPlan(value)) throw new Error();
      setPlan(value);
      setPhase("preview");
    }).catch((reason: unknown) => {
      setError(targetFailureMessage(reason, "无法制定批量处置计划；条目可能已过期或目标已切换。"));
      setPhase("error");
    });
  };

  const runSteps = async (batchHandle: string) => {
    setPhase("running");
    stopRef.current = false;
    try {
      while (!stopRef.current) {
        const step = await api.stepEmergencyPathBatch(bindingHandle, batchHandle);
        if (!isEmergencyPathBatchStep(step)) throw new Error();
        if (step.receipt !== null) setReceipts((rows) => [...rows, step.receipt as EmergencyPathReceipt]);
        if (step.finished) {
          setPhase("done");
          return;
        }
      }
      // The operator stopped between items: the ones not yet run go back.
      await api.cancelEmergencyPathBatch(bindingHandle, batchHandle).catch(() => undefined);
      setPhase("stopped");
    } catch (reason: unknown) {
      setError(targetFailureMessage(reason, "批量处置中途失败；已完成的条目见其各自结果。"));
      setPhase("error");
    }
  };

  const confirmPlan = () => {
    if (plan === null) return;
    void api.confirmEmergencyPathBatch(bindingHandle, plan.batchHandle).then((value) => {
      if (!isEmergencyPathBatchPlan(value) || value.batchHandle !== plan.batchHandle) {
        throw new Error();
      }
      setPlan(value);
      void runSteps(value.batchHandle);
    }).catch((reason: unknown) => {
      setError(targetFailureMessage(reason, "确认未能送达；计划可能已过期。"));
      setPhase("error");
    });
  };

  const undoItem = (planHandle: string) => {
    void api.undoEmergencyPathAction(bindingHandle, planHandle).then((value) => {
      if (!isEmergencyPathUndoResult(value) || value.planHandle !== planHandle) throw new Error();
      setUndone((map) => new Map(map).set(planHandle, value.detail));
    }).catch((reason: unknown) => {
      setUndone((map) => new Map(map).set(
        planHandle,
        targetFailureMessage(reason, "撤销没有完成，请在目标机上核对文件现状。"),
      ));
    });
  };

  const close = () => {
    // Closing mid-run lets the pending items go back rather than finishing
    // a set nobody is watching.
    if (phase === "running" && plan !== null) {
      void api.cancelEmergencyPathBatch(bindingHandle, plan.batchHandle).catch(() => undefined);
    } else if (phase === "preview" && plan !== null) {
      void api.cancelEmergencyPathBatch(bindingHandle, plan.batchHandle).catch(() => undefined);
    }
    onClose();
  };

  const actionLabel = plan === null ? "" :
    (BATCH_ACTION_LABELS[plan.action as "disarm" | "quarantine"] ?? plan.action);
  return (
    <div className="emergency-path-backdrop" role="presentation">
      <section className="emergency-path-dialog emergency-path-batch" role="dialog" aria-modal="true"
        aria-label="批量处置" data-testid="emergency-path-batch">
        <header>
          <h2>批量处置</h2>
          <p>{phase === "choose"
            ? `对选中的 ${pathHandles.length} 个文件条目执行同一种处置。`
            : `${actionLabel} · ${pathHandles.length} 个条目`}</p>
        </header>
        {phase === "choose" ? (
          <EmergencyPathBatchChoose count={pathHandles.length} onPick={beginPlan} />
        ) : null}
        {phase === "planning" ? <p role="status">正在为每个条目制定处置计划…</p> : null}
        {(phase === "preview" || phase === "running" || phase === "done" || phase === "stopped") &&
          plan !== null ? (
          <>
            <EmergencyPathBatchItems items={plan.items} receipts={receipts} undone={undone}
              onUndo={undoItem} />
            {phase === "preview" ? (
              <p className="emergency-path-batch-summary" role="status">
                {plan.planned} 项可执行{plan.refused > 0 ? `，${plan.refused} 项被拒绝（原因见上）` : ""}。
                确认后逐项执行，可随时停止；各项结果与撤销互不影响。
              </p>
            ) : null}
            {phase === "running" ? (
              <p className="emergency-path-batch-summary" role="status">
                正在逐项执行…已完成 {receipts.length} 项
              </p>
            ) : null}
            {phase === "done" ? (
              <p className="emergency-path-batch-summary" role="status">
                全部完成：{receipts.filter((row) => row.passed).length} 项成功，
                {receipts.filter((row) => !row.passed).length} 项未成功，
                {plan.refused} 项被拒绝。
              </p>
            ) : null}
            {phase === "stopped" ? (
              <p className="emergency-path-batch-summary" role="status">
                已在条目之间停止：{receipts.length} 项已执行，其余未执行；已完成项仍可各自撤销。
              </p>
            ) : null}
          </>
        ) : null}
        {phase === "error" ? (
          <p className="emergency-path-batch-error" role="alert">
            {error ?? "批量处置未能完成。"}
            {receipts.length > 0 ? ` 已完成的 ${receipts.length} 项见其上方结果。` : ""}
          </p>
        ) : null}
        <footer>
          {phase === "choose" ? (
            <button type="button" onClick={close}>取消</button>
          ) : null}
          {phase === "preview" ? (
            <>
              <button type="button" onClick={close}>取消</button>
              <button type="button" className="is-primary" disabled={plan === null || plan.planned === 0}
                onClick={confirmPlan}>
                确认执行{plan === null ? "" : ` ${plan.planned} 项`}
              </button>
            </>
          ) : null}
          {phase === "running" ? (
            <button type="button" onClick={() => { stopRef.current = true; }}>
              停止后续条目
            </button>
          ) : null}
          {phase === "done" || phase === "stopped" || phase === "error" ? (
            <button type="button" className="is-primary" onClick={close}>关闭</button>
          ) : null}
        </footer>
      </section>
    </div>
  );
}
