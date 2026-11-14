import { useEffect, useRef, useState } from "react";

import type {
  EmergencyPathLine,
  EmergencyPathLinesPlan,
  EmergencyPathLinesPreview,
  EmergencyPathReceipt,
  EmergencyPathUndoResult,
} from "../shared/emergency-command-contract";
import { EmergencyPathOutcome } from "./EmergencyPathDialog";
import { useModalScrim } from "./modal-scrim";
import { planExpiryLabel } from "./plan-expiry";
import "./emergency-path.css";

export interface EmergencyPathLinesDialogProps {
  /** The file the operator right-clicked, as the target printed it. */
  path: string;
  preview: EmergencyPathLinesPreview | null;
  plan: EmergencyPathLinesPlan | null;
  receipt: EmergencyPathReceipt | null;
  undo?: EmergencyPathUndoResult | null;
  undoSpent?: boolean;
  busy: boolean;
  error: string | null;
  onPlan: (firstLine: number, lastLine: number) => void;
  onBack: () => void;
  onConfirm: () => void;
  onUndo?: () => void;
  onClose: () => void;
}

/** A chosen range never removes more than a person can read before confirming. */
const MAX_DELETE_LINES = 200;

interface Selection {
  anchor: number;
  extent: number;
}

function selectedRange(selection: Selection | null): { first: number; last: number } | null {
  if (selection === null) return null;
  return {
    first: Math.min(selection.anchor, selection.extent),
    last: Math.max(selection.anchor, selection.extent),
  };
}

/**
 * Pick a contiguous range of a managed file's lines, read exactly what will
 * go, confirm, run — the same order every other path action uses. Nothing
 * executes from a default button or a stray Enter inside the line list.
 */
export function EmergencyPathLinesDialog({
  path,
  preview,
  plan,
  receipt,
  undo = null,
  undoSpent = false,
  busy,
  error,
  onPlan,
  onBack,
  onConfirm,
  onUndo = () => undefined,
  onClose,
}: EmergencyPathLinesDialogProps) {
  useModalScrim();
  const [askingUndo, setAskingUndo] = useState(false);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [cursor, setCursor] = useState(1);
  const [firstText, setFirstText] = useState("");
  const [lastText, setLastText] = useState("");
  const listRef = useRef<HTMLDivElement>(null);
  const planHeadingRef = useRef<HTMLParagraphElement>(null);
  const total = preview?.totalLines ?? 0;

  // A newly made plan must not sit under Enter: focus moves to its heading,
  // and the destructive button only fires when somebody chooses it.
  useEffect(() => {
    if (plan !== null) planHeadingRef.current?.focus();
  }, [plan]);

  const range = selectedRange(selection);
  const rangeError = (() => {
    if (range === null) return null;
    if (range.first < 1 || range.last > total) return "行号超出文件范围。";
    if (range.last - range.first + 1 > MAX_DELETE_LINES) {
      return `一次最多删除 ${MAX_DELETE_LINES} 行，请缩小范围。`;
    }
    return null;
  })();

  const pick = (number: number, extend: boolean) => {
    setSelection((current) => {
      const next = extend && current !== null
        ? { anchor: current.anchor, extent: number }
        : { anchor: number, extent: number };
      const chosen = selectedRange(next);
      setFirstText(chosen === null ? "" : String(chosen.first));
      setLastText(chosen === null ? "" : String(chosen.last));
      return next;
    });
  };

  const pickNumbers = (first: string, last: string) => {
    const firstValue = first.trim() === "" ? Number.NaN : Number(first);
    const lastValue = last.trim() === "" ? first.trim() === "" ? Number.NaN : Number(first) : Number(last);
    if (!Number.isSafeInteger(firstValue) || !Number.isSafeInteger(lastValue)) {
      setSelection(null);
      return;
    }
    setSelection({ anchor: Math.trunc(firstValue), extent: Math.trunc(lastValue) });
  };

  const onListKey = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (preview === null || preview.lines.length === 0) return;
    const shown = preview.lines.length;
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      const next = Math.min(Math.max(cursor + step, 1), shown);
      setCursor(next);
      if (event.shiftKey) {
        setSelection((current) => current === null ? { anchor: next, extent: next }
          : { anchor: current.anchor, extent: next });
        const chosen = selectedRange(selection === null ? { anchor: next, extent: next }
          : { anchor: selection.anchor, extent: next });
        setFirstText(chosen === null ? "" : String(chosen.first));
        setLastText(chosen === null ? "" : String(chosen.last));
      }
      listRef.current
        ?.querySelector(`[data-line-number="${next}"]`)
        ?.scrollIntoView({ block: "nearest" });
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      pick(cursor, event.shiftKey);
    } else if (event.key === "Home") {
      event.preventDefault();
      setCursor(1);
      listRef.current?.querySelector('[data-line-number="1"]')?.scrollIntoView({ block: "nearest" });
    } else if (event.key === "End") {
      event.preventDefault();
      setCursor(shown);
      listRef.current?.querySelector(`[data-line-number="${shown}"]`)?.scrollIntoView({ block: "nearest" });
    }
  };

  return (
    <div className="emergency-path-backdrop" role="presentation">
      <section
        className="emergency-path-dialog emergency-path-lines-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="删除指定行"
        data-testid="emergency-path-lines-dialog"
      >
        <header>
          <h2>删除指定行</h2>
          <p>{path}</p>
        </header>

        {receipt !== null ? (
          <EmergencyPathOutcome
            action="delete-lines"
            receipt={receipt}
            undo={undo}
            undoSpent={undoSpent}
            askingUndo={askingUndo}
            busy={busy}
            error={error}
            onAskUndo={() => setAskingUndo(true)}
            onKeep={() => setAskingUndo(false)}
            onUndo={() => {
              setAskingUndo(false);
              onUndo();
            }}
            onClose={onClose} />
        ) : (
          <>
            <p className="emergency-path-note">
              “注释”把原行保留在文件里便于回看；这里是从文件中彻底移除所选行，文件中不再保留该行原文。
              写入前会把整份文件备份到同目录的 <code>.lovelyres-backups/</code>，
              文件若在查看后变化会拒绝写入。删除完成不等于系统已无入侵，请结合留证继续排查。
            </p>
            {preview === null ? (
              <p className="emergency-path-note" role="status">
                {busy ? "正在读取文件内容…" : "未能读取文件内容。"}
              </p>
            ) : plan === null ? (
              <>
                {preview.truncated ? (
                  <p className="emergency-path-note" role="note">
                    该文件共 {preview.totalLines} 行，下面只显示前 {preview.lines.length} 行；
                    超出部分仍可通过右侧行号输入选择，生成计划时会列出实际要删除的内容。
                  </p>
                ) : null}
                <div
                  ref={listRef}
                  className="emergency-path-lines"
                  role="listbox"
                  aria-label="文件行列表"
                  aria-multiselectable="false"
                  tabIndex={0}
                  onKeyDown={onListKey}
                  data-testid="emergency-path-lines"
                >
                  {preview.lines.map((line) => (
                    <LineRow
                      key={line.number}
                      line={line}
                      selected={range !== null && line.number >= range.first && line.number <= range.last}
                      active={line.number === cursor}
                      onPick={(extend) => {
                        setCursor(line.number);
                        pick(line.number, extend);
                      }} />
                  ))}
                </div>
                <div className="emergency-path-range">
                  <label>
                    从第
                    <input
                      type="number"
                      min={1}
                      max={total}
                      inputMode="numeric"
                      value={firstText}
                      disabled={busy}
                      data-testid="emergency-path-first-line"
                      onChange={(event) => {
                        setFirstText(event.target.value);
                        pickNumbers(event.target.value, lastText);
                      }}
                    />
                    行
                  </label>
                  <label>
                    到第
                    <input
                      type="number"
                      min={1}
                      max={total}
                      inputMode="numeric"
                      value={lastText}
                      disabled={busy}
                      data-testid="emergency-path-last-line"
                      onChange={(event) => {
                        setLastText(event.target.value);
                        pickNumbers(firstText, event.target.value);
                      }}
                    />
                    行
                  </label>
                  <span className="emergency-path-hint">
                    单击选择整行；按住 Shift 再选另一行选中两者之间的连续范围；未显示的行可直接输入行号。
                  </span>
                </div>
                {rangeError === null ? null : (
                  <p className="emergency-path-error" role="alert">{rangeError}</p>
                )}
                {error === null ? null : <p className="emergency-path-error" role="alert">{error}</p>}
                <footer>
                  <button type="button" onClick={onClose} disabled={busy}>取消</button>
                  <button
                    type="button"
                    className="is-primary"
                    disabled={busy || range === null || rangeError !== null}
                    data-testid="emergency-path-lines-plan"
                    onClick={() => {
                      if (range !== null && rangeError === null) onPlan(range.first, range.last);
                    }}
                  >
                    {busy ? "生成计划中…" : "生成删除计划"}
                  </button>
                </footer>
              </>
            ) : (
              <>
                <div className="emergency-path-panel is-dangerous">
                  <p
                    ref={planHeadingRef}
                    className="emergency-path-summary"
                    tabIndex={-1}
                    data-testid="emergency-path-lines-plan-heading"
                  >
                    将要删除 {plan.removedLines.length} 行
                  </p>
                  <dl>
                    <div>
                      <dt>将要执行</dt>
                      <dd>{plan.summary}</dd>
                    </div>
                    <div>
                      <dt>出错后如何还原</dt>
                      <dd>{plan.restoreDescription ?? "无备份，执行后不可自动还原"}</dd>
                    </div>
                    <div>
                      <dt>计划有效期</dt>
                      <dd>{planExpiryLabel(plan.expiresInSeconds)}</dd>
                    </div>
                  </dl>
                  <div className="emergency-path-lines is-removed" role="list" aria-label="将被删除的行">
                    {plan.removedLines.map((line) => (
                      <div key={line.number} className="emergency-path-line" role="listitem">
                        <span className="emergency-path-line-number">{line.number}</span>
                        <span className="emergency-path-line-text">
                          {line.text === "" ? "（空行）" : line.text}
                          {line.clipped ? <em className="emergency-path-line-clip">（过长，显示已截断）</em> : null}
                        </span>
                      </div>
                    ))}
                  </div>
                  <p className="emergency-path-note">
                    对 init.d 脚本与 rc.local，写入后会用 sh -n 做语法检查，不通过则自动放回原文件；
                    语法检查不能证明脚本行为无害。
                  </p>
                </div>
                {error === null ? null : <p className="emergency-path-error" role="alert">{error}</p>}
                <footer>
                  <button type="button" onClick={onBack} disabled={busy}
                    data-testid="emergency-path-lines-back">
                    返回选择行
                  </button>
                  <button type="button" onClick={onClose} disabled={busy}>取消</button>
                  <button
                    type="button"
                    className="is-dangerous"
                    disabled={busy}
                    data-testid="emergency-path-execute"
                    onClick={onConfirm}
                  >
                    {busy ? "执行并复核中…" : "确认并删除"}
                  </button>
                </footer>
              </>
            )}
          </>
        )}
      </section>
    </div>
  );
}

function LineRow({
  line,
  selected,
  active,
  onPick,
}: {
  line: EmergencyPathLine;
  selected: boolean;
  /** The keyboard cursor sits here. */
  active: boolean;
  onPick: (extend: boolean) => void;
}) {
  return (
    <div
      className={`emergency-path-line${selected ? " is-selected" : ""}${active ? " is-active" : ""}`}
      role="option"
      aria-selected={selected}
      data-line-number={line.number}
      onClick={(event) => onPick(event.shiftKey)}
    >
      <span className="emergency-path-line-number">{line.number}</span>
      <span className="emergency-path-line-text">
        {line.text === "" ? "（空行）" : line.text}
        {line.clipped ? <em className="emergency-path-line-clip">（过长，显示已截断）</em> : null}
      </span>
    </div>
  );
}
