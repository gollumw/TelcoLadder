"use client";

import { t, useLang } from "../i18n";
import { useEffect, useState } from "react";
import { Loader2, Plus, RotateCw, Trash2, Wrench } from "lucide-react";
import { cn } from "@/lib/utils";
import type { DecodeAsRule } from "@/data/source";

/** `-d` 規則的選擇器。這四個涵蓋電信擷取檔實際會遇到的情況。 */
const SELECTORS = ["tcp.port", "udp.port", "sctp.port", "sctp.ppi"];

/** 常見的目標協定。可以自己打，這只是省得查拼法。 */
const PROTOCOLS = ["http2", "ngap", "nas-5gs", "pfcp", "gtp", "diameter", "sip"];

const ORIGIN_META: Record<string, { label: string; className: string; hint: string }> = {
  default: {
    label: "Built-in default",
    className: "border-border bg-surface-2 text-fg-dim",
    hint: "The protocol's own definition (SBI runs on 7777); ships with the program",
  },
  shipped: {
    label: "Built-in default",
    className: "border-border bg-surface-2 text-fg-dim",
    hint: "Field-verified experience, shipped to every user. Only takes effect when it actually decodes more messages",
  },
  auto: {
    label: "Auto-detected",
    className: "border-signal-cyan-border bg-signal-cyan-bg text-signal-cyan",
    hint: "Detected when this file was opened; applies to this capture only",
  },
  user: {
    label: "Yours",
    className: "border-signal-mint-border bg-signal-mint-bg text-signal-mint font-medium",
    hint: "Stored in your config; applied to every capture from now on",
  },
};

/**
 * Wireshark 式的「Decode As」。
 *
 * 存在的理由：自動偵測只在**載荷看起來像 HTTP/2** 時才敢猜。電信商把
 * Diameter 放在 3868 以外的埠、把 SIP 放在 5060 以外的埠時，自動偵測認
 * 不出來，而症狀是封包清單上一整片「TCP」。那時使用者要能自己說「這個埠
 * 上跑的是這個協定」。
 *
 * **套用會整份重跑**（不只重建封包清單）—— 規則會改變訊息邊界，訂戶、
 * 梯形圖、關聯矩陣全都要跟著變。只重建清單的話，清單解開了而下面三個面板
 * 還是舊的。
 */
export function DecodeAsPanel({
  rules,
  configPath,
  busy,
  error,
  promotable,
  disabled,
  shippedPath,
  onApply,
  onDisable,
  onEnable,
  onPromote,
}: {
  rules: DecodeAsRule[];
  configPath: string;
  busy: boolean;
  error: string | null;
  /** 這次自動偵測到、但還不在出貨清單裡的規則。 */
  promotable: string[];
  /** 被關掉的內建規則。 */
  disabled: string[];
  shippedPath: string;
  onApply: (userRules: string[]) => void;
  onDisable: (rule: string) => void;
  onEnable: (rule: string) => void;
  onPromote: (rules: string[]) => void;
}) {
  useLang(); // 換語言時重新渲染 —— t() 讀的是模組層級的狀態
  const [open, setOpen] = useState(false);
  const [selector, setSelector] = useState(SELECTORS[0]);
  const [value, setValue] = useState("");
  const [protocol, setProtocol] = useState(PROTOCOLS[0]);
  // 待套用的使用者規則。**與已生效的分開** —— 使用者按「套用」之前，
  // 畫面上顯示的必須還是目前真正生效的那組，不然他會以為已經改了。
  const [pending, setPending] = useState<string[] | null>(null);

  const applied = rules.filter((r) => r.origin === "user").map((r) => r.rule);
  const builtin = rules.filter((r) => r.origin === "default" || r.origin === "shipped");
  const draft = pending ?? applied;
  const dirty = pending !== null && pending.join("\n") !== applied.join("\n");

  useEffect(() => {
    // 重跑完成後，草稿回到「跟已生效的一樣」。
    if (!busy) setPending(null);
  }, [busy]);

  function add() {
    const rule = `${selector}==${value.trim()},${protocol.trim()}`;
    if (!value.trim() || !protocol.trim() || draft.includes(rule)) return;
    setPending([...draft, rule]);
    setValue("");
  }

  return (
    <div className="rounded-lg border border-border bg-surface-1">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wide text-fg-dim hover:text-fg transition-colors"
      >
        <Wrench className="h-3.5 w-3.5 text-signal-cyan" />
        {t("Decode As")}
        <span className="ml-1 font-normal normal-case tracking-normal text-fg-dim font-mono">
          {t("{n} rule(s) active", { n: rules.length })}
        </span>
        <span className="ml-auto text-fg-dim">{open ? t("Collapse ▲") : t("Expand list ▼")}</span>
      </button>

      {open && (
        <div className="space-y-3 border-t border-border p-3">
          <table className="w-full text-left text-[11px]">
            <thead className="text-fg-dim font-mono border-b border-border">
              <tr>
                <th className="pb-1 font-medium">{t("Selector")}</th>
                <th className="pb-1 font-medium">{t("Decode as")}</th>
                <th className="pb-1 font-medium">{t("Origin")}</th>
                <th className="pb-1" />
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50 font-mono">
              {builtin.map((r) => (
                <Row
                  key={r.rule}
                  rule={r}
                  // 內建的不能「刪」（下次啟動又回來），但可以關掉 ——
                  // 那是一個記錄下來的決定，存在使用者的設定檔裡。
                  onRemove={() => onDisable(r.rule)}
                  removeTitle={t("Disable this built-in rule (remembered in your config; never applied again)")}
                />
              ))}
              {rules
                .filter((r) => r.origin === "auto")
                .map((r) => (
                  <Row key={r.rule} rule={r} />
                ))}
              {draft.map((rule) => (
                <Row
                  key={rule}
                  rule={{
                    rule,
                    origin: "user",
                    selector: rule.split(",")[0],
                    protocol: rule.split(",").pop() ?? "",
                  }}
                  onRemove={() => setPending(draft.filter((r) => r !== rule))}
                />
              ))}
              {rules.length === 0 && draft.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-3 text-center text-fg-dim">
                    {t("No rules at the moment")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>

          <div className="flex flex-wrap items-end gap-1.5">
            <select
              value={selector}
              onChange={(e) => setSelector(e.target.value)}
              className="rounded border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-fg-muted focus:border-signal-cyan focus:outline-none transition-colors"
            >
              {SELECTORS.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <span className="pb-2 font-mono text-xs text-fg-dim">==</span>
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && add()}
              placeholder="8080"
              className="w-24 rounded border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-fg placeholder:text-fg-dim focus:border-signal-cyan focus:outline-none transition-colors"
            />
            <span className="pb-2 font-mono text-xs text-fg-dim">{t("Decode as")}</span>
            <input
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && add()}
              list="decode-as-protocols"
              placeholder="http2"
              className="w-28 rounded border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-fg placeholder:text-fg-dim focus:border-signal-cyan focus:outline-none transition-colors"
            />
            <datalist id="decode-as-protocols">
              {PROTOCOLS.map((p) => (
                <option key={p} value={p} />
              ))}
            </datalist>
            <button
              type="button"
              onClick={add}
              className="flex items-center gap-1 rounded border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
            >
              <Plus className="h-3 w-3" />
              {t("Add")}
            </button>
          </div>

          {error && (
            // tshark 自己的訊息，原樣顯示 —— 那是使用者要據以修正的東西。
            // **可捲動而不是截斷。** tshark 對「未知協定」會把全部可用的
            // 協定名列出來 —— 那是一面牆，但也正是修正指示本身。截掉它等於
            // 把答案藏起來。
            <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded border border-signal-red-border bg-signal-red-bg p-2 font-mono text-[11px] text-signal-red-fg">
              {error}
            </pre>
          )}

          {disabled.length > 0 && (
            // **關掉的規則要看得見。** 只是從表上消失的話，使用者三個月後
            // 遇到同一種擷取檔解不開，不會想到是自己關過。
            <div className="rounded border border-border bg-surface-2/60 p-2.5">
              <p className="text-[11px] text-fg-dim">{t("Disabled built-in rules")}</p>
              <ul className="mt-1 space-y-1">
                {disabled.map((rule) => (
                  <li key={rule} className="flex items-center gap-2 font-mono text-[11px] text-fg-dim">
                    <span className="line-through">{rule}</span>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => onEnable(rule)}
                      className="rounded border border-border px-2 py-0.5 text-[10px] not-italic text-fg-muted hover:border-signal-cyan hover:text-signal-cyan disabled:opacity-50 transition-colors"
                    >
                      {t("Re-enable")}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {promotable.length > 0 && (
            // **這是「把我驗證過的經驗傳給別人」那個動作。**
            // 使用者規則存在 ~/.config，那不會跟著程式走；出貨清單在版控裡，
            // 所以要 commit 才會真的給到別人 —— 這件事必須講出來。
            <div className="rounded border border-signal-mint-border bg-signal-mint-bg/30 p-2.5">
              <p className="text-[11px] leading-relaxed text-signal-mint font-medium">
                {t("Auto-detection found {n} rule(s) not yet adopted. Once adopted they ", { n: promotable.length })}
                <strong className="font-semibold">{t("ship with the program to every user")}</strong>
                {t(", so the next person opening a similar capture does not hit the same wall.")}
              </p>
              <p className="mt-1 font-mono text-[11px] text-signal-mint/80">
                {promotable.join("　")}
              </p>
              <button
                type="button"
                disabled={busy}
                onClick={() => onPromote(promotable)}
                className="mt-2 flex items-center gap-1.5 rounded border border-signal-mint-border px-2.5 py-1 text-[11px] font-medium text-signal-mint hover:bg-signal-mint-bg disabled:opacity-50 transition-colors"
              >
                <Plus className="h-3 w-3" />
                {t("Adopt as built-in default")}
              </button>
              <p className="mt-1.5 text-[10px] leading-relaxed text-fg-dim">
                {t("Writes to ")}<code className="text-fg-muted">{t(shippedPath)}</code>{t(" (a file under version control - it reaches others only after a commit). Adopted rules are still only ")}
                <strong className="font-semibold text-fg-muted">{t("candidates")}</strong>
                {t(" - on someone else's capture they withdraw themselves if they do not decode more messages, so they cannot break their file.")}
              </p>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={!dirty || busy}
              onClick={() => onApply(draft)}
              className={cn(
                "flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium transition-colors",
                dirty && !busy
                  ? "bg-signal-cyan-bg text-signal-cyan border border-signal-cyan-border hover:bg-signal-cyan-bg/80 shadow-sm"
                  : "cursor-not-allowed bg-surface-2 text-fg-dim border border-border/40",
              )}
            >
              {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <RotateCw className="h-3 w-3" />}
              {busy ? t("Re-running…") : t("Apply & re-run")}
            </button>
            {dirty && !busy && (
              <button
                type="button"
                onClick={() => setPending(null)}
                className="text-[11px] text-fg-dim hover:text-fg-muted transition-colors"
              >
                {t("Discard changes")}
              </button>
            )}
            <p className="text-[11px] leading-relaxed text-fg-dim">
              {t("Applying ")}<strong className="font-semibold text-fg-muted">{t("re-runs the whole analysis")}</strong>{t(" (minutes on a large file) - rules change message boundaries, so subscribers, the ladder and the matrix all change with them.")}
              <br />
              {t("Your rules live in ")}<code className="text-fg-muted">{t(configPath)}</code>{t(" and apply to every capture from now on.")}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

function Row({
  rule,
  onRemove,
  removeTitle,
}: {
  rule: DecodeAsRule;
  onRemove?: () => void;
  removeTitle?: string;
}) {
  useLang();
  const removeLabel = removeTitle ?? t("Remove this rule");
  const meta = ORIGIN_META[rule.origin] ?? ORIGIN_META.default;
  return (
    <tr>
      <td className="py-1 text-fg-muted">{rule.selector}</td>
      <td className="py-1 text-signal-cyan font-medium">{rule.protocol}</td>
      <td className="py-1">
        <span
          className={cn("rounded-full border px-2 py-0.5 text-[10px]", meta.className)}
          title={rule.note ? `${t(meta.hint)}\n\n${rule.note}` : t(meta.hint)}
        >
          {t(meta.label)}
        </span>
      </td>
      <td className="py-1 text-right">
        {onRemove ? (
          <button
            type="button"
            onClick={onRemove}
            title={removeLabel}
            className="rounded p-1 text-fg-dim hover:bg-surface-hover hover:text-signal-red transition-colors"
          >
            <Trash2 className="h-3 w-3" />
          </button>
        ) : (
          <span className="inline-block h-3 w-3" />
        )}
      </td>
    </tr>
  );
}
