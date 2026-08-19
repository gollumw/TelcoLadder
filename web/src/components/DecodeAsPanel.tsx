"use client";

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
    label: "內建預設",
    className: "border-slate-600 bg-slate-700/40 text-slate-300",
    hint: "adapter 自己宣告的，不能刪",
  },
  auto: {
    label: "自動偵測",
    className: "border-sky-500/40 bg-sky-500/10 text-sky-300",
    hint: "這次開檔時偵測到的，只對這份擷取檔有效",
  },
  user: {
    label: "你設定的",
    className: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
    hint: "存在設定檔裡，以後每份擷取檔都會套用",
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
  onApply,
}: {
  rules: DecodeAsRule[];
  configPath: string;
  busy: boolean;
  error: string | null;
  onApply: (userRules: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const [selector, setSelector] = useState(SELECTORS[0]);
  const [value, setValue] = useState("");
  const [protocol, setProtocol] = useState(PROTOCOLS[0]);
  // 待套用的使用者規則。**與已生效的分開** —— 使用者按「套用」之前，
  // 畫面上顯示的必須還是目前真正生效的那組，不然他會以為已經改了。
  const [pending, setPending] = useState<string[] | null>(null);

  const applied = rules.filter((r) => r.origin === "user").map((r) => r.rule);
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
    <div className="rounded-lg border border-slate-800 bg-slate-900/60">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wide text-slate-400 hover:text-slate-200"
      >
        <Wrench className="h-3.5 w-3.5" />
        Decode As · 解碼方式
        <span className="ml-1 font-normal normal-case tracking-normal text-slate-600">
          {rules.length} 條規則生效中
        </span>
        <span className="ml-auto text-slate-500">{open ? "收合 ▲" : "展開 ▼"}</span>
      </button>

      {open && (
        <div className="space-y-3 border-t border-slate-800 p-3">
          <table className="w-full text-left text-[11px]">
            <thead className="text-slate-500">
              <tr>
                <th className="pb-1 font-medium">選擇器</th>
                <th className="pb-1 font-medium">解成</th>
                <th className="pb-1 font-medium">來源</th>
                <th className="pb-1" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {rules
                .filter((r) => r.origin !== "user")
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
                  <td colSpan={4} className="py-3 text-center text-slate-600">
                    目前沒有任何規則
                  </td>
                </tr>
              )}
            </tbody>
          </table>

          <div className="flex flex-wrap items-end gap-1.5">
            <select
              value={selector}
              onChange={(e) => setSelector(e.target.value)}
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 font-mono text-xs text-slate-300 focus:border-sky-500 focus:outline-none"
            >
              {SELECTORS.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <span className="pb-2 font-mono text-xs text-slate-500">==</span>
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && add()}
              placeholder="8080"
              className="w-24 rounded border border-slate-700 bg-slate-950 px-2 py-1.5 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-sky-500 focus:outline-none"
            />
            <span className="pb-2 font-mono text-xs text-slate-500">解成</span>
            <input
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && add()}
              list="decode-as-protocols"
              placeholder="http2"
              className="w-28 rounded border border-slate-700 bg-slate-950 px-2 py-1.5 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-sky-500 focus:outline-none"
            />
            <datalist id="decode-as-protocols">
              {PROTOCOLS.map((p) => (
                <option key={p} value={p} />
              ))}
            </datalist>
            <button
              type="button"
              onClick={add}
              className="flex items-center gap-1 rounded border border-slate-700 px-2.5 py-1.5 text-xs text-slate-300 hover:border-sky-500 hover:text-sky-300"
            >
              <Plus className="h-3 w-3" />
              加入
            </button>
          </div>

          {error && (
            // tshark 自己的訊息，原樣顯示 —— 那是使用者要據以修正的東西。
            // **可捲動而不是截斷。** tshark 對「未知協定」會把全部可用的
            // 協定名列出來 —— 那是一面牆，但也正是修正指示本身。截掉它等於
            // 把答案藏起來。
            <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded border border-rose-500/30 bg-rose-500/5 p-2 font-mono text-[11px] text-rose-300">
              {error}
            </pre>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={!dirty || busy}
              onClick={() => onApply(draft)}
              className={cn(
                "flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium",
                dirty && !busy
                  ? "bg-sky-500/20 text-sky-200 hover:bg-sky-500/30"
                  : "cursor-not-allowed bg-slate-800 text-slate-600",
              )}
            >
              {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <RotateCw className="h-3 w-3" />}
              {busy ? "重跑中……" : "套用並重跑"}
            </button>
            {dirty && !busy && (
              <button
                type="button"
                onClick={() => setPending(null)}
                className="text-[11px] text-slate-500 hover:text-slate-300"
              >
                取消變更
              </button>
            )}
            <p className="text-[11px] leading-relaxed text-slate-500">
              套用會<strong className="font-semibold text-slate-400">整份重跑</strong>（大檔要幾分鐘）——
              規則會改變訊息邊界，訂戶、梯形圖與關聯矩陣都要跟著變。
              <br />
              你設定的規則存在 <code className="text-slate-400">{configPath}</code>，以後每份擷取檔都會套用。
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

function Row({ rule, onRemove }: { rule: DecodeAsRule; onRemove?: () => void }) {
  const meta = ORIGIN_META[rule.origin] ?? ORIGIN_META.default;
  return (
    <tr>
      <td className="py-1 text-slate-300">{rule.selector}</td>
      <td className="py-1 text-violet-300">{rule.protocol}</td>
      <td className="py-1">
        <span
          className={cn("rounded-full border px-2 py-0.5 text-[10px]", meta.className)}
          title={meta.hint}
        >
          {meta.label}
        </span>
      </td>
      <td className="py-1 text-right">
        {onRemove ? (
          <button
            type="button"
            onClick={onRemove}
            title="移除這條規則"
            className="rounded p-1 text-slate-500 hover:bg-slate-800 hover:text-rose-300"
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
