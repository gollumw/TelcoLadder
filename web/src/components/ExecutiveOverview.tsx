"use client";

import { t, useLang } from "../i18n";
import { AlertTriangle, ArrowUpRight, Binary, CheckCircle2, EyeOff, LayoutList, Loader2, ShieldAlert, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Overview, OverviewCause, OverviewProcedure } from "@/data/source";

/**
 * 首屏總覽 —— 給第一眼看這份檔的人：健不健康、誰失敗、為什麼、依據哪條。
 *
 * **這個元件只排版，不算任何數字。** 每個數字都是後端 `/overview` 對全母體
 * 算好的（`telcoladder/overview.py`）；在瀏覽器裡聚合會隨載入狀態改變，而且
 * 不報錯（見 `Overview` 型別的說明）。
 *
 * **沒有分數。** 沒有 0–100 的健康度：權重是編的，而編出來的數字在畫面上跟
 * 量出來的一樣可信。標題只講最差的那盞燈是什麼顏色，底下的每個數字都指得回
 * 工作階段表或程序清單的某一列。
 *
 * **「看不見什麼」排在結論之前。** 一份只抓到 N2 的檔，核網內部的失敗根本
 * 不在檔案裡 —— 不先講這件事，「0 個失敗」會被讀成「網路沒問題」。
 *
 * **常見根因叫常見根因。** `commonCauses` 是 cause 表裡人寫的現場經驗，
 * 不是本工具對這份檔的處置建議 —— 標題與註腳都要說清楚。
 */

const VERDICT_STYLE: Record<Overview["verdict"], { icon: typeof ShieldCheck; box: string; text: string }> = {
  red: { icon: ShieldAlert, box: "border-signal-red-border bg-signal-red-bg", text: "text-signal-red" },
  amber: { icon: AlertTriangle, box: "border-signal-amber-border bg-signal-amber-bg", text: "text-signal-amber" },
  green: { icon: ShieldCheck, box: "border-signal-mint-border bg-signal-mint-bg", text: "text-signal-mint" },
  empty: { icon: EyeOff, box: "border-border bg-surface-2", text: "text-fg-dim" },
};

//: 標題句只講事實。**紅燈不等於「網路壞了」** —— 一次認證重同步後成功註冊
//: 也是紅燈（有失敗訊息），所以措辭是「觀察到失敗」，不是「嚴重異常」。
const VERDICT_TEXT: Record<Overview["verdict"], string> = {
  red: "Failures observed in this capture",
  amber: "No failures, but some requests went unanswered or were retransmitted",
  green: "No anomalies in what could be decoded",
  empty: "Nothing in this capture was decoded as signalling",
};

export function ExecutiveOverview({
  overview,
  error,
  onOpenLadder,
  onOpenPacket,
}: {
  /** null＝還在算。 */
  overview: Overview | null;
  error: string | null;
  /** 開某個訂戶的梯形圖，並選中那一格。把手是 SUPI 數字或 `kind:raw`。 */
  onOpenLadder: (handle: string, frame: number) => void;
  /** 到封包清單選中那一格。 */
  onOpenPacket: (frame: number) => void;
}) {
  useLang(); // 換語言時重新渲染 —— t() 讀的是模組層級的狀態

  if (error) {
    return (
      <div className="rounded-lg border border-signal-red-border bg-signal-red-bg p-4 text-sm text-signal-red-fg">
        <p className="font-semibold">{t("The overview could not be loaded")}</p>
        <p className="mt-1 text-xs text-fg-muted">{error}</p>
      </div>
    );
  }
  if (!overview) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-border bg-surface-1 p-6 text-sm text-fg-muted">
        <Loader2 className="h-4 w-4 animate-spin text-signal-cyan" />
        {t("Computing the overview…")}
      </div>
    );
  }

  const v = VERDICT_STYLE[overview.verdict];
  const Icon = v.icon;
  const { subscribers, procedures, events, notVisible } = overview;

  return (
    <div className="space-y-4">
      {/* 一眼：最差的那盞燈是什麼顏色，以及它是怎麼算的 */}
      <section className={cn("rounded-lg border p-4", v.box)}>
        <div className="flex flex-wrap items-center gap-3">
          <Icon className={cn("h-6 w-6", v.text)} />
          <div>
            <h2 className={cn("text-base font-semibold", v.text)}>{t(VERDICT_TEXT[overview.verdict])}</h2>
            <p className="mt-0.5 text-xs text-fg-muted">
              {t("{red} red · {amber} amber · {green} green of {total} subscriber(s)", {
                red: subscribers.red, amber: subscribers.amber, green: subscribers.green, total: subscribers.total,
              })}
              {subscribers.unattributedFlows > 0 && (
                <span className="ml-2">
                  {t("· {n} flow(s) could not be attributed to any subscriber", { n: subscribers.unattributedFlows })}
                </span>
              )}
            </p>
          </div>
        </div>
        <p className="mt-2 text-[11px] leading-relaxed text-fg-dim">
          {t("Every light and count on this page points back to a row in the session table or the procedure list. Nothing here is scored or weighted.")}
        </p>
      </section>

      {/* 看不見什麼 —— 在所有數字之前 */}
      <NotVisiblePanel nv={notVisible} />

      {/* 數字：全部是引擎的計數 */}
      <section className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Tile
          label={t("Subscribers")}
          value={subscribers.total}
          sub={t("{red} red · {amber} amber · {green} green", { red: subscribers.red, amber: subscribers.amber, green: subscribers.green })}
          tone={subscribers.red ? "red" : subscribers.amber ? "amber" : "neutral"}
        />
        <Tile
          label={t("Procedures")}
          value={procedures.total}
          sub={t("{s} succeeded · {f} failed · {i} incomplete", { s: procedures.success, f: procedures.failure, i: procedures.incomplete })}
          tone={procedures.failure ? "red" : procedures.incomplete ? "amber" : "neutral"}
        />
        <Tile label={t("Failure messages")} value={events.failures} tone={events.failures ? "red" : "neutral"} />
        <Tile
          label={t("Unanswered requests")}
          value={events.unanswered}
          sub={t("no answer within the capture - not necessarily a timeout")}
          tone={events.unanswered ? "amber" : "neutral"}
        />
        <Tile label={t("Retransmissions")} value={events.retrans} tone={events.retrans ? "amber" : "neutral"} />
        <Tile
          label={t("Frames not decoded")}
          value={notVisible.framesNotDecoded === null ? "—" : notVisible.framesNotDecoded}
          sub={notVisible.framesNotDecoded === null ? t("not measured") : undefined}
          tone={notVisible.framesNotDecoded ? "amber" : "neutral"}
        />
      </section>

      {/* 失敗，依 cause 歸卡 */}
      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-fg">
          {t("Failures, grouped by cause")}
          <span className="ml-2 text-xs font-normal text-fg-dim">{t("{n} distinct cause(s)", { n: overview.causes.length })}</span>
        </h3>
        {overview.causes.length === 0 ? (
          <p className="rounded-lg border border-border bg-surface-1 p-4 text-xs text-fg-dim">
            <CheckCircle2 className="mr-1.5 inline h-3.5 w-3.5 text-signal-mint" />
            {t("No failure message in this capture - within the limits listed above.")}
          </p>
        ) : (
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            {overview.causes.map((cause) => (
              <CauseCard key={cause.key} cause={cause} onOpenLadder={onOpenLadder} onOpenPacket={onOpenPacket} />
            ))}
          </div>
        )}
      </section>

      {/* 失敗收場的程序 */}
      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-fg">
          {t("Procedures that ended in failure")}
          <span className="ml-2 text-xs font-normal text-fg-dim">{overview.failedProcedures.length}</span>
        </h3>
        {overview.failedProcedures.length === 0 ? (
          <p className="rounded-lg border border-border bg-surface-1 p-4 text-xs text-fg-dim">
            {t("No procedure ended in failure. A failure message followed by a successful outcome counts as recovered, not failed.")}
          </p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border bg-surface-1">
            <table className="w-full text-left text-xs">
              <thead className="bg-surface-2 text-[11px] uppercase tracking-wide text-fg-dim">
                <tr>
                  <th className="px-3 py-2 font-medium">{t("Procedure")}</th>
                  <th className="px-3 py-2 font-medium">{t("Subscriber")}</th>
                  <th className="px-3 py-2 font-medium">{t("Frames")}</th>
                  <th className="px-3 py-2 font-medium">{t("First failure")}</th>
                  <th className="px-3 py-2 font-medium">{t("Terminal cause")}</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>
                {overview.failedProcedures.map((p) => (
                  <ProcedureRow key={`${p.startFrame}-${p.subscriber?.handle ?? ""}`} p={p} onOpenLadder={onOpenLadder} onOpenPacket={onOpenPacket} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function Tile({ label, value, sub, tone }: { label: string; value: number | string; sub?: string; tone: "red" | "amber" | "neutral" }) {
  return (
    <div className="rounded-lg border border-border bg-surface-1 p-3">
      <p className="text-[11px] uppercase tracking-wide text-fg-dim">{label}</p>
      <p className={cn("mt-1 text-2xl font-semibold tabular-nums", tone === "red" ? "text-signal-red" : tone === "amber" ? "text-signal-amber" : "text-fg")}>
        {value}
      </p>
      {sub && <p className="mt-0.5 text-[11px] leading-snug text-fg-dim">{sub}</p>}
    </div>
  );
}

function NotVisiblePanel({ nv }: { nv: Overview["notVisible"] }) {
  const items: string[] = [];
  if (nv.cipheredNas > 0) items.push(t("{n} NAS message(s) are ciphered; a failure inside them is invisible here.", { n: nv.cipheredNas }));
  if (nv.protectedSuci > 0) items.push(t("{n} SUCI(s) are ECIES-protected; the SUPI cannot be recovered even in principle.", { n: nv.protectedSuci }));
  if (nv.onlyN2) items.push(t("Only N2 (gNB↔AMF) is in this file. The core network's own signalling (SBI, N4) is not here, so its failures cannot be seen."));
  // 沒解碼的流量**不在這裡另寫一句** —— 引擎的 coverage 句子（`nv.notes`）已經講了
  // 是哪個埠、幾格、加參數救不救得回來。同一件事兩種措辭，就是會漂移的那種。
  const all = [...items, ...nv.notes];
  return (
    <section className="rounded-lg border border-signal-amber-border bg-signal-amber-bg/60 p-3">
      <p className="flex items-center gap-1.5 text-xs font-semibold text-signal-amber">
        <EyeOff className="h-3.5 w-3.5" />
        {t("What this capture cannot show")}
      </p>
      {all.length === 0 ? (
        <p className="mt-1 text-[11px] text-fg-muted">{t("Everything in this capture was decoded; the numbers below cover the whole file.")}</p>
      ) : (
        <ul className="mt-1 list-disc space-y-0.5 pl-5 text-[11px] leading-relaxed text-fg-muted">
          {all.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      )}
    </section>
  );
}

function CauseCard({
  cause,
  onOpenLadder,
  onOpenPacket,
}: {
  cause: OverviewCause;
  onOpenLadder: (handle: string, frame: number) => void;
  onOpenPacket: (frame: number) => void;
}) {
  const first = cause.subscribers[0];
  return (
    <article className="flex flex-col rounded-lg border border-signal-red-border bg-surface-1 p-3">
      <header className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          {/* 出處先於一切：名稱、號碼、規範、條號 —— 查不到時是引擎那句「還沒收錄」 */}
          <p className="text-sm font-semibold text-signal-red">{cause.citation ?? cause.message}</p>
          <p className="mt-0.5 font-mono text-[11px] text-fg-dim">
            {cause.protocol} · {cause.message}
          </p>
        </div>
        <span className="shrink-0 rounded-full border border-border bg-surface-2 px-2 py-0.5 text-[11px] tabular-nums text-fg-muted">
          {t("{n} occurrence(s) · {m} subscriber(s)", { n: cause.count, m: cause.subscribers.length })}
        </span>
      </header>

      {cause.explanation ? (
        <p className="mt-2 text-xs leading-relaxed text-fg">{cause.explanation}</p>
      ) : (
        <p className="mt-2 text-xs italic text-fg-dim">{t("No plain-language explanation is catalogued for this cause.")}</p>
      )}

      {cause.commonCauses.length > 0 && (
        <div className="mt-2 rounded border border-border bg-surface-2 p-2">
          <p className="text-[11px] font-semibold text-fg-muted">{t("Most common root causes (field experience)")}</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[11px] leading-relaxed text-fg-muted">
            {cause.commonCauses.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
          <p className="mt-1.5 text-[10px] text-fg-dim">
            {t("From the cause table, written by people - what usually causes this code in the field, not a diagnosis of this capture.")}
          </p>
        </div>
      )}

      {cause.subscribers.length > 0 && (
        <div className="mt-2">
          <p className="text-[11px] text-fg-dim">{t("Affected subscribers")}</p>
          <div className="mt-1 flex flex-wrap gap-1">
            {cause.subscribers.map((s) => (
              <button
                key={s.handle}
                type="button"
                onClick={() => onOpenLadder(s.handle, s.frame ?? cause.frames[0])}
                title={t("Open this subscriber's ladder at the failing message")}
                className="rounded border border-border bg-surface-2 px-2 py-0.5 font-mono text-[11px] text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>
      )}

      <footer className="mt-3 flex flex-wrap gap-2">
        {first && (
          <button
            type="button"
            onClick={() => onOpenLadder(first.handle, first.frame ?? cause.frames[0])}
            className="flex items-center gap-1.5 rounded border border-signal-cyan-border bg-signal-cyan-bg px-2.5 py-1 text-[11px] font-medium text-signal-cyan hover:bg-signal-cyan/20 transition-colors"
          >
            <LayoutList className="h-3 w-3" />
            {t("Open in ladder")}
            <ArrowUpRight className="h-3 w-3" />
          </button>
        )}
        <button
          type="button"
          onClick={() => onOpenPacket(cause.frames[0])}
          className="flex items-center gap-1.5 rounded border border-border bg-surface-2 px-2.5 py-1 text-[11px] font-medium text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
        >
          <Binary className="h-3 w-3" />
          {t("Open packet #{n}", { n: cause.frames[0] })}
        </button>
      </footer>
    </article>
  );
}

function ProcedureRow({
  p,
  onOpenLadder,
  onOpenPacket,
}: {
  p: OverviewProcedure;
  onOpenLadder: (handle: string, frame: number) => void;
  onOpenPacket: (frame: number) => void;
}) {
  return (
    <tr className="border-t border-border align-top">
      <td className="px-3 py-2 font-mono text-fg">
        {p.kind}
        {p.pduSessionId && <span className="ml-1 text-fg-dim">#{p.pduSessionId}</span>}
      </td>
      <td className="px-3 py-2 font-mono text-fg-muted">{p.subscriber?.label ?? "—"}</td>
      <td className="px-3 py-2 font-mono tabular-nums text-fg-dim">
        {p.startFrame}–{p.endFrame}
      </td>
      {/* 起因與終端原因**並列**：ki-mismatch 的終端 cause 是零資訊量的「協定錯誤」，
          起因才是「SQN 不同步」。只給終端會把人帶去追一個不存在的故障。 */}
      <td className="px-3 py-2 text-signal-amber">{p.firstFailure ?? <span className="text-fg-dim">—</span>}</td>
      <td className="px-3 py-2 text-signal-red">{p.cause ?? <span className="text-fg-dim">—</span>}</td>
      <td className="px-3 py-2">
        <div className="flex gap-1">
          {p.subscriber && (
            <button
              type="button"
              onClick={() => onOpenLadder(p.subscriber!.handle, p.startFrame)}
              title={t("Open in ladder")}
              className="rounded border border-border bg-surface-2 p-1 text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
            >
              <LayoutList className="h-3 w-3" />
            </button>
          )}
          <button
            type="button"
            onClick={() => onOpenPacket(p.startFrame)}
            title={t("Open packet #{n}", { n: p.startFrame })}
            className="rounded border border-border bg-surface-2 p-1 text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
          >
            <Binary className="h-3 w-3" />
          </button>
        </div>
      </td>
    </tr>
  );
}
