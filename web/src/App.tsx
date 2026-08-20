/**
 * 外層殼：負責「把資料拿到手」，拿到之前與拿不到時要說什麼。
 *
 * `SessionAnalyzer` 保持「吃資料、不取資料」—— 它與底下 6 個元件仍然是
 * 對四個陣列的純函式運算，可以用假資料單獨測試。Phase 3 換後端時
 * 不會碰到任何一個 View。
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";

import SessionAnalyzer from "@/components/SessionAnalyzer";
import { apiSource } from "@/data/apiSource";
import { mockSource } from "@/data/mockSource";
import {
  currentSid,
  wantsApiSource,
  type DataSource,
  type Dataset,
  type CallFlow,
  type DecodeAsState,
  type PacketPage,
} from "@/data/source";
import type { ProtocolNode, RawPacket } from "@/lib/types";

function pickSource(): DataSource {
  return wantsApiSource() ? apiSource(currentSid()) : mockSource();
}

/**
 * 一次抓幾列。與舊檢視器 `viewer.js` 的 `PAGE` 同一個值 —— 那套虛擬滾動
 * 在這個 codebase 的真實擷取檔上驗過（436 MB / 250 萬封包）。
 */
const ROW_PAGE = 200;

/** 封包清單的狀態：稀疏的列 ＋ 總數。列的鍵是**篩選後的序位**，不是 frame 編號。 */
interface PacketStore {
  rows: Record<number, RawPacket>;
  totals: Omit<PacketPage, "rows" | "offset">;
}

export default function App() {
  const [source] = useState<DataSource>(pickSource);
  const [data, setData] = useState<Dataset | null>(null);
  const [error, setError] = useState<Error | null>(null);
  // 已取到的原始位元組。放在這裡而不是元件裡，是為了讓元件維持
  // 「吃資料、不取資料」—— 它只會呼叫一個注入進去的函式，不知道有 HTTP。
  const [bytesByFrame, setBytesByFrame] = useState<Record<number, string | null>>({});
  const [treeByFrame, setTreeByFrame] = useState<Record<number, ProtocolNode[] | null>>({});
  /** 已取到的梯形圖，一個訂戶一份。 */
  const [flowBySupi, setFlowBySupi] = useState<Record<string, CallFlow | null>>({});
  /** 目前顯示的是誰的梯形圖 —— 決定要把哪一份交下去。 */
  const [flowSupi, setFlowSupi] = useState<string | null>(null);
  const [packets, setPackets] = useState<PacketStore | null>(null);
  /** display filter 的語法錯誤。**不是**整頁的錯誤 —— 打錯字不該把畫面清空。 */
  const [filterError, setFilterError] = useState<string | null>(null);
  const [decodeAs, setDecodeAs] = useState<DecodeAsState>({
    rules: [],
    promotable: [],
    disabled: [],
    configPath: "",
    shippedPath: "",
  });
  const [decodeAsError, setDecodeAsError] = useState<string | null>(null);
  /** 套用規則後整份重跑中。期間不接受第二次套用 —— 兩趟會搶同一份檔。 */
  const [rerunning, setRerunning] = useState(false);
  /** 正在取的頁（以 offset 為鍵）。防止同一頁被重複請求。 */
  const inFlight = useRef<Set<number>>(new Set());
  /**
   * 過濾條件的版次。每次條件變動就 +1；回應帶著發出時的版次回來，
   * 對不上就丟掉。
   *
   * 沒有這個守衛時：使用者連續改兩次過濾，兩個請求誰先回來不保證，
   * 慢的那個後到就會把畫面蓋回舊條件的結果 —— 而畫面上的過濾框寫的是
   * 新條件。舊檢視器用的是同一招（`viewer.js` 的 `railSeq`）。
   */
  const generation = useRef(0);

  useEffect(() => {
    let cancelled = false;
    source
      .load()
      .then((loaded) => {
        if (cancelled) return;
        setData(loaded);
        const { rows, offset, ...totals } = loaded.page;
        setPackets({
          rows: Object.fromEntries(rows.map((row, i) => [offset + i, row])),
          totals,
        });
        void source.loadDecodeAs().then((state) => {
          if (!cancelled) setDecodeAs(state);
        });
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err : new Error(String(err)));
      });
    return () => {
      cancelled = true;
    };
  }, [source]);

  /**
   * 補齊 [first, first+count) 這段裡缺的列。
   *
   * **一次只補第一個缺口那一頁**，比照 `viewer.js:145`：快速捲動會掃過
   * 上百頁，每一格都發請求會打爆後端，而使用者最後只會停在一個位置。
   * 停下來時 `draw` 會再叫一次，缺的那頁自然補上。
   */
  const requestRows = useCallback(
    (first: number, count: number) => {
      setPackets((current) => {
        if (!current) return current;
        for (let i = first; i < first + count && i < current.totals.matched; i++) {
          if (i in current.rows) continue;
          const offset = Math.floor(i / ROW_PAGE) * ROW_PAGE;
          if (inFlight.current.has(offset)) break;
          inFlight.current.add(offset);
          const mine = generation.current;
          void source
            .loadPacketPage(offset, ROW_PAGE)
            .then((page) => {
              inFlight.current.delete(offset);
              // 條件已經換過了 —— 這頁是舊條件下的序位，貼上去會錯位。
              if (mine !== generation.current) return;
              setPackets((c) =>
                c === null
                  ? c
                  : {
                      rows: {
                        ...c.rows,
                        ...Object.fromEntries(
                          page.rows.map((row, k) => [page.offset + k, row]),
                        ),
                      },
                      // 索引還在跑時 matched 會長，順手更新。
                      totals: { ...c.totals, matched: page.matched, indexed: page.indexed },
                    },
              );
            })
            .catch(() => {
              inFlight.current.delete(offset);
            });
          break;
        }
        return current;
      });
    },
    [source],
  );

  /** 條件變動後重取第一頁。已載入的列全部作廢 —— 它們的序位是舊條件下的。 */
  const reloadPackets = useCallback(async () => {
    generation.current += 1;
    const mine = generation.current;
    inFlight.current.clear();
    const page = await source.loadPacketPage(0, ROW_PAGE);
    if (mine !== generation.current) return;
    const { rows, offset, ...totals } = page;
    setPackets({
      rows: Object.fromEntries(rows.map((row, i) => [offset + i, row])),
      totals,
    });
  }, [source]);

  const applyDisplayFilter = useCallback(
    (expr: string) => {
      setFilterError(null);
      void source
        .applyDisplayFilter(expr)
        .then(reloadPackets)
        .catch((err: unknown) => {
          // 語法錯誤原樣顯示（含 tshark 指到出錯位置的 caret）。**不清空
          // 封包清單** —— 打錯一個字就把畫面清掉，會讓人以為是過濾結果為零。
          setFilterError(err instanceof Error ? err.message : String(err));
        });
    },
    [source, reloadPackets],
  );

  const restrictToSupi = useCallback(
    (supi: string | null) => {
      void source.focusIdentity(supi).then(reloadPackets).catch(() => {});
    },
    [source, reloadPackets],
  );

  /**
   * 換掉解碼規則並整份重跑。
   *
   * 重跑之後**所有東西都作廢** —— 封包清單、解碼樹、位元組、梯形圖、
   * 矩陣全是用舊規則算的。所以這裡不是「更新一部分」，是把整個資料層
   * 重新載入一次；少清哪一塊，那一塊就會用舊規則的內容繼續顯示。
   */
  const applyDecodeAs = useCallback(
    (rules: string[], options?: { disabled?: string[]; promote?: string[] }) => {
      setDecodeAsError(null);
      setRerunning(true);
      void source
        .applyDecodeAs(rules, options)
        .then(() => source.load())
        .then((loaded) => {
          setData(loaded);
          const { rows, offset, ...totals } = loaded.page;
          setPackets({
            rows: Object.fromEntries(rows.map((row, i) => [offset + i, row])),
            totals,
          });
          setBytesByFrame({});
          setTreeByFrame({});
          setFlowBySupi({});
          setFilterError(null);
          return source.loadDecodeAs().then(setDecodeAs);
        })
        .catch((err: unknown) => {
          setDecodeAsError(err instanceof Error ? err.message : String(err));
        })
        .finally(() => setRerunning(false));
    },
    [source],
  );

  const requestCallFlow = useCallback(
    (supi: string) => {
      setFlowSupi(supi);
      setFlowBySupi((current) => {
        if (supi in current) return current;
        void source
          .loadCallFlow(supi)
          .then((flow) => setFlowBySupi((c) => ({ ...c, [supi]: flow })))
          .catch(() => setFlowBySupi((c) => ({ ...c, [supi]: null })));
        return { ...current, [supi]: null };
      });
    },
    [source],
  );

  const requestBytes = useCallback(
    (frame: number) => {
      if (!source.loadFrameBytes) return;
      // 已經問過就不再問 —— 包含問到 null（那格真的沒有）的情況。
      setBytesByFrame((current) => {
        if (frame in current) return current;
        void source
          .loadFrameBytes!(frame)
          .then((hex) => setBytesByFrame((c) => ({ ...c, [frame]: hex })))
          .catch(() => setBytesByFrame((c) => ({ ...c, [frame]: null })));
        return { ...current, [frame]: null };
      });
    },
    [source],
  );

  const requestTree = useCallback(
    (frame: number) => {
      if (!source.loadDecodeTree) return;
      setTreeByFrame((current) => {
        if (frame in current) return current;
        void source
          .loadDecodeTree!(frame)
          .then((tree) => setTreeByFrame((c) => ({ ...c, [frame]: tree })))
          .catch(() => setTreeByFrame((c) => ({ ...c, [frame]: null })));
        return { ...current, [frame]: null };
      });
    },
    [source],
  );

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 p-6">
        <div className="max-w-xl rounded-lg border border-rose-500/30 bg-rose-500/5 p-5">
          <div className="flex items-center gap-2 text-rose-300">
            <AlertTriangle className="h-4 w-4" />
            <span className="text-sm font-semibold">讀不到資料</span>
          </div>
          {/* 講出實際原因，不要縮成「發生錯誤」—— 使用者要能據此判斷
              是自己弄錯了，還是工具還沒做到。 */}
          <p className="mt-2 text-sm leading-relaxed text-slate-300">{error.message}</p>
          <p className="mt-3 text-xs text-slate-500">
            來源：{source.label}
            {wantsApiSource() && "　·　拿掉網址的 ?source=api 可以看內建範例資料"}
          </p>
        </div>
      </div>
    );
  }

  if (!data || !packets) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950">
        <div className="flex items-center gap-2 text-sm text-slate-400">
          <Loader2 className="h-4 w-4 animate-spin" />
          載入{source.label}……
        </div>
      </div>
    );
  }

  return (
    <>
      {data.autoDecode.length > 0 && (
        // 與 coverage 是一組的：一個說「我沒看到什麼」，這個說「我為了
        // 看到它做了什麼」。只印前者，使用者不知道結果已經被調整過。
        <div className="border-b border-sky-500/30 bg-sky-500/10 px-4 py-2 text-xs text-sky-200">
          <p className="font-semibold">這份擷取檔的解碼方式經過自動調整</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-5 leading-relaxed">
            {data.autoDecode.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      )}
      {source.notice && (
        // 常駐橫幅，不是可關閉的提示 —— 使用者每一眼看到的畫面都少了東西，
        // 那件事不該只在載入時說一次。
        <div className="border-b border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-200">
          {source.notice}
        </div>
      )}
      <SessionAnalyzer
        data={data}
        packetRows={packets.rows}
        packetTotals={packets.totals}
        onNeedRows={requestRows}
        onApplyDisplayFilter={applyDisplayFilter}
        onRestrictToSupi={restrictToSupi}
        filterError={filterError}
        callFlow={flowSupi ? (flowBySupi[flowSupi] ?? null) : null}
        onRequestCallFlow={requestCallFlow}
        decodeAs={decodeAs}
        decodeAsError={decodeAsError}
        decodeAsBusy={rerunning}
        onApplyDecodeAs={applyDecodeAs}
        bytesByFrame={bytesByFrame}
        onRequestBytes={source.loadFrameBytes ? requestBytes : undefined}
        treeByFrame={treeByFrame}
        onRequestTree={source.loadDecodeTree ? requestTree : undefined}
      />
    </>
  );
}
