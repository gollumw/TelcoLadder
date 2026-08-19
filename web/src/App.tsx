/**
 * 外層殼：負責「把資料拿到手」，拿到之前與拿不到時要說什麼。
 *
 * `SessionAnalyzer` 保持「吃資料、不取資料」—— 它與底下 6 個元件仍然是
 * 對四個陣列的純函式運算，可以用假資料單獨測試。Phase 3 換後端時
 * 不會碰到任何一個 View。
 */

import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";

import SessionAnalyzer from "@/components/SessionAnalyzer";
import { apiSource } from "@/data/apiSource";
import { mockSource } from "@/data/mockSource";
import { currentSid, wantsApiSource, type DataSource, type Dataset } from "@/data/source";
import type { ProtocolNode } from "@/lib/types";

function pickSource(): DataSource {
  return wantsApiSource() ? apiSource(currentSid()) : mockSource;
}

export default function App() {
  const [source] = useState<DataSource>(pickSource);
  const [data, setData] = useState<Dataset | null>(null);
  const [error, setError] = useState<Error | null>(null);
  // 已取到的原始位元組。放在這裡而不是元件裡，是為了讓元件維持
  // 「吃資料、不取資料」—— 它只會呼叫一個注入進去的函式，不知道有 HTTP。
  const [bytesByFrame, setBytesByFrame] = useState<Record<number, string | null>>({});
  const [treeByFrame, setTreeByFrame] = useState<Record<number, ProtocolNode[] | null>>({});

  useEffect(() => {
    let cancelled = false;
    source
      .load()
      .then((loaded) => {
        if (!cancelled) setData(loaded);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err : new Error(String(err)));
      });
    return () => {
      cancelled = true;
    };
  }, [source]);

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

  if (!data) {
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
      {source.notice && (
        // 常駐橫幅，不是可關閉的提示 —— 使用者每一眼看到的畫面都少了東西，
        // 那件事不該只在載入時說一次。
        <div className="border-b border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-200">
          {source.notice}
        </div>
      )}
      <SessionAnalyzer
        data={data}
        bytesByFrame={bytesByFrame}
        onRequestBytes={source.loadFrameBytes ? requestBytes : undefined}
        treeByFrame={treeByFrame}
        onRequestTree={source.loadDecodeTree ? requestTree : undefined}
      />
    </>
  );
}
