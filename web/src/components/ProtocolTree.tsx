"use client";

import { useEffect, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ProtocolNode } from "@/lib/types";

// Shared recursive decode-tree renderer — used by both the Session Analysis
// Decode Inspector and the Data Mining Packet Details pane, since a packet
// only carries one decode tree regardless of which mode is looking at it.
export function ProtocolTree({
  nodes,
  selectedId,
  onSelect,
  depth = 0,
}: {
  nodes: ProtocolNode[];
  selectedId?: string | null;
  onSelect?: (node: ProtocolNode) => void;
  depth?: number;
}) {
  return (
    <div className="font-mono text-xs">
      {nodes.map((node) => (
        <ProtocolTreeNode key={node.id} node={node} selectedId={selectedId} onSelect={onSelect} depth={depth} />
      ))}
    </div>
  );
}

function ProtocolTreeNode({
  node,
  selectedId,
  onSelect,
  depth,
}: {
  node: ProtocolNode;
  selectedId?: string | null;
  onSelect?: (node: ProtocolNode) => void;
  depth: number;
}) {
  // **預設全部收合**，比照 Wireshark。真實封包的解碼樹動輒上百個節點，
  // 展開兩層就會把整個面板灌滿，使用者得先捲過一堆 Frame/IP/TCP 的細節
  // 才看得到他真正要的那一層。
  //
  // 唯一的例外是 `selectedId` 的祖先鏈 —— 那是「自動聚焦到 Cause IE」
  // 那個功能，收合它等於把功能關掉。
  const [open, setOpen] = useState(!!selectedId && nodeContainsId(node, selectedId));

  // 選中的節點換了（例如點了另一則失敗事件），祖先鏈要重新展開。
  // 少了這段，第二次點的那一格會停在收合狀態而看不出原因。
  useEffect(() => {
    if (selectedId && nodeContainsId(node, selectedId)) setOpen(true);
  }, [selectedId, node]);
  const hasChildren = !!node.children?.length;
  const isSelected = node.id === selectedId;

  return (
    <div>
      <div
        className={cn(
          "flex cursor-pointer items-start gap-1.5 rounded py-0.5 pr-1 transition-colors hover:bg-surface-hover",
          // **每一列都換行，不截斷。** 原本只有選中的那一列攤開、其他列單行 `truncate`
          // —— 可是每深一層縮排吃掉 14 px，展開到 HTTP/2 標頭的 Value／:path 那幾層時，
          // 整列只剩一半寬，要看的值正好被截在 `…`，而且看不出後面還有什麼。
          // Wireshark 用水平捲軸；這裡的樹在一個窄欄裡，捲軸會讓人捲丟位置。
          isSelected && "bg-signal-cyan-bg text-fg font-medium",
        )}
        style={{ paddingLeft: depth * 14 }}
        onClick={() => {
          onSelect?.(node);
          if (hasChildren) setOpen((o) => !o);
        }}
      >
        {hasChildren ? (
          open ? (
            <ChevronDown className="mt-0.5 h-3 w-3 shrink-0 text-fg-dim" />
          ) : (
            <ChevronRight className="mt-0.5 h-3 w-3 shrink-0 text-fg-dim" />
          )
        ) : (
          <span className="inline-block h-3 w-3 shrink-0" />
        )}
        {/* `min-w-0` 讓 flex 子項縮得比內容窄（否則換不了行）；`[overflow-wrap:anywhere]`
            而不是 `break-words`：值是 JSON、十六進位與長 URI，沒有空白可以斷。 */}
        <span className="min-w-0 font-mono [overflow-wrap:anywhere]">
          <span className="text-signal-cyan">{node.label}</span>
          {node.detail && <span className="text-fg-muted">{" "}{node.detail}</span>}
        </span>
      </div>
      {hasChildren && open && (
        <div>
          {node.children!.map((child) => (
            <ProtocolTreeNode key={child.id} node={child} selectedId={selectedId} onSelect={onSelect} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

function nodeContainsId(node: ProtocolNode, id: string): boolean {
  if (node.id === id) return true;
  return node.children?.some((child) => nodeContainsId(child, id)) ?? false;
}
