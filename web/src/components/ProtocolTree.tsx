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
          "flex cursor-pointer items-center gap-1.5 rounded py-0.5 pr-1 hover:bg-slate-800/60",
          isSelected && "bg-sky-500/20",
        )}
        style={{ paddingLeft: depth * 14 }}
        onClick={() => {
          onSelect?.(node);
          if (hasChildren) setOpen((o) => !o);
        }}
      >
        {hasChildren ? (
          open ? (
            <ChevronDown className="h-3 w-3 shrink-0 text-slate-500" />
          ) : (
            <ChevronRight className="h-3 w-3 shrink-0 text-slate-500" />
          )
        ) : (
          <span className="inline-block h-3 w-3 shrink-0" />
        )}
        <span className="text-sky-300">{node.label}</span>
        {node.detail && <span className="truncate text-slate-400">{node.detail}</span>}
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
