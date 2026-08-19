"use client";

import { useState } from "react";
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
  // Default-open the first couple of levels, but always force-open any node whose
  // subtree contains the focused/selected id (e.g. an ERROR event's Cause IE),
  // regardless of how deep it is — the point of auto-focus is not to hide it.
  const [open, setOpen] = useState(depth < 2 || (!!selectedId && nodeContainsId(node, selectedId)));
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
