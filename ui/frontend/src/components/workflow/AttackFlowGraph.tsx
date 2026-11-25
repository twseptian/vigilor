import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { ZoomIn, ZoomOut, Maximize2, Download } from "lucide-react";
import type { WorkflowGraph, WorkflowEdge, WorkflowNode } from "@/api/workflows";
import { tacticFor } from "./mitre";
import { useThemeStore } from "@/store/themeStore";

const NODE_W = 200;
const NODE_H = 68;
const COL_GAP = 72;
const ROW_GAP = 22;
const HEADER_H = 44;
const PAD = 20;

type Swatch = { fill: string; stroke: string; text: string; detail: string };
type Pack = {
  canvas: string;
  grid: string;
  border: string;
  headerBg: string;
  headerBorder: string;
  headerText: string;
  tacticText: string;
  edge: string;
  edgeHot: string;
  edgeSolo: string;
  target: Swatch;
  impact: Swatch;
  sev: Record<string, Swatch>;
};

const DARK: Pack = {
  canvas: "#12161c",
  grid: "linear-gradient(rgba(148,163,184,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.06) 1px, transparent 1px)",
  border: "border-slate-700",
  headerBg: "#1a222d",
  headerBorder: "#2dd4bf",
  headerText: "#e2e8f0",
  tacticText: "#5eead4",
  edge: "#0ea5e9",
  edgeHot: "#d97706",
  edgeSolo: "#8b5cf6",
  target: { fill: "#134e4a", stroke: "#2dd4bf", text: "#ccfbf1", detail: "#5eead4" },
  impact: { fill: "#4c1d3a", stroke: "#db2777", text: "#fce7f3", detail: "#f9a8d4" },
  sev: {
    Critical: { fill: "#450a0a", stroke: "#ef4444", text: "#fecaca", detail: "#fca5a5" },
    High: { fill: "#431407", stroke: "#f97316", text: "#fed7aa", detail: "#fdba74" },
    Medium: { fill: "#422006", stroke: "#ca8a04", text: "#fde68a", detail: "#facc15" },
    Low: { fill: "#172554", stroke: "#3b82f6", text: "#bfdbfe", detail: "#93c5fd" },
    Informational: { fill: "#1e293b", stroke: "#64748b", text: "#cbd5e1", detail: "#94a3b8" },
  },
};

const LIGHT: Pack = {
  canvas: "#f8fafc",
  grid: "linear-gradient(rgba(100,116,139,0.07) 1px, transparent 1px), linear-gradient(90deg, rgba(100,116,139,0.07) 1px, transparent 1px)",
  border: "border-slate-300",
  headerBg: "#eef2f6",
  headerBorder: "#0f766e",
  headerText: "#334155",
  tacticText: "#0f766e",
  edge: "#0284c7",
  edgeHot: "#b45309",
  edgeSolo: "#7c3aed",
  target: { fill: "#ccfbf1", stroke: "#0f766e", text: "#134e4a", detail: "#0f766e" },
  impact: { fill: "#fce7f3", stroke: "#be185d", text: "#831843", detail: "#9d174d" },
  sev: {
    Critical: { fill: "#fee2e2", stroke: "#b91c1c", text: "#7f1d1d", detail: "#991b1b" },
    High: { fill: "#ffedd5", stroke: "#c2410c", text: "#7c2d12", detail: "#9a3412" },
    Medium: { fill: "#fef9c3", stroke: "#a16207", text: "#713f12", detail: "#854d0e" },
    Low: { fill: "#dbeafe", stroke: "#1d4ed8", text: "#1e3a8a", detail: "#1e40af" },
    Informational: { fill: "#f1f5f9", stroke: "#64748b", text: "#334155", detail: "#475569" },
  },
};

function swatch(T: Pack, node: WorkflowNode): Swatch {
  if (node.kind === "target") return T.target;
  if (node.kind === "impact") return T.impact;
  return T.sev[node.severity ?? "Informational"] ?? T.sev.Informational;
}

function trunc(text: string, max: number): string {
  const s = String(text ?? "");
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

// ── Memoized primitives (avoid re-creating SVG trees on hover of unrelated nodes) ─

const GraphEdge = memo(function GraphEdge({
  edge, s, t, active, hot, T, showLabel, strokeFallback,
}: {
  edge: WorkflowEdge;
  s: { x: number; y: number };
  t: { x: number; y: number };
  active: boolean;
  hot: boolean;
  T: Pack;
  showLabel: boolean;
  strokeFallback: string;
}) {
  const forward = t.x > s.x;
  const x1 = forward ? s.x + NODE_W : s.x;
  const y1 = s.y + NODE_H / 2;
  const x2 = forward ? t.x : t.x + NODE_W;
  const y2 = t.y + NODE_H / 2;
  const dx = forward ? Math.max(36, (x2 - x1) / 2) : 48;
  const d = forward
    ? `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`
    : `M ${x1} ${y1} C ${x1 - dx} ${y1 + 64}, ${x2 + dx} ${y2 + 64}, ${x2} ${y2}`;
  const solo = edge.kind === "standalone";
  const stroke = hot ? T.edgeHot : solo ? T.edgeSolo : strokeFallback;
  const marker = hot ? "url(#wf-ah)" : solo ? "url(#wf-as)" : "url(#wf-a)";

  return (
    <g opacity={active ? 1 : 0.12}>
      <path
        d={d}
        fill="none"
        stroke={stroke}
        strokeWidth={hot ? 3 : 2.2}
        strokeDasharray={solo ? "6 4" : undefined}
        markerEnd={marker}
        strokeLinecap="round"
      />
      {showLabel && edge.label && (
        <text
          x={(x1 + x2) / 2}
          y={(y1 + y2) / 2 - 6}
          textAnchor="middle"
          style={{ fontSize: 9, fontWeight: 700, fill: hot ? T.edgeHot : T.headerText }}
        >
          {trunc(edge.label, 10)}
        </text>
      )}
    </g>
  );
});

const GraphNode = memo(function GraphNode({
  node, x, y, T, active, hovered, onEnter, onLeave, onClick,
}: {
  node: WorkflowNode;
  x: number;
  y: number;
  T: Pack;
  active: boolean;
  hovered: boolean;
  onEnter: (id: string) => void;
  onLeave: () => void;
  onClick?: (node: WorkflowNode) => void;
}) {
  const pal = swatch(T, node);
  const clickable = !!(node.finding_id && onClick);
  return (
    <g
      transform={`translate(${x}, ${y})`}
      opacity={active ? 1 : 0.22}
      style={{ cursor: clickable ? "pointer" : "default" }}
      onMouseEnter={() => onEnter(node.id)}
      onMouseLeave={onLeave}
      onClick={() => clickable && onClick!(node)}
    >
      <title>
        {[
          node.finding_ref ? `${node.finding_ref}: ${node.label}` : node.label,
          node.detail,
          node.severity ? `Severity: ${node.severity}` : "",
        ].filter(Boolean).join("\n")}
      </title>
      <rect
        width={NODE_W}
        height={NODE_H}
        rx={node.kind === "target" ? 14 : 10}
        fill={pal.fill}
        stroke={hovered ? T.headerText : pal.stroke}
        strokeWidth={hovered ? 2.5 : 2}
      />
      <rect x={0} y={0} width={4} height={NODE_H} rx={2} fill={pal.stroke} />
      <text x={12} y={18} style={{ fontSize: 10, fontWeight: 800, fill: pal.stroke, letterSpacing: 0.5 }}>
        {node.finding_ref ?? (node.kind === "target" ? "TARGET" : "IMPACT")}
      </text>
      <text x={12} y={38} style={{ fontSize: 12.5, fontWeight: 800, fill: pal.text }}>
        {trunc(node.label, 24)}
      </text>
      <text x={12} y={56} style={{ fontSize: 10, fontWeight: 600, fill: pal.detail }}>
        {trunc(node.category ? `${node.category} · ${node.detail || ""}` : (node.detail || node.severity || node.kind), 30)}
      </text>
    </g>
  );
});

interface Props {
  graph: WorkflowGraph;
  activeChain?: string | null;
  onNodeClick?: (node: WorkflowNode) => void;
  exportName?: string;
  height?: number;
}

export default function AttackFlowGraph({
  graph,
  activeChain = null,
  onNodeClick,
  exportName = "attack-flow",
  height = 520,
}: Props) {
  const appTheme = useThemeStore(s => s.theme);
  const T = appTheme === "light" ? LIGHT : DARK;
  const isLight = appTheme === "light";

  const [scale, setScale] = useState(1);
  const [fitScale, setFitScale] = useState(1);
  const [hovered, setHovered] = useState<string | null>(null);
  const [userZoomed, setUserZoomed] = useState(false);
  const svgRef = useRef<SVGSVGElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);

  const nodeById = useMemo(() => {
    const m = new Map<string, WorkflowNode>();
    for (const n of graph.nodes) m.set(n.id, n);
    return m;
  }, [graph.nodes]);

  const { positions, width, innerHeight, columns } = useMemo(() => {
    const pos = new Map<string, { x: number; y: number }>();
    let maxCol = 0;
    let maxRow = 0;
    for (const n of graph.nodes) {
      pos.set(n.id, {
        x: PAD + n.column * (NODE_W + COL_GAP),
        y: HEADER_H + PAD + n.row * (NODE_H + ROW_GAP),
      });
      maxCol = Math.max(maxCol, n.column);
      maxRow = Math.max(maxRow, n.row);
    }
    return {
      positions: pos,
      width: PAD * 2 + maxCol * (NODE_W + COL_GAP) + NODE_W,
      innerHeight: HEADER_H + PAD * 2 + maxRow * (NODE_H + ROW_GAP) + NODE_H + 8,
      columns: graph.columns ?? [],
    };
  }, [graph]);

  useLayoutEffect(() => {
    const box = boxRef.current;
    if (!box) return;
    const fit = () => {
      const avail = box.clientWidth - 8;
      if (avail <= 0) return;
      // Prefer fitting to full container width; allow slight upscale on wide layouts
      setFitScale(Math.max(0.55, Math.min(1.15, +(avail / width).toFixed(2))));
    };
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(box);
    return () => ro.disconnect();
  }, [width]);

  useEffect(() => {
    if (!userZoomed) setScale(fitScale);
  }, [fitScale, userZoomed]);

  const zoom = (delta: number) => {
    setUserZoomed(true);
    setScale(s => Math.min(1.8, Math.max(0.4, +(s + delta).toFixed(2))));
  };
  const resetZoom = () => {
    setUserZoomed(false);
    setScale(fitScale);
  };

  const onEnter = useCallback((id: string) => setHovered(id), []);
  const onLeave = useCallback(() => setHovered(null), []);

  const exportSvg = () => {
    if (!svgRef.current) return;
    const clone = svgRef.current.cloneNode(true) as SVGSVGElement;
    clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    const bg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    bg.setAttribute("width", String(width));
    bg.setAttribute("height", String(innerHeight));
    bg.setAttribute("fill", T.canvas);
    clone.insertBefore(bg, clone.firstChild);
    const blob = new Blob(
      ['<?xml version="1.0" encoding="UTF-8"?>\n', new XMLSerializer().serializeToString(clone)],
      { type: "image/svg+xml" },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${exportName}-${appTheme}.svg`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!graph.nodes?.length) {
    return (
      <div className="flex flex-col items-center justify-center py-12 gap-2 rounded-xl border border-border bg-card">
        <p className="text-[12px] text-muted-foreground">No attack path to render yet</p>
      </div>
    );
  }

  return (
    <div className="relative">
      <div className="flex items-center justify-between gap-2 mb-2">
        <p className="text-[12px] font-semibold text-foreground">
          Attack flow · {graph.nodes.length} nodes · {graph.edges?.length ?? 0} edges
        </p>
        <div className="flex items-center gap-0.5 rounded-lg border border-border bg-card p-0.5 text-foreground">
          <button onClick={() => zoom(-0.15)} title="Zoom out" className="p-1.5 rounded-md hover:bg-muted">
            <ZoomOut className="h-3.5 w-3.5" />
          </button>
          <span className="text-[11px] font-bold tabular-nums w-10 text-center">{Math.round(scale * 100)}%</span>
          <button onClick={() => zoom(0.15)} title="Zoom in" className="p-1.5 rounded-md hover:bg-muted">
            <ZoomIn className="h-3.5 w-3.5" />
          </button>
          <button onClick={resetZoom} title="Fit" className="p-1.5 rounded-md hover:bg-muted">
            <Maximize2 className="h-3.5 w-3.5" />
          </button>
          <button onClick={exportSvg} title="Download SVG" className="p-1.5 rounded-md text-teal-600 hover:bg-muted">
            <Download className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* CSS transform zoom — cheaper than resizing SVG geometry */}
      <div
        ref={boxRef}
        className={`overflow-auto rounded-xl border-2 ${T.border}`}
        style={{
          maxHeight: height,
          backgroundColor: T.canvas,
          backgroundImage: T.grid,
          backgroundSize: "28px 28px",
        }}
      >
        <div style={{ width: width * scale, height: innerHeight * scale, position: "relative" }}>
          <svg
            ref={svgRef}
            width={width}
            height={innerHeight}
            style={{
              display: "block",
              transform: `scale(${scale})`,
              transformOrigin: "0 0",
              willChange: "transform",
            }}
          >
            <defs>
              <marker id="wf-a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0 0 L10 5 L0 10 z" fill={T.edge} />
              </marker>
              <marker id="wf-ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0 0 L10 5 L0 10 z" fill={T.edgeHot} />
              </marker>
              <marker id="wf-as" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0 0 L10 5 L0 10 z" fill={T.edgeSolo} />
              </marker>
            </defs>

            {columns.map(col => {
              const cx = PAD + col.column * (NODE_W + COL_GAP) + NODE_W / 2;
              const tactic = tacticFor(col.label);
              return (
                <g key={col.key}>
                  <rect x={cx - NODE_W / 2} y={6} width={NODE_W} height={tactic ? 32 : 20} rx={5}
                    fill={T.headerBg} stroke={T.headerBorder} strokeWidth={1.2} />
                  <text x={cx} y={20} textAnchor="middle"
                    style={{ fontSize: 11, fontWeight: 800, letterSpacing: 1.2, fill: T.headerText }}>
                    {col.label.toUpperCase()}
                  </text>
                  {tactic && (
                    <text x={cx} y={32} textAnchor="middle"
                      style={{ fontSize: 9, fontWeight: 700, fill: T.tacticText }}>
                      {tactic.id}
                    </text>
                  )}
                </g>
              );
            })}

            {graph.edges.map(edge => {
              const s = positions.get(edge.source);
              const t = positions.get(edge.target);
              if (!s || !t) return null;
              const active = !activeChain || edge.chains?.includes(activeChain);
              const hot = activeChain != null && active;
              const src = nodeById.get(edge.source);
              return (
                <GraphEdge
                  key={edge.id}
                  edge={edge}
                  s={s}
                  t={t}
                  active={!!active}
                  hot={!!hot}
                  T={T}
                  showLabel={hot || hovered === edge.source || hovered === edge.target}
                  strokeFallback={src ? swatch(T, src).stroke : T.edge}
                />
              );
            })}

            {graph.nodes.map(node => {
              const p = positions.get(node.id)!;
              return (
                <GraphNode
                  key={node.id}
                  node={node}
                  x={p.x}
                  y={p.y}
                  T={T}
                  active={!activeChain || !!node.chains?.includes(activeChain)}
                  hovered={hovered === node.id}
                  onEnter={onEnter}
                  onLeave={onLeave}
                  onClick={onNodeClick}
                />
              );
            })}
          </svg>
        </div>
      </div>

      <div className="flex items-center gap-2 flex-wrap px-1 pt-2.5">
        {[
          { label: "Target", ...T.target },
          { label: "Critical", ...T.sev.Critical },
          { label: "High", ...T.sev.High },
          { label: "Medium", ...T.sev.Medium },
          { label: "Low", ...T.sev.Low },
          { label: "Impact", ...T.impact },
        ].map(l => (
          <span key={l.label} className="text-[10px] font-bold px-2 py-0.5 rounded border"
            style={{ backgroundColor: l.fill, borderColor: l.stroke, color: l.text }}>
            {l.label}
          </span>
        ))}
        <span className={`ml-auto text-[10px] ${isLight ? "text-slate-500" : "text-zinc-400"}`}>
          Follows app theme (White / Dark in header)
        </span>
      </div>
    </div>
  );
}
