"use client";

import { useEffect, useRef, useState } from "react";
import JSZip from "jszip";
import { Network, DataSet } from "vis-network/standalone";
import "vis-network/styles/vis-network.css";
import { CircularProgress, Modal, ModalClose } from "@mui/joy";
import CVEItem from "@/components/Item/CVEItem";
import AiReportModal from "@/components/Modal/AiReportModal";
import DarkModeToggle from "@/components/Button/DarkModeToggle";
import Hero from "@/components/Hero/Hero";
import ConfigMenu from "@/components/Button/ConfigMenu";
import { useSearchParams } from "next/navigation";

declare module "react" {
  interface InputHTMLAttributes<T> {
    webkitdirectory?: boolean;
    directory?: boolean;
  }
}

/* =====================
   Types
===================== */

export type CVE = {
  id: string;
  description: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  cvss: number;
  published_date: string;
  exploit_db?: string;
  affected_versions?: string;
};

export type ProjectInfos = {
  name?: string;
  version?: string;
  standard?: string;
  cmake?: CMake;
  call_graph?: CallGraphNode;
};

export type CMake = {
  dependencies: LibraryInfos[];
};

export type LibraryInfos = {
  name: string;
  vendor?: string;
  version: string;
  source: string;
  cves: CVE[];
  git_repo?: string;
  options: Record<string, string>;
  checked_at?: string;
};

export type Location = {
  file: string;
  line: number;
  column?: number;
};

export type CallGraphNode = {
  id?: string;
  func_name?: string;
  locations: Location[];
  library?: LibraryInfos | null;
  children: CallGraphNode[];
  extracted_code?: string;
  ai_report?: string;
  ai_vulnerability_score?: number;
  global_report?: string;
  global_score?: number;
  critical_nodes?: CallGraphNode[];
};

/* =====================
   Argus brand SVG logo (the eye)
===================== */

function ArgusEye({ size = 32 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      {/* Outer eye shape */}
      <path
        d="M3 16 C8 7, 24 7, 29 16 C24 25, 8 25, 3 16Z"
        stroke="#3b82f6"
        strokeWidth="1.5"
        fill="rgba(59,130,246,0.06)"
      />
      {/* Iris ring */}
      <circle cx="16" cy="16" r="6.5" stroke="#3b82f6" strokeWidth="1.2" fill="rgba(29,58,122,0.6)" />
      {/* Pupil */}
      <circle cx="16" cy="16" r="3.2" fill="#3b82f6" />
      {/* Highlight */}
      <circle cx="14.2" cy="14.2" r="1.1" fill="#93c5fd" opacity="0.9" />
      {/* Scan line */}
      <line x1="3" y1="16" x2="29" y2="16" stroke="#3b82f6" strokeWidth="0.5" opacity="0.25" />
    </svg>
  );
}

/* =====================
   Color system — continuous gradient
===================== */

function scoreToHex(r: number, g: number, b: number): string {
  const toHex = (n: number) => Math.round(n).toString(16).padStart(2, "0");
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
}

function interpolateColor(
  [r1, g1, b1]: [number, number, number],
  [r2, g2, b2]: [number, number, number],
  t: number,
): string {
  return scoreToHex(r1 + (r2 - r1) * t, g1 + (g2 - g1) * t, b1 + (b2 - b1) * t);
}

const GREEN: [number, number, number] = [22, 163, 74];    // #16a34a
const YELLOW: [number, number, number] = [234, 179, 8];   // #eab308
const RED: [number, number, number] = [220, 38, 38];      // #dc2626
const AMBER_UNSCORED = "#d97706";
const SLATE_SAFE = "#475569";
const SLATE_DESCENDANT = "#94a3b8";

export function vulnerabilityColor(node: CallGraphNode): string {
  const hasCves = (node.library?.cves?.length ?? 0) > 0;

  if (!hasCves) {
    const hasDescendant =
      node.children?.some((c) => hasVulnerabilitiesRecursively(c)) ?? false;
    return hasDescendant ? SLATE_DESCENDANT : SLATE_SAFE;
  }

  if (
    node.ai_vulnerability_score === undefined ||
    node.ai_vulnerability_score === null
  ) {
    return AMBER_UNSCORED;
  }

  const s = Math.max(0, Math.min(10, node.ai_vulnerability_score));

  if (s <= 5) {
    return interpolateColor(GREEN, YELLOW, s / 5);
  } else {
    return interpolateColor(YELLOW, RED, (s - 5) / 5);
  }
}

export function vulnerabilityColorRgba(node: CallGraphNode, alpha = 1): string {
  const hex = vulnerabilityColor(node);
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}

export function vulnerabilityLabel(node: CallGraphNode): string {
  const hasCves = (node.library?.cves?.length ?? 0) > 0;
  if (!hasCves) {
    const hasDescendant =
      node.children?.some((c) => hasVulnerabilitiesRecursively(c)) ?? false;
    return hasDescendant ? "Vulnerable by Descendant" : "Safe";
  }
  if (
    node.ai_vulnerability_score === undefined ||
    node.ai_vulnerability_score === null
  ) {
    return "Pending Analysis";
  }
  const s = node.ai_vulnerability_score;
  if (s >= 8) return `Critical Risk (${s.toFixed(1)})`;
  if (s >= 6) return `High Risk (${s.toFixed(1)})`;
  if (s >= 4) return `Medium Risk (${s.toFixed(1)})`;
  if (s >= 2) return `Low Risk (${s.toFixed(1)})`;
  return `Minimal Risk (${s.toFixed(1)})`;
}

/* =====================
   Graph helpers
===================== */

const ENDPOINT = process.env.NEXT_PUBLIC_BACKEND_ENDPOINT;

const hasVulnerabilitiesRecursively = (
  node: CallGraphNode,
  memo = new WeakMap<CallGraphNode, boolean>(),
): boolean => {
  if (memo.has(node)) return memo.get(node)!;
  const selfHasCves = (node.library?.cves?.length ?? 0) > 0;
  const scored =
    node.ai_vulnerability_score !== undefined &&
    node.ai_vulnerability_score !== null;
  const aboveThreshold = (node.ai_vulnerability_score ?? 10) >= 2;
  if (selfHasCves && (!scored || aboveThreshold)) {
    memo.set(node, true);
    return true;
  }
  const childHas =
    node.children?.some((c) => hasVulnerabilitiesRecursively(c, memo)) ?? false;
  memo.set(node, childHas);
  return childHas;
};

const collectVulnerableDescendants = (
  node: CallGraphNode,
  result: Set<CallGraphNode> = new Set(),
  visited: Set<CallGraphNode> = new Set(),
): CallGraphNode[] => {
  if (visited.has(node)) return [];
  visited.add(node);
  node.children?.forEach((child) => {
    if ((child.library?.cves?.length ?? 0) > 0) result.add(child);
    collectVulnerableDescendants(child, result, visited);
  });
  return Array.from(result);
};

type GraphNode = {
  id: string;
  label: string;
  color: string;
  level: number;
  data: CallGraphNode;
};
type GraphEdge = {
  id: string;
  from: string;
  to: string;
  color: { color: string; highlight: string; hover: string };
};

function buildGraph(
  node: CallGraphNode,
  nodes: GraphNode[],
  edges: GraphEdge[],
  nodeMap: Map<string, string> = new Map(),
  parentId?: string,
  level = 0,
) {
  if (!node.func_name) node.func_name = "anonymous";
  const locKey = node.locations
    .map((l) => `${l.file}:${l.line}:${l.column ?? 0}`)
    .sort()
    .join("|");
  const nodeKey = `${node.func_name}_${locKey}`;
  const color = vulnerabilityColor(node);

  if (nodeMap.has(nodeKey)) {
    const nodeId = nodeMap.get(nodeKey)!;
    if (parentId)
      edges.push({
        id: `edge-${edges.length}`,
        from: parentId,
        to: nodeId,
        color: { color, highlight: color, hover: color },
      });
  } else {
    const nodeId = `node-${nodes.length}`;
    nodeMap.set(nodeKey, nodeId);
    node.id = nodeId;
    nodes.push({ id: nodeId, label: node.func_name, color, level, data: node });
    if (parentId)
      edges.push({
        id: `edge-${edges.length}`,
        from: parentId,
        to: nodeId,
        color: { color, highlight: color, hover: color },
      });
    node.children.forEach((child) =>
      buildGraph(child, nodes, edges, nodeMap, nodeId, level + 1),
    );
  }
}

const NETWORK_OPTIONS = {
  layout: {
    hierarchical: {
      enabled: true,
      direction: "UD",
      sortMethod: "directed",
      levelSeparation: 150,
      nodeSpacing: 200,
      treeSpacing: 250,
    },
  },
  edges: {
    smooth: {
      enabled: true,
      type: "cubicBezier",
      forceDirection: true,
      roundness: 0.4,
    },
    arrows: { from: true },
  },
  physics: false,
};

/* =====================
   Score gradient bar
===================== */

function ScoreBar({ score }: { score: number }) {
  const pct = (score / 10) * 100;
  const color = vulnerabilityColor({
    locations: [],
    children: [],
    library: {
      name: "",
      version: "",
      source: "",
      cves: [{}] as CVE[],
      options: {},
    },
    ai_vulnerability_score: score,
  });

  return (
    <div className="flex items-center gap-2">
      <div className="relative flex-1 h-2 rounded-full overflow-hidden" style={{ background: "#1b2d4f" }}>
        <div
          className="absolute left-0 top-0 h-full rounded-full transition-all duration-700"
          style={{
            width: `${pct}%`,
            background: `linear-gradient(90deg, #16a34a, #eab308, #dc2626)`,
            clipPath: `inset(0 ${100 - pct}% 0 0)`,
          }}
        />
      </div>
      <span className="text-xs font-mono font-bold" style={{ color }}>
        {score.toFixed(1)}
      </span>
    </div>
  );
}

/* =====================
   Component
===================== */

export default function Page() {
  const searchParams = useSearchParams();
  // Default to dark mode — Argus dark theme is the primary experience
  const [isDarkMode, setIsDarkMode] = useState(true);

  useEffect(() => {
    const dm = searchParams.get("isDarkModeInit");
    if (dm !== null) setIsDarkMode(dm === "true");
  }, [searchParams]);

  const folderInputRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const networkRef = useRef<Network | null>(null);

  const [files, setFiles] = useState<FileList | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingGenerateReport, setLoadingGenerateReport] = useState(false);
  const [openModalAiReport, setOpenModalAiReport] = useState(false);
  const [showAiReport, setShowAiReport] = useState<CallGraphNode | null>(null);
  const [projectInfo, setProjectInfo] = useState<ProjectInfos | null>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [selectedNode, setSelectedNode] = useState<CallGraphNode | null>(null);
  const [openSelectFolderModal, setOpenSelectFolderModal] = useState(false);

  useEffect(() => {
    if (folderInputRef.current) {
      folderInputRef.current.setAttribute("webkitdirectory", "");
      folderInputRef.current.setAttribute("directory", "");
    }
  }, []);

  useEffect(() => {
    if (files) uploadAndAnalyzeProject();
  }, [files]);

  const handleFolderSelect = (fileList: FileList) => setFiles(fileList);

  const buildAndRenderGraph = (
    project: ProjectInfos,
    graphNodes: GraphNode[],
    graphEdges: GraphEdge[],
  ) => {
    if (!containerRef.current) return;
    const net = new Network(
      containerRef.current,
      { nodes: new DataSet(graphNodes), edges: new DataSet(graphEdges) },
      NETWORK_OPTIONS,
    );
    net.on("selectNode", (params) => {
      const nodeId = params.nodes[0];
      const node = graphNodes.find((n) => n.id === nodeId);
      if (node) setSelectedNode(node.data);
    });
    networkRef.current = net;
  };

  const uploadAndAnalyzeProject = async () => {
    if (!files) return;
    setLoading(true);
    try {
      setOpenSelectFolderModal(false);
      const zip = new JSZip();
      Array.from(files).forEach((file) =>
        zip.file(file.webkitRelativePath || file.name, file),
      );
      const zipBlob = await zip.generateAsync({ type: "blob" });
      const formData = new FormData();
      formData.append("project", zipBlob, "project.zip");

      const res = await fetch(`${ENDPOINT}/analyze`, {
        method: "POST",
        body: formData,
      });
      if (!res.ok) throw new Error("Failed to analyze project");

      const project: ProjectInfos = await res.json();
      setProjectInfo(project);

      const graphNodes: GraphNode[] = [];
      const graphEdges: GraphEdge[] = [];
      if (project.call_graph)
        buildGraph(project.call_graph, graphNodes, graphEdges);
      setNodes(graphNodes);
      setEdges(graphEdges);
      buildAndRenderGraph(project, graphNodes, graphEdges);
    } catch (err) {
      console.error(err);
      alert("Error analyzing project");
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateAiReport = async (selectedNode?: CallGraphNode) => {
    if (!files) return;
    setLoadingGenerateReport(true);
    try {
      const zip = new JSZip();
      Array.from(files).forEach((file) =>
        zip.file(file.webkitRelativePath || file.name, file),
      );
      const zipBlob = await zip.generateAsync({ type: "blob" });
      const formData = new FormData();
      formData.append("project", zipBlob, "project.zip");
      formData.append("projectInfos", JSON.stringify(projectInfo || {}));
      if (selectedNode)
        formData.append("selectedNode", JSON.stringify(selectedNode));

      const res = await fetch(`${ENDPOINT}/llm_generate_report`, {
        method: "POST",
        body: formData,
      });
      if (!res.ok) throw new Error("Failed to generate report");

      const project: ProjectInfos = await res.json();
      setProjectInfo(project);

      const graphNodes: GraphNode[] = [];
      const graphEdges: GraphEdge[] = [];
      if (project.call_graph)
        buildGraph(project.call_graph, graphNodes, graphEdges);
      setNodes(graphNodes);
      setEdges(graphEdges);
      buildAndRenderGraph(project, graphNodes, graphEdges);

      if (!selectedNode) setOpenModalAiReport(true);
      setSelectedNode(null);
    } catch (err) {
      console.error(err);
      alert("Error generating AI report");
    } finally {
      setLoadingGenerateReport(false);
    }
  };

  /**
   * Safely unwrap a ```markdown ... ``` block from LLM output.
   *
   * Handles three failure modes:
   *  1. non-string value (object/null/number) — backend sometimes returns
   *     global_report as a dict when the LLM mis-formats its JSON output.
   *     We probe known string keys before falling back to JSON.stringify.
   *  2. lazy regex stopping at inner code fences — replaced by lastIndexOf
   *     so ```cpp blocks inside the report don't truncate the capture.
   *  3. no ```markdown wrapper at all — returned as-is.
   */
  const unwrapMarkdownBlock = (text: unknown): string => {
    // ── Step 1: coerce to string ─────────────────────────────────────────
    let str: string;
    if (typeof text === "string") {
      str = text;
    } else if (text !== null && typeof text === "object") {
      // LLM returned a dict instead of a plain string — try common keys
      const obj = text as Record<string, unknown>;
      const candidate = (
        obj.global_report ?? obj.report ?? obj.content ??
        obj.text ?? obj.markdown ?? obj.summary
      );
      if (typeof candidate === "string") {
        str = candidate;
      } else {
        str = JSON.stringify(text, null, 2);
      }
    } else {
      str = String(text ?? "");
    }

    // ── Step 2: strip outer ```markdown ... ``` wrapper if present ────────
    const trimmed = str.trim();
    const fenceEnd = trimmed.indexOf("\n");
    if (
      fenceEnd !== -1 &&
      trimmed.slice(0, fenceEnd).trim().toLowerCase() === "```markdown"
    ) {
      const inner = trimmed.slice(fenceEnd + 1);
      // Use lastIndexOf so inner code blocks (```cpp etc.) are never consumed
      const lastFence = inner.lastIndexOf("\n```");
      if (lastFence !== -1) {
        return inner.slice(0, lastFence).trim();
      }
      if (inner.trimEnd().endsWith("```")) {
        return inner.slice(0, inner.lastIndexOf("```")).trim();
      }
      return inner.trim();
    }
    return str;
  };

  /* ---------- Argus color tokens ---------- */
  const BG        = isDarkMode ? "#070c18" : "#f0f5ff";
  const SURFACE   = isDarkMode ? "#0d1828" : "#ffffff";
  const BORDER    = isDarkMode ? "#1b2d4f" : "#bfdbfe";
  const TEXT      = isDarkMode ? "#e2e8f0" : "#0f172a";
  const MUTED     = isDarkMode ? "#64748b" : "#64748b";
  const card      = isDarkMode
    ? "border rounded-xl"
    : "bg-white border rounded-xl";

  return (
    <div
      className="h-screen flex flex-col overflow-hidden"
      style={{ background: BG, color: TEXT }}
    >
      {/* ===== Top nav bar ===== */}
      <header
        className="sticky top-0 z-50 flex items-center justify-between px-6 py-3 border-b"
        style={{
          background: isDarkMode
            ? "rgba(7,12,24,0.92)"
            : "rgba(240,245,255,0.92)",
          borderColor: BORDER,
          backdropFilter: "blur(12px)",
        }}
      >
        {/* Brand */}
        <div className="flex items-center gap-3">
          <ArgusEye size={30} />
          <div className="flex flex-col leading-none">
            <span
              className="text-lg font-black tracking-widest uppercase"
              style={{ color: "#60a5fa", letterSpacing: "0.2em" }}
            >
              Argus
            </span>
            <span className="text-[10px] uppercase tracking-widest" style={{ color: MUTED }}>
              C++ Vulnerability Intelligence
            </span>
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-3">
          <DarkModeToggle isDarkMode={isDarkMode} setIsDarkMode={setIsDarkMode} />
          <ConfigMenu isDarkMode={isDarkMode} />
        </div>
      </header>

      {/* ===== Main layout ===== */}
      <div className="flex flex-1 min-h-0 flex-col md:flex-row gap-5 p-5 overflow-hidden">
        {/* Left: graph area */}
        <div className="flex-1 flex flex-col gap-4 min-h-0">

          {/* Action buttons */}
          <div className="flex flex-wrap gap-3 items-center">
            <button
              onClick={() => setOpenSelectFolderModal(true)}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg cursor-pointer font-medium transition-all border"
              style={{
                background: isDarkMode ? "#0d1828" : "#fff",
                borderColor: BORDER,
                color: isDarkMode ? "#93c5fd" : "#1d4ed8",
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.borderColor = "#3b82f6")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.borderColor = BORDER)
              }
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
              </svg>
              Select Project Folder
              <input
                ref={folderInputRef}
                type="file"
                multiple
                className="hidden"
                onChange={(e) =>
                  e.target.files && handleFolderSelect(e.target.files)
                }
              />
            </button>

            {nodes.some((n) => (n.data.library?.cves?.length ?? 0) > 0) &&
              !projectInfo?.call_graph?.global_report && (
                <button
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg cursor-pointer font-semibold transition-all"
                  style={{
                    background: "linear-gradient(135deg, #1d4ed8, #3b82f6)",
                    boxShadow: "0 0 18px rgba(59,130,246,0.35)",
                    color: "#fff",
                  }}
                  onMouseEnter={(e) =>
                    (e.currentTarget.style.boxShadow =
                      "0 0 24px rgba(59,130,246,0.55)")
                  }
                  onMouseLeave={(e) =>
                    (e.currentTarget.style.boxShadow =
                      "0 0 18px rgba(59,130,246,0.35)")
                  }
                  onClick={() => handleGenerateAiReport()}
                >
                  <ArgusEye size={18} />
                  Generate Global AI Report
                </button>
              )}

            {projectInfo?.call_graph?.global_report && (
              <button
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg cursor-pointer font-semibold transition-all"
                style={{
                  background: "linear-gradient(135deg, #1d4ed8, #3b82f6)",
                  boxShadow: "0 0 18px rgba(59,130,246,0.35)",
                  color: "#fff",
                }}
                onMouseEnter={(e) =>
                  (e.currentTarget.style.boxShadow =
                    "0 0 24px rgba(59,130,246,0.55)")
                }
                onMouseLeave={(e) =>
                  (e.currentTarget.style.boxShadow =
                    "0 0 18px rgba(59,130,246,0.35)")
                }
                onClick={() => setOpenModalAiReport(true)}
              >
                <ArgusEye size={18} />
                Show AI Report
              </button>
            )}
          </div>

          {/* Risk gradient legend */}
          {nodes.length > 0 && (
            <div
              className="flex items-center gap-3 px-4 py-2.5 rounded-xl border text-xs font-medium"
              style={{ background: SURFACE, borderColor: BORDER }}
            >
              <span style={{ color: MUTED }}>Risk</span>
              <div
                className="flex-1 h-2.5 rounded-full"
                style={{
                  background:
                    "linear-gradient(90deg, #16a34a 0%, #eab308 50%, #dc2626 100%)",
                }}
              />
              <div className="flex gap-4">
                <span style={{ color: "#16a34a" }}>0 – Safe</span>
                <span style={{ color: "#eab308" }}>5 – Medium</span>
                <span style={{ color: "#dc2626" }}>10 – Critical</span>
              </div>
              <span style={{ color: MUTED }}>
                ◆{" "}
                <span style={{ color: AMBER_UNSCORED }}>Pending</span>
                {"  "}◆ <span style={{ color: SLATE_SAFE }}>Safe</span>
                {"  "}◆{" "}
                <span style={{ color: SLATE_DESCENDANT }}>Desc.</span>
              </span>
            </div>
          )}

          {/* Call graph */}
          <div
            className="border rounded-xl overflow-hidden flex-1 min-h-0"
            style={{
              background: isDarkMode ? "#0a1018" : "#f8faff",
              borderColor: BORDER,
            }}
          >
            {nodes.length === 0 && (
              <div className="h-full flex flex-col items-center justify-center gap-4 opacity-30">
                <ArgusEye size={56} />
                <p className="text-sm tracking-widest uppercase" style={{ color: MUTED }}>
                  No project loaded
                </p>
              </div>
            )}
            <div ref={containerRef} className="h-full w-full" />
          </div>
        </div>

        {/* Right: sidebar */}
        <div
          className="w-full md:w-96 flex flex-col gap-5 p-5 rounded-xl border shadow-lg overflow-y-auto min-h-0"
          style={{ background: SURFACE, borderColor: BORDER }}
        >
          {/* Project info */}
          <div>
            <h2
              className="text-xs font-bold uppercase tracking-widest mb-3"
              style={{ color: "#60a5fa" }}
            >
              Project
            </h2>
            {projectInfo ? (
              <div className="space-y-1.5 text-sm" style={{ color: TEXT }}>
                <div>
                  <span style={{ color: MUTED }}>Name</span>{" "}
                  <span className="font-semibold">{projectInfo.name}</span>
                </div>
                <div>
                  <span style={{ color: MUTED }}>Version</span>{" "}
                  <span className="font-mono">{projectInfo.version}</span>
                </div>
                {projectInfo.call_graph?.global_score !== undefined &&
                  projectInfo.call_graph.global_score !== null && (
                    <div className="mt-3">
                      <span
                        className="block text-xs mb-1.5 uppercase tracking-wider"
                        style={{ color: MUTED }}
                      >
                        Global Risk Score
                      </span>
                      <ScoreBar score={projectInfo.call_graph.global_score} />
                    </div>
                  )}
              </div>
            ) : (
              <p className="text-sm" style={{ color: MUTED }}>
                No project loaded
              </p>
            )}
          </div>

          <div className="h-px" style={{ background: BORDER }} />

          {/* Node info */}
          <div>
            <h2
              className="text-xs font-bold uppercase tracking-widest mb-3"
              style={{ color: "#60a5fa" }}
            >
              Function
            </h2>
            {selectedNode ? (
              <div className="space-y-3 text-sm" style={{ color: TEXT }}>
                <div>
                  <span style={{ color: MUTED }}>Name</span>{" "}
                  <span className="font-semibold font-mono">
                    {selectedNode.func_name}
                  </span>
                </div>

                {selectedNode.library ? (
                  <div>
                    <span style={{ color: MUTED }}>Library</span>{" "}
                    <span
                      className="cursor-pointer hover:underline"
                      style={{ color: "#60a5fa" }}
                      onClick={() =>
                        window.open(selectedNode.library?.git_repo, "_blank")
                      }
                    >
                      {selectedNode.library.name}
                    </span>
                    {selectedNode.library.version && (
                      <span className="ml-1 text-xs" style={{ color: MUTED }}>
                        v{selectedNode.library.version}
                      </span>
                    )}
                  </div>
                ) : (
                  <div>
                    <span style={{ color: MUTED }}>Library</span>{" "}
                    <span>None (or std)</span>
                  </div>
                )}

                {/* Risk badge */}
                <div
                  className="flex items-center gap-2 px-3 py-2 rounded-lg border"
                  style={{
                    background: isDarkMode ? "#070c18" : "#f0f5ff",
                    borderColor: vulnerabilityColorRgba(selectedNode, 0.3),
                  }}
                >
                  <span
                    className="inline-block w-2.5 h-2.5 rounded-full flex-shrink-0"
                    style={{ background: vulnerabilityColor(selectedNode) }}
                  />
                  <span
                    style={{ color: vulnerabilityColor(selectedNode) }}
                    className="font-semibold text-xs uppercase tracking-wide"
                  >
                    {vulnerabilityLabel(selectedNode)}
                  </span>
                </div>

                {/* Score bar */}
                {selectedNode.ai_vulnerability_score !== undefined &&
                  selectedNode.ai_vulnerability_score !== null && (
                    <div>
                      <span
                        className="block text-xs mb-1.5 uppercase tracking-wider"
                        style={{ color: MUTED }}
                      >
                        AI Vulnerability Score
                      </span>
                      <ScoreBar score={selectedNode.ai_vulnerability_score} />
                    </div>
                  )}

                {/* AI report actions */}
                {(selectedNode.library?.cves?.length ?? 0) > 0 &&
                  (selectedNode.ai_report ? (
                    <button
                      className="w-full px-3 py-2 rounded-lg text-sm cursor-pointer font-semibold transition-all flex items-center justify-center gap-2"
                      style={{
                        background: "linear-gradient(135deg, #1d4ed8, #3b82f6)",
                        boxShadow: "0 0 14px rgba(59,130,246,0.3)",
                        color: "#fff",
                      }}
                      onClick={() => setShowAiReport(selectedNode)}
                    >
                      <ArgusEye size={16} />
                      Show AI Report
                    </button>
                  ) : (
                    <button
                      className="w-full px-3 py-2 rounded-lg text-sm cursor-pointer font-semibold transition-all flex items-center justify-center gap-2"
                      style={{
                        background: "linear-gradient(135deg, #1d4ed8, #3b82f6)",
                        boxShadow: "0 0 14px rgba(59,130,246,0.3)",
                        color: "#fff",
                      }}
                      onClick={() => handleGenerateAiReport(selectedNode)}
                    >
                      <ArgusEye size={16} />
                      Analyze with AI
                    </button>
                  ))}

                {/* Vulnerable descendants */}
                {(selectedNode.library?.cves?.length ?? 0) === 0 &&
                  collectVulnerableDescendants(selectedNode).length > 0 && (
                    <div>
                      <span
                        className="block text-xs mb-1.5 uppercase tracking-wider"
                        style={{ color: MUTED }}
                      >
                        Vulnerable Descendants
                      </span>
                      <ul className="space-y-1.5">
                        {collectVulnerableDescendants(selectedNode).map(
                          (child) => (
                            <li
                              key={
                                child.func_name +
                                child.locations
                                  .map((l) => `${l.file}:${l.line}`)
                                  .join("|")
                              }
                              className="flex items-center justify-between gap-2"
                            >
                              <span className="flex items-center gap-1.5 text-xs font-mono">
                                <span
                                  className="w-2 h-2 rounded-full flex-shrink-0"
                                  style={{
                                    background: vulnerabilityColor(child),
                                  }}
                                />
                                {child.func_name}
                              </span>
                              <button
                                className="text-xs cursor-pointer px-2 py-0.5 rounded-md font-medium transition-colors border"
                                style={{
                                  background: isDarkMode ? "#0d1828" : "#f0f5ff",
                                  borderColor: BORDER,
                                  color: isDarkMode ? "#93c5fd" : "#1d4ed8",
                                }}
                                onClick={() => {
                                  setSelectedNode(child);
                                  if (child.id)
                                    networkRef?.current?.selectNodes([child.id]);
                                }}
                              >
                                Focus
                              </button>
                            </li>
                          ),
                        )}
                      </ul>
                    </div>
                  )}

                {/* Call locations */}
                {selectedNode.locations.length > 0 && (
                  <>
                    <div className="h-px" style={{ background: BORDER }} />
                    <div>
                      <span
                        className="block text-xs mb-1.5 uppercase tracking-wider"
                        style={{ color: MUTED }}
                      >
                        Called in
                      </span>
                      <ul className="space-y-0.5">
                        {selectedNode.locations.map((loc) => (
                          <li
                            key={`${loc.file}:${loc.line}:${loc.column ?? 0}`}
                            className="text-xs font-mono"
                            style={{ color: MUTED }}
                          >
                            • {loc.file.replace(/^\/tmp\/[^/]+\//, "")}:
                            {loc.line}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </>
                )}

                {/* CVEs */}
                {(selectedNode.library?.cves?.length ?? 0) > 0 && (
                  <>
                    <div className="h-px" style={{ background: BORDER }} />
                    <div>
                      <span
                        className="block text-xs mb-1.5 uppercase tracking-wider"
                        style={{ color: MUTED }}
                      >
                        CVEs ({selectedNode.library!.cves.length})
                      </span>
                      <ul className="space-y-1">
                        {selectedNode.library!.cves.map((cve) => (
                          <CVEItem
                            key={cve.id}
                            cve={cve}
                            isDarkMode={isDarkMode}
                          />
                        ))}
                      </ul>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <p className="text-sm" style={{ color: MUTED }}>
                Click a node in the graph
              </p>
            )}
          </div>
        </div>
      </div>

      {/* ===== Modals ===== */}
      <Modal
        open={loading}
        sx={{ display: "flex", alignItems: "center", justifyContent: "center" }}
      >
        <div
          className="p-8 rounded-2xl flex flex-col items-center gap-4 border"
          style={{
            background: SURFACE,
            borderColor: "#3b82f6",
            boxShadow: "0 0 40px rgba(59,130,246,0.25)",
          }}
        >
          <ArgusEye size={48} />
          <CircularProgress sx={{ color: "#3b82f6" }} />
          <p className="text-sm tracking-wider uppercase" style={{ color: "#93c5fd" }}>
            Analyzing project…
          </p>
        </div>
      </Modal>

      <Modal
        open={loadingGenerateReport}
        sx={{ display: "flex", alignItems: "center", justifyContent: "center" }}
      >
        <div
          className="p-8 rounded-2xl flex flex-col items-center gap-4 border"
          style={{
            background: SURFACE,
            borderColor: "#3b82f6",
            boxShadow: "0 0 40px rgba(59,130,246,0.25)",
          }}
        >
          <ArgusEye size={48} />
          <CircularProgress sx={{ color: "#3b82f6" }} />
          <p className="text-sm tracking-wider uppercase" style={{ color: "#93c5fd" }}>
            Generating report…
          </p>
        </div>
      </Modal>

      <Modal
        open={openSelectFolderModal}
        onClose={() => setOpenSelectFolderModal(false)}
        sx={{ display: "flex", alignItems: "center", justifyContent: "center" }}
      >
        <div
          className="p-8 rounded-2xl flex flex-col items-center gap-4 border relative"
          style={{
            background: SURFACE,
            borderColor: "#1b2d4f",
            boxShadow: "0 0 60px rgba(59,130,246,0.15)",
          }}
        >
          <ModalClose
            onClick={() => setOpenSelectFolderModal(false)}
            sx={{ color: "#94a3b8" }}
          />
          <Hero
            title={
              <span className="flex items-center gap-3 justify-center">
                <ArgusEye size={42} />
                <span style={{ color: "#60a5fa" }}>Argus</span>
              </span>
            }
            descriptive="C++ Vulnerability Intelligence"
            description="Select your project folder to analyze its vulnerabilities. Your code remains local and private."
            isBlackTheme={true}
            bouton2OnClick={() => folderInputRef.current?.click()}
            bouton2Text="Browse Folder"
            isTopPage={true}
          />
        </div>
      </Modal>

      <AiReportModal
        openModalAiReport={openModalAiReport}
        setOpenModalAiReport={setOpenModalAiReport}
        aiScore={projectInfo?.call_graph?.global_score ?? null}
        aiReport={unwrapMarkdownBlock(
          projectInfo?.call_graph?.global_report ?? "",
        )}
        isDarkMode={isDarkMode}
      />
      <AiReportModal
        openModalAiReport={!!showAiReport}
        setOpenModalAiReport={() => setShowAiReport(null)}
        aiScore={showAiReport?.ai_vulnerability_score ?? null}
        aiReport={unwrapMarkdownBlock(showAiReport?.ai_report ?? "")}
        isDarkMode={isDarkMode}
      />
    </div>
  );
}
