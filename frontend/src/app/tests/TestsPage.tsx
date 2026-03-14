"use client";

import { useEffect, useState } from "react";
import {
  Modal,
  Button,
  Checkbox,
  Radio,
  RadioGroup,
  Stack,
  Typography,
  Divider,
  CircularProgress,
} from "@mui/joy";
import ReactMarkdown from "react-markdown";

import { CallGraphNode, ProjectInfos } from "../page";
import { vulnerabilityColor } from "../page";
import FolderPicker from "@/components/Input/FolderPicker";
import DarkModeToggle from "@/components/Button/DarkModeToggle";
import ConfigMenuTest from "@/components/Button/ConfigMenuTest";
import { useSearchParams } from "next/navigation";
import JSZip from "jszip";

declare module "react" {
  interface InputHTMLAttributes<T> {
    webkitdirectory?: boolean;
    directory?: boolean;
  }
}

const ENDPOINT = process.env.NEXT_PUBLIC_BACKEND_ENDPOINT;

/* ─────────────────────────────────────────
   Argus brand SVG (same as main page)
───────────────────────────────────────── */
function ArgusEye({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M3 16 C8 7, 24 7, 29 16 C24 25, 8 25, 3 16Z" stroke="#3b82f6" strokeWidth="1.5" fill="rgba(59,130,246,0.06)" />
      <circle cx="16" cy="16" r="6.5" stroke="#3b82f6" strokeWidth="1.2" fill="rgba(29,58,122,0.6)" />
      <circle cx="16" cy="16" r="3.2" fill="#3b82f6" />
      <circle cx="14.2" cy="14.2" r="1.1" fill="#93c5fd" opacity="0.9" />
      <line x1="3" y1="16" x2="29" y2="16" stroke="#3b82f6" strokeWidth="0.5" opacity="0.25" />
    </svg>
  );
}

/* ─────────────────────────────────────────
   Types
───────────────────────────────────────── */

export type JudgeReports = Record<string, string>;
export type JudgeScores = Record<string, number>;
export type JudgeMetricScores = Record<string, Record<string, number>>;

export type JudgedCallGraphNode = CallGraphNode & {
  judge_ai_reports?: JudgeReports;
  judge_ai_vulnerability_scores?: JudgeScores;
  judge_ai_metric_scores?: JudgeMetricScores;
  judge_global_ai_metric_scores?: JudgeMetricScores;
  judge_ai_global_reports?: JudgeReports;
  judge_ai_global_scores?: JudgeScores;
  // Phase-2 revised scores (after peer review)
  judge_revised_scores?: JudgeScores;
  judge_revised_global_scores?: JudgeScores;
  // Phase-3 consensus outputs
  consensus_local_score?: number | null;
  consensus_global_score?: number | null;
  consensus_report?: string | null;
};

export type TestResult = {
  id: string;
  created_at: string;
  tested_model: string;
  project: ProjectInfos & { call_graph: JudgedCallGraphNode };
};

/* ─────────────────────────────────────────
   Color helpers  (continuous 0→10)
───────────────────────────────────────── */

function scoreColor(score: number): string {
  const s = Math.max(0, Math.min(10, score));
  const GREEN: [number, number, number] = [22, 163, 74];
  const YELLOW: [number, number, number] = [234, 179, 8];
  const RED: [number, number, number] = [220, 38, 38];
  const lerp = (
    a: [number, number, number],
    b: [number, number, number],
    t: number,
  ) =>
    `rgb(${Math.round(a[0] + (b[0] - a[0]) * t)},${Math.round(a[1] + (b[1] - a[1]) * t)},${Math.round(a[2] + (b[2] - a[2]) * t)})`;
  return s <= 5 ? lerp(GREEN, YELLOW, s / 5) : lerp(YELLOW, RED, (s - 5) / 5);
}

function metricColor(v: number): string {
  // 0→1: red→green
  const r = Math.round(220 + (22 - 220) * v);
  const g = Math.round(38 + (163 - 38) * v);
  const b = Math.round(38 + (74 - 38) * v);
  return `rgb(${r},${g},${b})`;
}

/* ─────────────────────────────────────────
   Sub-components
───────────────────────────────────────── */

/** Horizontal score bar — continuous gradient, 0-10 */
function ScoreBar({
  score,
  max = 10,
  label,
}: {
  score: number;
  max?: number;
  label?: string;
}) {
  const pct = (score / max) * 100;
  const color = max === 10 ? scoreColor(score) : metricColor(score);
  return (
    <div className="flex items-center gap-2 w-full">
      {label && (
        <span className="text-xs w-36 shrink-0 opacity-70 truncate">
          {label}
        </span>
      )}
      <div className="relative flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(30,41,59,0.5)" }}>
        <div
          className="absolute inset-y-0 left-0 rounded-full transition-all duration-700"
          style={{
            width: `${pct}%`,
            background:
              max === 10
                ? "linear-gradient(90deg,#16a34a,#eab308,#dc2626)"
                : `linear-gradient(90deg,#dc2626,#eab308,#16a34a)`,
            clipPath: `inset(0 ${100 - pct}% 0 0)`,
          }}
        />
      </div>
      <span
        className="text-xs font-mono font-bold w-8 text-right"
        style={{ color }}
      >
        {score.toFixed(max === 1 ? 2 : 1)}
      </span>
    </div>
  );
}

/** Score pill badge */
function ScorePill({
  score,
  size = "md",
}: {
  score: number;
  size?: "sm" | "md";
}) {
  const color = scoreColor(score);
  const pad = size === "sm" ? "px-2 py-0.5 text-xs" : "px-3 py-1 text-sm";
  return (
    <span
      className={`${pad} rounded-full font-bold border`}
      style={{ color, borderColor: color, background: `${color}18` }}
    >
      {score.toFixed(1)}
    </span>
  );
}

/** Delta badge: tested score vs judge average */
function DeltaBadge({
  tested,
  judgeAvg,
}: {
  tested: number;
  judgeAvg: number;
}) {
  const delta = tested - judgeAvg;
  const abs = Math.abs(delta).toFixed(1);
  if (Math.abs(delta) < 0.3)
    return <span className="text-xs opacity-40">≈</span>;
  const color = delta > 0 ? "#dc2626" : "#16a34a";
  const sign = delta > 0 ? "▲" : "▼";
  return (
    <span className="text-xs font-mono font-bold" style={{ color }}>
      {sign}
      {abs}
    </span>
  );
}

/** Shows whether a consensus was reached and how tight the spread is */
function ConsensusBadge({
  node,
  global = false,
}: {
  node: JudgedCallGraphNode;
  global?: boolean;
}) {
  const spread = scoreSpread(node, global);
  const consensus = hasConsensus(node, global);

  if (spread === null) return null;

  // Tight consensus: spread ≤ 1.5  →  green lock
  // Moderate:        spread ≤ 3.0  →  yellow ~
  // Divergent:       spread  > 3.0 →  red !
  const tight = spread <= 1.5;
  const moderate = spread <= 3.0;
  const color = tight ? "#16a34a" : moderate ? "#eab308" : "#dc2626";
  const icon = tight ? "🔒" : moderate ? "~" : "⚡";
  const label = `spread ${spread.toFixed(1)}`;
  const title = consensus
    ? `Consensus reached — score spread: ${spread.toFixed(1)}`
    : `Revised scores spread: ${spread.toFixed(1)} (no consensus synthesis)`;

  return (
    <span
      className="text-xs font-mono px-1 rounded border"
      style={{ color, borderColor: color, opacity: 0.85 }}
      title={title}
    >
      {icon} {label}
    </span>
  );
}

/** Markdown modal */
function ReportModal({
  open,
  onClose,
  title,
  content,
  isDarkMode,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  content: string;
  isDarkMode: boolean;
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      sx={{ display: "flex", alignItems: "center", justifyContent: "center" }}
    >
      <div
        className="w-[800px] max-h-[80vh] overflow-y-auto rounded-2xl p-8 shadow-2xl border"
        style={{
          background: isDarkMode ? "#0d1828" : "#ffffff",
          color: isDarkMode ? "#e2e8f0" : "#1e293b",
          borderColor: isDarkMode ? "#1b2d4f" : "#bfdbfe",
          boxShadow: "0 0 60px rgba(59,130,246,0.15)",
        }}
      >
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-lg font-bold font-mono">{title}</h3>
          <button
            onClick={onClose}
            className="opacity-50 hover:opacity-100 text-xl cursor-pointer"
          >
            ✕
          </button>
        </div>
        <div className="prose prose-sm dark:prose-invert max-w-none">
          <ReactMarkdown>{content}</ReactMarkdown>
        </div>
      </div>
    </Modal>
  );
}

/* ─────────────────────────────────────────
   Collect all judged nodes recursively
───────────────────────────────────────── */

function collectJudgedNodes(
  node: JudgedCallGraphNode,
  visited = new Set<string>(),
): JudgedCallGraphNode[] {
  const key = `${node.func_name}_${node.locations?.map((l) => `${l.file}:${l.line}`).join("|")}`;
  if (visited.has(key)) return [];
  visited.add(key);

  const hasCves = (node.library?.cves?.length ?? 0) > 0;
  const hasJudge =
    node.judge_ai_vulnerability_scores &&
    Object.keys(node.judge_ai_vulnerability_scores).length > 0;

  const results: JudgedCallGraphNode[] = [];
  if (hasCves || hasJudge) results.push(node);
  node.children?.forEach((c) =>
    results.push(...collectJudgedNodes(c as JudgedCallGraphNode, visited)),
  );
  return results;
}

/** Best available local score: consensus → revised median → simple avg */
function judgeAvgScore(node: JudgedCallGraphNode): number | null {
  if (node.consensus_local_score != null) return node.consensus_local_score;
  const revised = Object.values(node.judge_revised_scores ?? {});
  if (revised.length) {
    const sorted = [...revised].sort((a, b) => a - b);
    return sorted[Math.floor(sorted.length / 2)];
  }
  const scores = Object.values(node.judge_ai_vulnerability_scores ?? {});
  if (!scores.length) return null;
  return scores.reduce((a, b) => a + b, 0) / scores.length;
}

/** Best available global score: consensus → revised median → simple avg */
function judgeAvgGlobalScore(node: JudgedCallGraphNode): number | null {
  if (node.consensus_global_score != null) return node.consensus_global_score;
  const revised = Object.values(node.judge_revised_global_scores ?? {});
  if (revised.length) {
    const sorted = [...revised].sort((a, b) => a - b);
    return sorted[Math.floor(sorted.length / 2)];
  }
  const scores = Object.values(node.judge_ai_global_scores ?? {});
  if (!scores.length) return null;
  return scores.reduce((a, b) => a + b, 0) / scores.length;
}

/** Spread of revised scores — indicates consensus quality */
function scoreSpread(node: JudgedCallGraphNode, global = false): number | null {
  const raw = global
    ? node.judge_revised_global_scores
    : node.judge_revised_scores;
  const scores = Object.values(raw ?? {});
  if (scores.length < 2) return null;
  return Math.max(...scores) - Math.min(...scores);
}

/** True when we have a Phase-3 consensus score */
function hasConsensus(node: JudgedCallGraphNode, global = false): boolean {
  return global
    ? node.consensus_global_score != null
    : node.consensus_local_score != null;
}

/* ─────────────────────────────────────────
   Main Panel — selected test overview
───────────────────────────────────────── */

function TestOverview({
  test,
  isDarkMode,
  onSelectNode,
  selectedNode,
}: {
  test: TestResult;
  isDarkMode: boolean;
  onSelectNode: (n: JudgedCallGraphNode) => void;
  selectedNode: JudgedCallGraphNode | null;
}) {
  const dk = isDarkMode;
  const OV_SURFACE = dk ? "#0d1828" : "#ffffff";
  const OV_BORDER  = dk ? "#1b2d4f" : "#bfdbfe";
  const OV_MUTED   = "#64748b";
  const cg = test.project.call_graph;
  const judgeModels = Object.keys(cg.judge_ai_global_scores ?? {});
  const globalTested = cg.global_score ?? null;
  const globalJudgeAvg = judgeAvgGlobalScore(cg);
  const nodes = collectJudgedNodes(cg);

  const sep = "";

  const [reportModal, setReportModal] = useState<{
    title: string;
    content: string;
  } | null>(null);

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* ── Global scores header ── */}
      <div className="shrink-0 border-b px-6 py-4" style={{ borderColor: OV_BORDER }}>
        <div className="flex items-start justify-between gap-8 flex-wrap">
          {/* Tested model global */}
          <div>
            <p className="text-xs font-mono opacity-50 mb-1 uppercase tracking-widest">
              Tested Model
            </p>
            <p className="font-bold text-base mb-1">{test.tested_model}</p>
            {globalTested !== null && (
              <div className="flex items-center gap-3 flex-wrap">
                <ScorePill score={globalTested} />
                {globalJudgeAvg !== null && (
                  <DeltaBadge tested={globalTested} judgeAvg={globalJudgeAvg} />
                )}
                {cg.global_report && (
                  <button
                    onClick={() =>
                      setReportModal({
                        title: `Global Report — ${test.tested_model}`,
                        content: cg.global_report!,
                      })
                    }
                    className="text-xs opacity-50 hover:opacity-100 underline cursor-pointer"
                  >
                    read report
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Consensus score (Phase-3) */}
          {globalJudgeAvg !== null && (
            <div>
              <p className="text-xs font-mono opacity-50 mb-1 uppercase tracking-widest">
                {hasConsensus(cg, true) ? "Consensus Score" : "Revised Median"}
              </p>
              <div className="flex items-center gap-2 flex-wrap">
                <ScorePill score={globalJudgeAvg} />
                <ConsensusBadge node={cg} global />
                {cg.consensus_report && (
                  <button
                    onClick={() =>
                      setReportModal({
                        title: "Consensus Report",
                        content: cg.consensus_report!,
                      })
                    }
                    className="text-xs opacity-50 hover:opacity-100 underline cursor-pointer"
                  >
                    read consensus
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Judges — show revised score if available */}
          {judgeModels.length > 0 && (
            <div>
              <p className="text-xs font-mono opacity-50 mb-2 uppercase tracking-widest">
                Judge Models
              </p>
              <div className="flex flex-wrap gap-4">
                {judgeModels.map((m) => {
                  const initial = cg.judge_ai_global_scores?.[m];
                  const revised = cg.judge_revised_global_scores?.[m];
                  return (
                    <div key={m} className="flex flex-col gap-1 items-start">
                      <span className="text-xs opacity-60 font-mono truncate max-w-[140px]">
                        {m}
                      </span>
                      <div className="flex items-center gap-1">
                        {revised !== undefined ? (
                          <>
                            <ScorePill score={revised} size="sm" />
                            <span className="text-[10px] opacity-40">rev</span>
                          </>
                        ) : (
                          initial !== undefined && (
                            <ScorePill score={initial} size="sm" />
                          )
                        )}
                        {revised !== undefined &&
                          initial !== undefined &&
                          Math.abs(revised - initial) >= 0.5 && (
                            <span className="text-[10px] opacity-50 font-mono">
                              (was {initial.toFixed(1)})
                            </span>
                          )}
                      </div>
                      {cg.judge_ai_global_reports?.[m] && (
                        <button
                          onClick={() =>
                            setReportModal({
                              title: `Global Report — ${m}`,
                              content: cg.judge_ai_global_reports![m],
                            })
                          }
                          className="text-xs opacity-40 hover:opacity-80 underline cursor-pointer"
                        >
                          read
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Global metric averages */}
          {cg.judge_global_ai_metric_scores && judgeModels.length > 0 && (
            <div className="min-w-[220px]">
              <p className="text-xs font-mono opacity-50 mb-2 uppercase tracking-widest">
                Avg. Metrics (judges)
              </p>
              {(() => {
                // Average each metric across all judges
                const allMetrics = new Set<string>();
                judgeModels.forEach((m) => {
                  Object.keys(
                    cg.judge_global_ai_metric_scores?.[m] ?? {},
                  ).forEach((k) => allMetrics.add(k));
                });
                return Array.from(allMetrics).map((metric) => {
                  const vals = judgeModels
                    .map((m) => cg.judge_global_ai_metric_scores?.[m]?.[metric])
                    .filter((v): v is number => v !== undefined);
                  const avg = vals.length
                    ? vals.reduce((a, b) => a + b, 0) / vals.length
                    : null;
                  if (avg === null) return null;
                  return (
                    <ScoreBar
                      key={metric}
                      score={avg}
                      max={1}
                      label={metric.replace(/_/g, " ")}
                    />
                  );
                });
              })()}
            </div>
          )}
        </div>
      </div>

      {/* ── Node table ── */}
      <div className="flex-1 overflow-y-auto px-6 py-4">
        <p className="text-xs font-mono opacity-40 uppercase tracking-widest mb-3">
          Vulnerable Nodes ({nodes.length})
        </p>

        {nodes.length === 0 ? (
          <div className="flex items-center justify-center h-32 opacity-40">
            No vulnerable nodes found
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {/* Header row */}
            <div
              className={`grid text-xs font-mono opacity-40 uppercase tracking-wider px-3 py-1`}
              style={{ gridTemplateColumns: "1fr 100px 110px 80px 80px" }}
            >
              <span>Function</span>
              <span className="text-center">Tested</span>
              <span className="text-center">Consensus</span>
              <span className="text-center">Delta</span>
              <span className="text-center">CVEs</span>
            </div>

            {nodes.map((node, i) => {
              const tested = node.ai_vulnerability_score ?? null;
              const jAvg = judgeAvgScore(node);
              const cves = node.library?.cves?.length ?? 0;
              const isSelected =
                selectedNode?.func_name === node.func_name &&
                JSON.stringify(selectedNode?.locations) ===
                  JSON.stringify(node.locations);

              return (
                <div
                  key={i}
                  onClick={() => onSelectNode(node)}
                  className={`grid items-center px-3 py-2.5 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? "border-blue-500/60 bg-blue-500/10"
                      : "hover:border-blue-500/30 hover:bg-blue-500/5"
                  }`}
                  style={{
                    gridTemplateColumns: "1fr 100px 110px 80px 80px",
                    ...(!isSelected ? { borderColor: OV_BORDER, background: dk ? "rgba(13,24,40,0.5)" : "#f8faff" } : {}),
                  }}
                >
                  {/* Function name + library */}
                  <div className="min-w-0">
                    <p className="font-mono text-sm font-semibold truncate">
                      {node.func_name}
                    </p>
                    {node.library && (
                      <p className="text-xs opacity-50 truncate">
                        {node.library.name} {node.library.version}
                      </p>
                    )}
                  </div>

                  {/* Tested score */}
                  <div className="flex justify-center">
                    {tested !== null ? (
                      <ScorePill score={tested} size="sm" />
                    ) : (
                      <span className="opacity-30 text-xs">—</span>
                    )}
                  </div>

                  {/* Consensus / revised median score + spread badge */}
                  <div className="flex flex-col items-center gap-0.5">
                    {jAvg !== null ? (
                      <>
                        <ScorePill score={jAvg} size="sm" />
                        <ConsensusBadge node={node} />
                      </>
                    ) : (
                      <span className="opacity-30 text-xs">—</span>
                    )}
                  </div>

                  {/* Delta */}
                  <div className="flex justify-center">
                    {tested !== null && jAvg !== null ? (
                      <DeltaBadge tested={tested} judgeAvg={jAvg} />
                    ) : (
                      <span className="opacity-30 text-xs">—</span>
                    )}
                  </div>

                  {/* CVE count */}
                  <div className="flex justify-center">
                    {cves > 0 ? (
                      <span className="text-xs font-bold px-1.5 py-0.5 rounded bg-red-500/10 text-red-500">
                        {cves}
                      </span>
                    ) : (
                      <span className="opacity-30 text-xs">0</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {reportModal && (
        <ReportModal
          open
          onClose={() => setReportModal(null)}
          title={reportModal.title}
          content={reportModal.content}
          isDarkMode={isDarkMode}
        />
      )}
    </div>
  );
}

/* ─────────────────────────────────────────
   Sidebar — selected node detail
───────────────────────────────────────── */

function NodeDetailSidebar({
  node,
  testedModel,
  isDarkMode,
}: {
  node: JudgedCallGraphNode;
  testedModel: string;
  isDarkMode: boolean;
}) {
  const dk = isDarkMode;
  const ND_BORDER = dk ? "#1b2d4f" : "#bfdbfe";
  const judgeModels = Object.keys(node.judge_ai_vulnerability_scores ?? {});
  const [reportModal, setReportModal] = useState<{
    title: string;
    content: string;
  } | null>(null);

  const testedScore = node.ai_vulnerability_score ?? null;
  const jAvg = judgeModels.length
    ? judgeModels
        .map((m) => node.judge_ai_vulnerability_scores![m])
        .reduce((a, b) => a + b, 0) / judgeModels.length
    : null;

  // Average metric scores across all judges
  const allMetrics = new Set<string>();
  judgeModels.forEach((m) => {
    Object.keys(node.judge_ai_metric_scores?.[m] ?? {}).forEach((k) =>
      allMetrics.add(k),
    );
  });
  const avgMetrics: Record<string, number> = {};
  allMetrics.forEach((metric) => {
    const vals = judgeModels
      .map((m) => node.judge_ai_metric_scores?.[m]?.[metric])
      .filter((v): v is number => v !== undefined);
    if (vals.length)
      avgMetrics[metric] = vals.reduce((a, b) => a + b, 0) / vals.length;
  });

  return (
    <div className="overflow-y-auto h-full flex flex-col gap-5 text-sm">
      {/* Function header */}
      <div>
        <p className="text-xs font-mono opacity-40 uppercase tracking-widest mb-1">
          Selected Node
        </p>
        <p className="font-mono font-bold text-base leading-tight">
          {node.func_name}
        </p>
        {node.library && (
          <p className="text-xs opacity-50 mt-0.5">
            {node.library.name} v{node.library.version}
          </p>
        )}
      </div>

      <div className="h-px" style={{ background: ND_BORDER }} />

      {/* Score comparison */}
      <div>
        <p className="text-xs font-mono opacity-40 uppercase tracking-widest mb-3">
          Score Comparison
        </p>

        {/* Tested */}
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs opacity-60 truncate max-w-[140px]">
            {testedModel}
          </span>
          <div className="flex items-center gap-2">
            {testedScore !== null && (
              <ScorePill score={testedScore} size="sm" />
            )}
            {node.ai_report && (
              <button
                onClick={() =>
                  setReportModal({
                    title: `Report — ${testedModel}`,
                    content: node.ai_report!,
                  })
                }
                className="text-xs opacity-40 hover:opacity-80 underline cursor-pointer"
              >
                read
              </button>
            )}
          </div>
        </div>

        {/* Score bar — tested */}
        {testedScore !== null && (
          <div className="mb-4">
            <ScoreBar score={testedScore} />
          </div>
        )}

        {/* Each judge — initial → revised */}
        {judgeModels.map((m) => {
          const initial = node.judge_ai_vulnerability_scores?.[m];
          const revised = node.judge_revised_scores?.[m];
          const displayScore = revised ?? initial;
          const changed =
            revised !== undefined &&
            initial !== undefined &&
            Math.abs(revised - initial) >= 0.5;
          return (
            <div key={m} className="mb-3">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs opacity-50 truncate max-w-[140px] font-mono">
                  {m}
                </span>
                <div className="flex items-center gap-1.5">
                  {displayScore !== undefined && (
                    <ScorePill score={displayScore} size="sm" />
                  )}
                  {revised !== undefined && (
                    <span className="text-[10px] font-mono opacity-50">
                      rev
                    </span>
                  )}
                  {changed && initial !== undefined && (
                    <span className="text-[10px] font-mono opacity-40">
                      (was {initial.toFixed(1)})
                    </span>
                  )}
                  {node.judge_ai_reports?.[m] && (
                    <button
                      onClick={() =>
                        setReportModal({
                          title: `Report — ${m}`,
                          content: node.judge_ai_reports![m],
                        })
                      }
                      className="text-xs opacity-40 hover:opacity-80 underline cursor-pointer"
                    >
                      read
                    </button>
                  )}
                </div>
              </div>
              {displayScore !== undefined && <ScoreBar score={displayScore} />}
            </div>
          );
        })}

        {/* Consensus row */}
        {node.consensus_local_score != null && (
          <div
            className={`mt-1 mb-3 p-2 rounded-lg border ${dk ? "border-blue-500/30 bg-blue-500/5" : "border-blue-300 bg-blue-50"}`}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-mono font-semibold opacity-70">
                Consensus
              </span>
              <div className="flex items-center gap-2">
                <ScorePill score={node.consensus_local_score} size="sm" />
                <ConsensusBadge node={node} />
              </div>
            </div>
            <ScoreBar score={node.consensus_local_score} />
          </div>
        )}

        {/* Delta summary */}
        {testedScore !== null && jAvg !== null && (
          <div
            className="mt-2 p-2 rounded-lg border text-xs"
            style={{ borderColor: ND_BORDER, background: dk ? "rgba(13,24,40,0.5)" : "#f8faff" }}
          >
            <span className="opacity-50">
              vs. {hasConsensus(node) ? "consensus" : "revised median"}{" "}
            </span>
            <DeltaBadge tested={testedScore} judgeAvg={jAvg} />
            <span className="opacity-50 ml-2">({jAvg.toFixed(1)})</span>
          </div>
        )}
      </div>

      {/* Metrics */}
      {Object.keys(avgMetrics).length > 0 && (
        <>
          <div className="h-px" style={{ background: ND_BORDER }} />
          <div>
            <p className="text-xs font-mono opacity-40 uppercase tracking-widest mb-3">
              Avg. Quality Metrics
            </p>
            <div className="flex flex-col gap-2">
              {Object.entries(avgMetrics).map(([k, v]) => (
                <ScoreBar
                  key={k}
                  score={v}
                  max={1}
                  label={k.replace(/_/g, " ")}
                />
              ))}
            </div>
          </div>
        </>
      )}

      {/* CVEs */}
      {(node.library?.cves?.length ?? 0) > 0 && (
        <>
          <div className="h-px" style={{ background: ND_BORDER }} />
          <div>
            <p className="text-xs font-mono opacity-40 uppercase tracking-widest mb-2">
              CVEs ({node.library!.cves.length})
            </p>
            <div className="flex flex-col gap-2">
              {node.library!.cves.map((cve) => (
                <div
                  key={cve.id}
                  className="text-xs p-2 rounded-lg border"
                  style={{ borderColor: ND_BORDER, background: dk ? "rgba(13,24,40,0.5)" : "#f8faff" }}
                >
                  <div className="flex items-center justify-between gap-2 mb-0.5">
                    <span className="font-mono font-bold">{cve.id}</span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        cve.severity === "CRITICAL"
                          ? "bg-red-500/20 text-red-400"
                          : cve.severity === "HIGH"
                            ? "bg-orange-500/20 text-orange-400"
                            : cve.severity === "MEDIUM"
                              ? "bg-yellow-500/20 text-yellow-400"
                              : "bg-green-500/20 text-green-400"
                      }`}
                    >
                      {cve.severity}
                    </span>
                  </div>
                  <p className="opacity-60 leading-relaxed line-clamp-3">
                    {cve.description}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {/* Call locations */}
      {node.locations?.length > 0 && (
        <>
          <div className="h-px" style={{ background: ND_BORDER }} />
          <div>
            <p className="text-xs font-mono opacity-40 uppercase tracking-widest mb-2">
              Called at
            </p>
            {node.locations.map((loc, i) => (
              <p key={i} className="text-xs font-mono opacity-50 leading-5">
                • {loc.file.replace(/^\/tmp\/[^/]+\//, "")}:{loc.line}
              </p>
            ))}
          </div>
        </>
      )}

      {reportModal && (
        <ReportModal
          open
          onClose={() => setReportModal(null)}
          title={reportModal.title}
          content={reportModal.content}
          isDarkMode={isDarkMode}
        />
      )}
    </div>
  );
}

/* ─────────────────────────────────────────
   Root component
───────────────────────────────────────── */

export default function TestsPage({
  serverTests,
  testModels,
  defaultJudgeModels,
}: {
  serverTests: TestResult[];
  testModels: string[];
  defaultJudgeModels?: string[];
}) {
  const searchParams = useSearchParams();
  const [isDarkMode, setIsDarkMode] = useState(false);

  useEffect(() => {
    const dm = searchParams.get("isDarkModeInit");
    setIsDarkMode(dm === "true");
  }, [searchParams]);

  const dk = isDarkMode;
  const BG     = dk ? "#070c18" : "#f0f5ff";
  const SURFACE = dk ? "#0d1828" : "#ffffff";
  const BORDER  = dk ? "#1b2d4f" : "#bfdbfe";
  const TEXT    = dk ? "#e2e8f0" : "#0f172a";
  const MUTED   = "#64748b";


  const [tests, setTests] = useState<TestResult[]>(serverTests);
  const [selectedTest, setSelectedTest] = useState<TestResult | null>(null);
  const [selectedNode, setSelectedNode] = useState<JudgedCallGraphNode | null>(
    null,
  );
  const [files, setFiles] = useState<FileList | null>(null);
  const [loading, setLoading] = useState(false);
  const [openCreateModal, setOpenCreateModal] = useState(false);
  const [testedModel, setTestedModel] = useState<string | null>(null);
  const [judgeModels, setJudgeModels] = useState<string[]>(
    defaultJudgeModels ?? [],
  );

  const toggleJudgeModel = (m: string) =>
    setJudgeModels((prev) =>
      prev.includes(m) ? prev.filter((x) => x !== m) : [...prev, m],
    );

  const handleCreateTest = async () => {
    if (!files || !testedModel || judgeModels.length === 0) return;
    setLoading(true);
    try {
      const zip = new JSZip();
      Array.from(files).forEach((f) =>
        zip.file(f.webkitRelativePath || f.name, f),
      );
      const zipBlob = await zip.generateAsync({ type: "blob" });
      const formData = new FormData();
      formData.append("project", zipBlob, "project.zip");
      formData.append("testedModel", testedModel);
      judgeModels.forEach((m) => formData.append("judgeModels", m));

      const res = await fetch(`${ENDPOINT}/test_results`, {
        method: "POST",
        body: formData,
      });
      if (!res.ok) throw new Error("Failed to create test");

      const newTest: TestResult = await res.json();
      setTests((prev) => [...prev, newTest]);
      setOpenCreateModal(false);
      setFiles(null);
      setTestedModel(null);
      setJudgeModels([]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="h-screen flex flex-col overflow-hidden"
      style={{ background: BG, color: TEXT }}
    >
      {/* ── Header ── */}
      <header
        className="shrink-0 flex items-center justify-between px-6 py-3 border-b z-50"
        style={{
          background: dk ? "rgba(7,12,24,0.95)" : "rgba(240,245,255,0.95)",
          borderColor: BORDER,
          backdropFilter: "blur(12px)",
        }}
      >
        <div className="flex items-center gap-3">
          <ArgusEye size={28} />
          <div className="flex flex-col leading-none">
            <span
              className="text-base font-black tracking-widest uppercase"
              style={{ color: "#60a5fa", letterSpacing: "0.2em" }}
            >
              Argus
            </span>
            <span className="text-[10px] uppercase tracking-widest" style={{ color: MUTED }}>
              Model Evaluation
            </span>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <DarkModeToggle isDarkMode={isDarkMode} setIsDarkMode={setIsDarkMode} />
          <ConfigMenuTest isDarkMode={isDarkMode} />
        </div>
      </header>

      {/* ── Three-column content ── */}
      <div className="flex flex-1 min-h-0">

      {/* ── Left: tests list ── */}
      <div
        className="w-72 shrink-0 border-r flex flex-col"
        style={{ borderColor: BORDER, background: SURFACE }}
      >
        <div className="px-4 py-4 flex items-center justify-between border-b" style={{ borderColor: BORDER }}>
          <h2 className="font-bold text-sm uppercase tracking-widest" style={{ color: "#60a5fa" }}>Tests</h2>
          <button
            className="px-3 py-1.5 text-sm rounded-lg cursor-pointer font-semibold transition-all hover:scale-105"
            style={{
              background: "linear-gradient(135deg, #1d4ed8, #3b82f6)",
              boxShadow: "0 0 14px rgba(59,130,246,0.3)",
              color: "#fff",
            }}
            onClick={() => setOpenCreateModal(true)}
          >
            + New
          </button>
        </div>

        <div className="overflow-y-auto flex-1 p-3 flex flex-col gap-1">
          {tests.length === 0 && (
            <p className="text-xs opacity-40 text-center mt-8">No tests yet</p>
          )}
          {tests.map((test) => {
            const cg = test.project.call_graph;
            const gScore = cg.global_score ?? null;
            const jAvg = judgeAvgGlobalScore(cg);
            const isSelected = selectedTest?.id === test.id;
            return (
              <div
                key={test.id}
                onClick={() => {
                  setSelectedTest(test);
                  setSelectedNode(null);
                }}
                className={`p-3 rounded-xl cursor-pointer transition-all border ${
                  isSelected
                    ? "border-blue-500/60 bg-blue-500/10"
                    : "border-transparent hover:border-blue-500/20 hover:bg-blue-500/5"
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="font-semibold text-sm truncate">
                      {test.project.name ?? "Unnamed"}
                    </p>
                    <p className="text-xs opacity-50 font-mono truncate mt-0.5">
                      {test.tested_model}
                    </p>
                  </div>
                  {gScore !== null && <ScorePill score={gScore} size="sm" />}
                </div>
                {gScore !== null && jAvg !== null && (
                  <div className="mt-2">
                    <ScoreBar score={gScore} />
                  </div>
                )}
                <p className="text-xs opacity-30 mt-1.5">
                  {new Date(test.created_at).toLocaleDateString()}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Center: test overview ── */}
      <div
        className="flex-1 flex flex-col min-h-0 border-r"
        style={{ borderColor: BORDER }}
      >
        {/* Header */}
        <div
          className="shrink-0 px-6 py-4 border-b"
          style={{ borderColor: BORDER }}
        >
          <h1 className="text-xl font-bold tracking-tight" style={{ color: TEXT }}>
            Results
          </h1>
          {selectedTest && (
            <p className="text-xs font-mono mt-0.5" style={{ color: MUTED }}>
              {selectedTest.project.name} ·{" "}
              {new Date(selectedTest.created_at).toLocaleString()}
            </p>
          )}
        </div>

        <div className="flex-1 overflow-hidden">
          {selectedTest ? (
            <TestOverview
              test={selectedTest}
              isDarkMode={isDarkMode}
              onSelectNode={setSelectedNode}
              selectedNode={selectedNode}
            />
          ) : (
            <div className="h-full flex flex-col items-center justify-center gap-3 opacity-30">
              <ArgusEye size={48} />
              <p className="text-sm tracking-widest uppercase" style={{ color: MUTED }}>
                Select a test to view results
              </p>
            </div>
          )}
        </div>
      </div>

      {/* ── Right: node detail sidebar ── */}
      <div
        className="w-96 shrink-0 flex flex-col"
        style={{ background: SURFACE }}
      >
        <div
          className="shrink-0 px-5 py-4 border-b"
          style={{ borderColor: BORDER }}
        >
          <h2 className="font-bold text-sm uppercase tracking-widest" style={{ color: "#60a5fa" }}>Node Details</h2>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-4">
          {selectedNode ? (
            <NodeDetailSidebar
              node={selectedNode}
              testedModel={selectedTest?.tested_model ?? ""}
              isDarkMode={isDarkMode}
            />
          ) : (
            <p className="text-xs text-center mt-8" style={{ color: MUTED }}>
              Select a node from the table
            </p>
          )}
        </div>
      </div>

      </div>{/* end three-column */}

      {/* ── Create modal ── */}
      <Modal
        open={openCreateModal}
        onClose={() => setOpenCreateModal(false)}
        sx={{ display: "flex", alignItems: "center", justifyContent: "center" }}
      >
        <div
          className="relative px-12 py-8 rounded-2xl flex flex-col items-center gap-5 w-[480px] max-h-[90vh] overflow-y-auto shadow-2xl border"
          style={{
            background: dk ? "rgba(13,24,40,0.97)" : "#ffffff",
            backdropFilter: "blur(12px)",
            borderColor: BORDER,
            boxShadow: "0 0 60px rgba(59,130,246,0.15)",
          }}
        >
          <Button
            variant="plain"
            onClick={() => setOpenCreateModal(false)}
            sx={{
              position: "absolute",
              top: 12,
              right: 12,
              color: dk ? "#9ca3af" : "#6b7280",
            }}
          >
            ✕
          </Button>

          <Typography
            level="h4"
            sx={{ color: dk ? "#e5e7eb" : "#111", fontWeight: 700 }}
          >
            New Evaluation Test
          </Typography>

          {/* Folder */}
          <div className="w-full flex flex-col items-center gap-2">
            <FolderPicker
              buttonText="Select Project Folder"
              onSelect={setFiles}
              isDarkMode={dk}
            />
            {files && (
              <Typography level="body-xs" sx={{ opacity: 0.6 }}>
                {files.length} files selected
              </Typography>
            )}
          </div>

          <Divider
            sx={{ width: "100%", borderColor: dk ? "#374151" : "#e5e7eb" }}
          />

          {/* Tested model */}
          <div className="w-full">
            <Typography
              level="title-sm"
              sx={{ color: dk ? "#e5e7eb" : "#111", mb: 1.5 }}
            >
              Tested Model
            </Typography>
            <RadioGroup orientation="vertical">
              {testModels.map((m) => (
                <Radio
                  key={m}
                  label={m}
                  checked={testedModel === m}
                  onChange={() => setTestedModel(m)}
                  sx={{ color: dk ? "#e5e7eb" : "#111", mb: 0.5 }}
                />
              ))}
            </RadioGroup>
          </div>

          <Divider
            sx={{ width: "100%", borderColor: dk ? "#374151" : "#e5e7eb" }}
          />

          {/* Judge models */}
          <div className="w-full">
            <Typography
              level="title-sm"
              sx={{ color: dk ? "#e5e7eb" : "#111", mb: 1.5 }}
            >
              Judge Models
            </Typography>
            <Stack spacing={0.5}>
              {(defaultJudgeModels ?? []).map((m: string) => (
                <Checkbox
                  key={m}
                  label={m}
                  checked={judgeModels.includes(m)}
                  onChange={() => toggleJudgeModel(m)}
                  sx={{ color: dk ? "#e5e7eb" : "#111" }}
                />
              ))}
            </Stack>
          </div>

          <Divider
            sx={{ width: "100%", borderColor: dk ? "#374151" : "#e5e7eb" }}
          />

          <button
            onClick={handleCreateTest}
            disabled={!files || !testedModel || judgeModels.length === 0}
            className="w-full py-3 rounded-xl font-bold text-sm transition-all"
            style={
              !files || !testedModel || judgeModels.length === 0
                ? { background: "#1e293b", color: "#475569", cursor: "not-allowed" }
                : {
                    background: "linear-gradient(135deg, #1d4ed8, #3b82f6)",
                    boxShadow: "0 0 18px rgba(59,130,246,0.4)",
                    color: "#fff",
                    cursor: "pointer",
                  }
            }
          >
            Launch Test
          </button>
        </div>
      </Modal>

      {/* ── Loading modal ── */}
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
          <CircularProgress size="lg" sx={{ color: "#3b82f6" }} />
          <p className="text-sm tracking-wider uppercase" style={{ color: "#93c5fd" }}>
            Running evaluation…
          </p>
        </div>
      </Modal>
    </div>
  );
}
