import React from "react";
import Modal from "@mui/joy/Modal";
import CircularProgress from "@mui/joy/CircularProgress";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";

type AiReportModalProps = {
  openModalAiReport: boolean;
  setOpenModalAiReport: (open: boolean) => void;
  aiScore: number | null;
  aiReport: string | null;
  isDarkMode?: boolean;
};

function ScoreBadge({ score }: { score: number }) {
  const color =
    score >= 7
      ? { bg: "rgba(220,38,38,0.15)", text: "#f87171", border: "rgba(220,38,38,0.3)" }
      : score >= 4
        ? { bg: "rgba(234,179,8,0.15)", text: "#fbbf24", border: "rgba(234,179,8,0.3)" }
        : { bg: "rgba(22,163,74,0.15)", text: "#4ade80", border: "rgba(22,163,74,0.3)" };

  return (
    <span
      className="px-3 py-1 rounded-full text-xs font-bold border tracking-wide"
      style={{ background: color.bg, color: color.text, borderColor: color.border }}
    >
      Score {score.toFixed(1)} / 10
    </span>
  );
}

export default function AiReportModal({
  openModalAiReport,
  setOpenModalAiReport,
  aiScore,
  aiReport,
  isDarkMode = true,
}: AiReportModalProps) {
  const SURFACE = isDarkMode ? "#0d1828" : "#ffffff";
  const BORDER  = isDarkMode ? "#1b2d4f" : "#bfdbfe";
  const TEXT    = isDarkMode ? "#e2e8f0" : "#0f172a";
  const MUTED   = isDarkMode ? "#64748b" : "#64748b";
  const CODE_BG = isDarkMode ? "#070c18" : "#f8faff";

  return (
    <Modal
      open={openModalAiReport}
      onClose={() => setOpenModalAiReport(false)}
      sx={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        backdropFilter: "blur(8px)",
        padding: "1rem",
      }}
    >
      <div
        className="w-full max-w-5xl max-h-[90vh] flex flex-col overflow-hidden rounded-xl border"
        style={{
          background: SURFACE,
          borderColor: "#3b82f6",
          boxShadow: "0 0 60px rgba(59,130,246,0.2)",
          color: TEXT,
        }}
      >
        {/* Header */}
        <div
          className="flex justify-between items-center px-6 py-4 border-b flex-shrink-0"
          style={{ borderColor: BORDER }}
        >
          <div className="flex items-center gap-4">
            <div>
              <h2
                className="text-lg font-bold tracking-tight"
                style={{ color: "#60a5fa" }}
              >
                AI Vulnerability Report
              </h2>
              <p className="text-xs mt-0.5" style={{ color: MUTED }}>
                Argus — powered by multi-model consensus
              </p>
            </div>
            {aiScore !== null && <ScoreBadge score={aiScore} />}
          </div>
          <button
            onClick={() => setOpenModalAiReport(false)}
            className="transition-colors cursor-pointer w-8 h-8 flex items-center justify-center rounded-lg border"
            style={{ borderColor: BORDER, color: MUTED }}
            onMouseEnter={(e) =>
              (e.currentTarget.style.color = "#e2e8f0")
            }
            onMouseLeave={(e) =>
              (e.currentTarget.style.color = MUTED)
            }
            aria-label="Close modal"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div
          className="flex-1 overflow-y-auto px-8 py-6"
          style={{ color: TEXT }}
        >
          {aiReport ? (
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                code: ({ node, className, children, ...props }) => {
                  const isInline = !className?.includes("language-");

                  if (isInline) {
                    return (
                      <code
                        className="text-sm font-mono px-1.5 py-0.5 rounded"
                        style={{
                          background: isDarkMode
                            ? "rgba(59,130,246,0.12)"
                            : "#eff6ff",
                          color: "#60a5fa",
                        }}
                      >
                        {children}
                      </code>
                    );
                  }

                  const languageMatch = /language-(\w+)/.exec(className || "");
                  const language = languageMatch ? languageMatch[1] : "text";

                  return (
                    <div className="relative mb-4 rounded-lg overflow-hidden border" style={{ borderColor: BORDER }}>
                      <SyntaxHighlighter
                        language={language}
                        style={oneDark}
                        PreTag="div"
                        wrapLines
                        showLineNumbers
                        lineNumberStyle={{ color: "#475569", paddingRight: 12 }}
                        customStyle={{ background: CODE_BG, margin: 0, borderRadius: 0 }}
                      >
                        {String(children).replace(/\n$/, "")}
                      </SyntaxHighlighter>

                      <button
                        className="absolute top-2 right-2 text-xs font-mono px-2 py-1 rounded border transition-colors cursor-pointer"
                        style={{
                          background: "rgba(59,130,246,0.15)",
                          borderColor: "rgba(59,130,246,0.3)",
                          color: "#93c5fd",
                        }}
                        onClick={() =>
                          navigator.clipboard.writeText(
                            String(children).replace(/\n$/, ""),
                          )
                        }
                      >
                        Copy
                      </button>
                    </div>
                  );
                },
                table: ({ children }) => (
                  <div className="overflow-x-auto my-4">
                    <table
                      className="table-auto border-collapse w-full text-sm"
                      style={{ borderColor: BORDER }}
                    >
                      {children}
                    </table>
                  </div>
                ),
                th: ({ children }) => (
                  <th
                    className="px-3 py-2 text-left font-semibold text-xs uppercase tracking-wide border"
                    style={{
                      borderColor: BORDER,
                      background: isDarkMode ? "#111f35" : "#eff6ff",
                      color: "#60a5fa",
                    }}
                  >
                    {children}
                  </th>
                ),
                td: ({ children }) => (
                  <td
                    className="px-3 py-2 align-top border"
                    style={{ borderColor: BORDER, color: TEXT }}
                  >
                    {children}
                  </td>
                ),
                h1: ({ children }) => (
                  <h1
                    className="text-2xl font-bold mt-6 mb-3 pb-2 border-b"
                    style={{ color: "#60a5fa", borderColor: BORDER }}
                  >
                    {children}
                  </h1>
                ),
                h2: ({ children }) => (
                  <h2
                    className="text-xl font-semibold mt-5 mb-2"
                    style={{ color: "#93c5fd" }}
                  >
                    {children}
                  </h2>
                ),
                h3: ({ children }) => (
                  <h3
                    className="text-base font-semibold mt-4 mb-2"
                    style={{ color: TEXT }}
                  >
                    {children}
                  </h3>
                ),
                p: ({ children }) => (
                  <p className="mb-3 leading-relaxed" style={{ color: TEXT }}>
                    {children}
                  </p>
                ),
                ul: ({ children }) => (
                  <ul
                    className="list-disc pl-5 mb-3 space-y-1"
                    style={{ color: TEXT }}
                  >
                    {children}
                  </ul>
                ),
                ol: ({ children }) => (
                  <ol
                    className="list-decimal pl-5 mb-3 space-y-1"
                    style={{ color: TEXT }}
                  >
                    {children}
                  </ol>
                ),
                a: ({ children, href }) => (
                  <a
                    href={href}
                    className="hover:underline"
                    style={{ color: "#60a5fa" }}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    {children}
                  </a>
                ),
                blockquote: ({ children }) => (
                  <blockquote
                    className="border-l-4 pl-4 my-3 italic"
                    style={{
                      borderColor: "#3b82f6",
                      background: "rgba(59,130,246,0.06)",
                      color: MUTED,
                    }}
                  >
                    {children}
                  </blockquote>
                ),
              }}
            >
              {aiReport}
            </ReactMarkdown>
          ) : (
            <div className="flex items-center justify-center h-full py-16">
              <CircularProgress sx={{ color: "#3b82f6" }} />
            </div>
          )}
        </div>
      </div>
    </Modal>
  );
}
