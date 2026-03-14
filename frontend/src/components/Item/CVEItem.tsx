"use client";
import { CVE } from "@/app/page";
import { useState } from "react";
import Modal from "@mui/joy/Modal";
import ModalDialog from "@mui/joy/ModalDialog";
import Typography from "@mui/joy/Typography";
import Button from "@mui/joy/Button";

export default function CVEItem({
  cve,
  isDarkMode,
}: {
  cve: CVE;
  isDarkMode: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const [openExploit, setOpenExploit] = useState(false);

  const MAX_CHARS = 30;
  const isLong = cve.description.length > MAX_CHARS;
  const text = expanded ? cve.description : cve.description.slice(0, MAX_CHARS);

  // const exploitDbToLink = (): string | null => {
  //   if (!cve.exploit_db) return null;
  //   const match = cve.exploit_db.match(/https?:\/\/[^\s]+/);
  //   return match ? match[0] : null;
  // };

  // const exploitLink = exploitDbToLink();

  const severityColor = (() => {
    switch (cve.severity.toLowerCase()) {
      case "low":
        return "#22c55e";
      case "medium":
        return "#eab308";
      case "high":
        return "#f97316";
      case "critical":
        return "#dc2626";
      default:
        return "#9ca3af";
    }
  })();

  return (
    <li className="mb-3">
      <div>
        • <span className="font-mono">{cve.id}</span> –{" "}
        <span style={{ color: severityColor }}>{cve.severity}</span> – CVSS:{" "}
        {cve.cvss}
      </div>

      <div className={isDarkMode ? "text-zinc-400" : "text-zinc-600"}>
        {text}
        {isLong && !expanded && "…"}
      </div>

      <div className="flex gap-2 mt-1 justify-between items-center">
        {isLong && (
          <button
            onClick={() => setExpanded(!expanded)}
            className={`text-sm cursor-pointer hover:underline ${
              isDarkMode ? "text-blue-400" : "text-blue-600"
            }`}
          >
            {expanded ? "Voir moins" : "Voir plus"}
          </button>
        )}

        {cve.exploit_db && (
          <button
            onClick={() => setOpenExploit(true)}
            className="text-sm px-2 py-0.5 cursor-pointer rounded border border-orange-500/40 text-orange-400 hover:bg-orange-500/10"
          >
            Exploit available
          </button>
        )}
      </div>

      {/* Modal exploit raw */}
      <Modal open={openExploit} onClose={() => setOpenExploit(false)}>
        <ModalDialog
          layout="center"
          sx={{ maxWidth: 700, maxHeight: "80vh", overflow: "auto" }}
        >
          <Typography level="h4" mb={1}>
            Exploit DB – contenu brut
          </Typography>
          <pre className="text-xs whitespace-pre-wrap break-words text-zinc-300 bg-zinc-900 p-3 rounded">
            {cve.exploit_db}
          </pre>
          <Button onClick={() => setOpenExploit(false)} sx={{ mt: 2 }}>
            Fermer
          </Button>
        </ModalDialog>
      </Modal>
    </li>
  );
}
