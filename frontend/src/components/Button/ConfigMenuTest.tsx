import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { Fa500Px, FaCog, FaSlidersH } from "react-icons/fa";

export default function ConfigMenuTest({
  isDarkMode,
}: {
  isDarkMode: boolean;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const navigation = useRouter();

  // Close on click outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  return (
    <div ref={ref} className="">
      {/* Bouton cogwheel */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="p-3 cursor-pointer rounded-full shadow-md hover:shadow-lg transition-transform hover:rotate-90"
        style={{
          backgroundColor: isDarkMode ? "#1f2937" : "#e5e7eb",
          color: isDarkMode ? "#e5e7eb" : "#1f2937",
        }}
        title="Configuration"
      >
        <FaCog size={20} />
      </button>

      {/* Menu déroulant */}
      <div
        className={`
          absolute right-0 mt-3 w-48 rounded-lg shadow-lg origin-top-right
          transition-all duration-200 ease-out
          ${open ? "scale-100 opacity-100" : "scale-95 opacity-0 pointer-events-none"}
        `}
        style={{
          backgroundColor: isDarkMode ? "#111827" : "#ffffff",
          border: isDarkMode ? "1px solid #374151" : "1px solid #e5e7eb",
        }}
      >
        <MenuItem
          icon={<Fa500Px />}
          label="Analyse de code"
          isDarkMode={isDarkMode}
          onClick={() => {
            setOpen(false);
            navigation.push(`/?isDarkModeInit=${isDarkMode}`);
          }}
        />
      </div>
    </div>
  );
}

function MenuItem({
  icon,
  label,
  onClick,
  isDarkMode,
}: {
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
  isDarkMode: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className="w-full flex cursor-pointer items-center gap-3 px-4 py-3 text-sm transition-colors"
      style={{
        color: isDarkMode ? "#e5e7eb" : "#1f2937",
      }}
      onMouseEnter={(e) =>
        (e.currentTarget.style.backgroundColor = isDarkMode
          ? "#1f2937"
          : "#f3f4f6")
      }
      onMouseLeave={(e) =>
        (e.currentTarget.style.backgroundColor = "transparent")
      }
    >
      {icon}
      {label}
    </button>
  );
}
