import { useState } from "react";
import { FaSun, FaMoon } from "react-icons/fa"; // ou n'importe quelle librairie d'icônes

export default function DarkModeToggle({
  isDarkMode,
  setIsDarkMode,
}: {
  isDarkMode: boolean;
  setIsDarkMode: (isDark: boolean) => void;
}) {
  return (
    <button
      onClick={() => setIsDarkMode(!isDarkMode)}
      className="p-3 rounded-full cursor-pointer transition-colors shadow-md hover:shadow-lg focus:outline-none"
      style={{
        backgroundColor: isDarkMode ? "#facc15" : "#1f2937",
        color: isDarkMode ? "#1f2937" : "#facc15",
      }}
      title={isDarkMode ? "Switch to light mode" : "Switch to dark mode"}
    >
      {isDarkMode ? <FaSun size={20} /> : <FaMoon size={20} />}
    </button>
  );
}
