"use client";

import { useRef, useEffect, useState } from "react";
import Hero from "../Hero/Hero";
import { Modal, ModalClose } from "@mui/joy";

export default function FolderPicker({
  onSelect,
  buttonText = "Select Folder",
  isDarkMode = false,
}: {
  onSelect: (files: FileList) => void;
  buttonText?: string;
  isDarkMode?: boolean;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [openSelectFolderModal, setOpenSelectFolderModal] = useState(false);

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.setAttribute("webkitdirectory", "true");
      inputRef.current.setAttribute("directory", "true");
    }
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      onSelect(e.target.files);
      setOpenSelectFolderModal(false);
    }
  };

  return (
    <>
      <button
        onClick={() => setOpenSelectFolderModal(true)}
        className={`px-5 py-2 rounded-lg cursor-pointer font-medium transition-colors ${isDarkMode ? "bg-zinc-800 hover:bg-zinc-700" : "bg-gray-800 hover:bg-gray-600"}`}
      >
        {buttonText}
      </button>
      <input
        type="file"
        ref={inputRef}
        onChange={handleChange}
        className="hidden"
      />
      {/* Folder picker modal */}
      <Modal
        open={openSelectFolderModal}
        onClose={() => setOpenSelectFolderModal(false)}
        sx={{ display: "flex", alignItems: "center", justifyContent: "center" }}
      >
        <div
          className={`p-6 rounded-2xl flex flex-col items-center gap-4 ${
            isDarkMode
              ? "bg-zinc-900/90 backdrop-blur-md"
              : "bg-white/90 backdrop-blur-sm"
          } shadow-lg pt-10`}
        >
          <ModalClose onClick={() => setOpenSelectFolderModal(false)} />

          <Hero
            title="Create a New Test"
            descriptive=""
            description="Select your project folder to create a test. The code you provide will be used by AI models, and we have no means to verify how it is used by them. On our side, we store the test and the code to generate precise test data in order to characterize the performance of our models."
            isBlackTheme={isDarkMode}
            bouton2OnClick={() => inputRef.current?.click()}
            bouton2Text="Browse Folder"
            isTopPage={true}
          />
        </div>
      </Modal>
    </>
  );
}
