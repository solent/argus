from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict
from .CallGraphNode import CallGraph, CallGraphNode
from .CMake import CMake

@dataclass
class ProjectInfos:
    project_dir: Path
    name: Optional[str] = None
    version: Optional[str] = None
    standard: Optional[str] = None
    cmake: Optional[CMake] = None
    call_graph: Optional[CallGraph] = None
    cpp_files: Optional[List[str]] = None

    @staticmethod
    def from_dict(data: dict, project_dir: Path) -> "ProjectInfos":
        return ProjectInfos(
            project_dir=project_dir,
            name=data.get("name"),
            version=data.get("version"),
            standard=data.get("standard"),
            cmake=CMake.from_dict(data["cmake"],project_dir)
            if data.get("cmake") else None,
            call_graph=CallGraphNode.from_dict(data["call_graph"], project_dir)
            if data.get("call_graph") else None,
            cpp_files=data.get("cpp_files"),
        )
    
    
    def __post_init__(self):
        if self.project_dir and not self.cmake:
            self.cmake = CMake(project_dir=self.project_dir)
            self.name = self.cmake.project_name
            self.version = self.cmake.project_version
            self.standard = self.cmake.cpp_standard
        if self.project_dir and not self.cpp_files:
            self.cpp_files = self.find_cpp_files(str(self.project_dir))
        # Call graph generation would go here
        if self.project_dir and not self.call_graph:
            if not self.cpp_files:
                raise RuntimeError("No C/C++ source files found")
            self.call_graph = CallGraphNode(func_name="main", cpp_files=self.cpp_files, cmake=self.cmake, project_dir=self.project_dir)



    def find_cpp_files(self, directory: str) -> List[str]:
        directory = Path(directory)
        cpp_files = []
        # Utilisation de rglob pour parcourir récursivement tous les niveaux
        # de sous-dossiers, y compris les headers (.h/.hpp) nécessaires à
        # l'analyse du graphe d'appels.
        for pattern in ["*.cpp", "*.cc", "*.cxx", "*.c", "*.h", "*.hpp"]:
            cpp_files.extend(str(f) for f in directory.rglob(pattern))
        return sorted(cpp_files)
    

@dataclass
class TestResult:
    id: str
    created_at: str
    tested_model: str
    project: ProjectInfos

