from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Dict, Set, Optional
import re
from .LibraryInfos import LibraryInfos

# =========================
# CMake Project Parser
# =========================

@dataclass
class CMake:
    """Represents a full CMake project with dependencies and metadata."""
    project_dir: Path
    cmake_path: str = ""
    dependencies: List[LibraryInfos] = field(default_factory=list)
    linked_libraries: Set[str] = field(default_factory=set)
    subdirectories: List[str] = field(default_factory=list)
    cmake_version: Optional[str] = None
    cpp_standard: Optional[str] = None
    project_name: Optional[str] = None
    project_version: Optional[str] = None
    compiler_requirements: Dict[str, Any] = field(default_factory=dict)
    

    @staticmethod
    def from_dict(data: dict, project_dir: Path) -> "CMake":
        return CMake(
            project_dir=project_dir,
            cmake_path=data.get("cmake_path", ""),
            dependencies=[
                LibraryInfos.from_dict(d)
                for d in data.get("dependencies", [])
            ],
            linked_libraries=set(data.get("linked_libraries", [])),
            subdirectories=data.get("subdirectories", []),
            cmake_version=data.get("cmake_version"),
            cpp_standard=data.get("cpp_standard"),
            project_name=data.get("project_name"),
            project_version=data.get("project_version"),
            compiler_requirements=data.get("compiler_requirements", {}),
        )
    
    def __post_init__(self):
        if isinstance(self.project_dir, str):
            self.project_dir = Path(self.project_dir)
    
        self.cmake_path = self._find_cmake(self.project_dir) or ""
        if not self.cmake_path:
            raise FileNotFoundError(f"CMakeLists.txt not found in {self.project_dir}")
        self.extract_dependencies()


    # =====================
    # Private helpers
    # =====================

    def _find_cmake(self, project_dir: Path) -> Optional[str]:
        # Recherche récursive dans toute l'arborescence du projet.
        # On trie les résultats par profondeur (nombre de composants du chemin)
        # afin de préférer le CMakeLists.txt le plus haut placé — nécessaire
        # quand le projet est structuré avec des sous-dossiers imbriqués
        # (ex. archive extraite contenant un répertoire intermédiaire).
        matches = sorted(project_dir.rglob("CMakeLists.txt"), key=lambda p: len(p.parts))
        return str(matches[0]) if matches else None

    @staticmethod
    def _infer_vendor_from_git(git_url: str) -> Optional[str]:
        if not git_url:
            return None
        url = git_url.strip().removesuffix(".git")
        match = re.search(r"(?:github|gitlab)\.com[:/]([^/]+)/", url)
        if match:
            return match.group(1)
        match = re.search(r"[:/]([^/]+)/[^/]+$", url)
        if match:
            return match.group(1)
        return None

    # =====================
    # LibraryInfos extractors
    # =====================

    @staticmethod
    def _extract_fetchcontent_dependencies(content: str) -> List[LibraryInfos]:
        deps = []
        pattern = r'FetchContent_Declare\s*\(\s*(\w+)(.*?)(?=\n\s*\))'
        for name, decl in re.findall(pattern, content, re.DOTALL | re.IGNORECASE):
            dep = LibraryInfos(name=name, source="FetchContent")
            if match := re.search(r'GIT_REPOSITORY\s+([^\s]+)', decl):
                dep.git_repo = match.group(1)
                dep.vendor = CMake._infer_vendor_from_git(dep.git_repo)
            if match := re.search(r'GIT_TAG\s+([^\s]+)', decl):
                dep.version = match.group(1)
            if match := re.search(r'URL\s+([^\s]+)', decl):
                dep.options['url'] = match.group(1)
            if match := re.search(r'URL_HASH\s+([^\s]+)', decl):
                dep.options['hash'] = match.group(1)
            deps.append(dep)
        return deps

    @staticmethod
    def _extract_find_package_dependencies(content: str) -> List[LibraryInfos]:
        deps = []
        patterns = [
            r'find_package\s*\(\s*(\w+)\s+([\d\.]+)\s+REQUIRED',
            r'find_package\s*\(\s*(\w+)\s+([\d\.]+)\s*\)',
            r'find_package\s*\(\s*(\w+)\s+REQUIRED\s*\)',
            r'find_package\s*\(\s*(\w+)\s*\)',
        ]
        seen = set()
        for pat in patterns:
            for match in re.findall(pat, content, re.IGNORECASE):
                if isinstance(match, tuple):
                    name, version = match[0], match[1] if len(match) > 1 else "any"
                else:
                    name, version = match, "any"
                if name not in seen:
                    deps.append(LibraryInfos(name=name, version=version, source="find_package"))
                    seen.add(name)
        return deps

    @staticmethod
    def _extract_external_projects(content: str) -> List[LibraryInfos]:
        deps = []
        pattern = r'ExternalProject_Add\s*\(\s*(\w+)(.*?)(?=\n\s*\))'
        for name, decl in re.findall(pattern, content, re.DOTALL | re.IGNORECASE):
            dep = LibraryInfos(name=name, source="ExternalProject")
            if match := re.search(r'GIT_REPOSITORY\s+([^\s]+)', decl):
                dep.git_repo = match.group(1)
            if match := re.search(r'GIT_TAG\s+([^\s]+)', decl):
                dep.version = match.group(1)
            deps.append(dep)
        return deps

    @staticmethod
    def _extract_pkg_config_dependencies(content: str) -> List[LibraryInfos]:
        deps = []
        pattern = r'pkg_check_modules\s*\(\s*\w+\s+REQUIRED\s+([\w\s\->=<\.]+)\)'
        for match in re.findall(pattern, content, re.IGNORECASE):
            for pkg in match.strip().split():
                if m := re.match(r'([\w\-]+)(>=|<=|=|>|<)([\d\.]+)', pkg):
                    name, op, version = m.groups()
                    deps.append(LibraryInfos(name=name, version=f"{op}{version}", source="pkg-config"))
                else:
                    deps.append(LibraryInfos(name=pkg, version="any", source="pkg-config"))
        return deps

    # =====================
    # Other extractors
    # =====================

    @staticmethod
    def _extract_linked_libraries(content: str) -> Set[str]:
        linked = set()
        pattern = r'target_link_libraries\s*\([^\)]*\)'
        for match in re.findall(pattern, content, re.DOTALL | re.IGNORECASE):
            libs = re.findall(r'(\w+(?:::\w+)?)', match)
            for lib in libs:
                if lib.upper() not in {'PRIVATE', 'PUBLIC', 'INTERFACE', 'target'}:
                    linked.add(lib)
        return linked

    @staticmethod
    def _extract_subdirectories(content: str) -> List[str]:
        return re.findall(r'add_subdirectory\s*\(\s*([^\s\)]+)', content, re.IGNORECASE)

    @staticmethod
    def _extract_project_metadata(content: str) -> Dict[str, Any]:
        metadata = {}
        if m := re.search(r'cmake_minimum_required\s*\(\s*VERSION\s+([\d\.]+)', content, re.IGNORECASE):
            metadata['cmake_version'] = m.group(1)
        if m := re.search(r'CMAKE_CXX_STANDARD\s+(\d+)', content):
            metadata['cpp_standard'] = m.group(1)
        if m := re.search(r'CMAKE_C_STANDARD\s+(\d+)', content):
            metadata['c_standard'] = m.group(1)
        if m := re.search(r'project\s*\(\s*(\w+)(?:\s+VERSION\s+([\d\.]+))?', content, re.IGNORECASE):
            metadata['project_name'] = m.group(1)
            metadata['project_version'] = m.group(2) or "unspecified"
        metadata['compile_options'] = re.findall(r'target_compile_options\s*\([^\)]+\)', content, re.IGNORECASE)
        return metadata

    # =====================
    # Public method
    # =====================

    def extract_dependencies(self) -> None:
        """Extracts dependencies and metadata directly into self"""
        path = Path(self.cmake_path)
        content = path.read_text(encoding='utf-8')

        self.dependencies.extend(self._extract_fetchcontent_dependencies(content))
        self.dependencies.extend(self._extract_find_package_dependencies(content))
        self.dependencies.extend(self._extract_external_projects(content))
        self.dependencies.extend(self._extract_pkg_config_dependencies(content))
        self.linked_libraries = self._extract_linked_libraries(content)
        self.subdirectories = self._extract_subdirectories(content)

        metadata = self._extract_project_metadata(content)
        self.cmake_version = metadata.get('cmake_version')
        self.cpp_standard = metadata.get('cpp_standard')
        self.project_name = metadata.get('project_name')
        self.project_version = metadata.get('project_version')
        if 'c_standard' in metadata:
            self.compiler_requirements['c_standard'] = metadata['c_standard']
        if 'compile_options' in metadata:
            self.compiler_requirements['compile_options'] = metadata['compile_options']
