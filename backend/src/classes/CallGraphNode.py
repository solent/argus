import asyncio
import json
import os
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, ClassVar, Dict, List, Optional, Set, TypedDict

from .LibraryInfos import LibraryInfos
from .Model import Model
from .CMake import CMake
from tree_sitter import Language, Parser
import tree_sitter_cpp as tscpp
from .config import Config
from .OpenRouter import OpenRouter, ModelConfig
from .BackSlicer import DataFlowBackwardSlicer

# Set DEBUG_AI=1 to log every prompt sent to an LLM and its raw response.
_DEBUG_AI = os.getenv("DEBUG_AI", "0").strip() == "1"


def _ai_log(label: str, model: str, prompt: str, raw_response: Optional[str]) -> None:
    """Print a clearly delimited debug block for a single LLM call."""
    sep = "=" * 72
    print(f"\n{sep}")
    print(f"[AI DEBUG] {label} | model={model}")
    print(f"--- PROMPT ---")
    print(prompt)
    print(f"--- RESPONSE ---")
    print(raw_response if raw_response is not None else "<no response>")
    print(f"{sep}\n")

CPP_LANGUAGE = Language(tscpp.language())
PARSER = Parser(CPP_LANGUAGE)

# Separate semaphores: local (on-premise, more limited) vs cloud (OpenRouter, more permissive)
_AI_SEMAPHORE_LOCAL = asyncio.Semaphore(3)
_AI_SEMAPHORE_CLOUD = asyncio.Semaphore(7)

# Module-level cache so we only ask the cloud once per CVE per process lifetime
_cve_context_cache: dict = {}


_OPENROUTER_BASE = "https://openrouter.ai/api/v1"


def _get_semaphore(model: Model):
    """Return the appropriate semaphore based on the model endpoint.
    If the model uses a non-OpenRouter base_url it's considered on-premise.
    """
    bu = (model.base_url or "").rstrip("/")
    return _AI_SEMAPHORE_LOCAL if bu and bu != _OPENROUTER_BASE else _AI_SEMAPHORE_CLOUD


def _make_client(model: Model) -> OpenRouter:
    """Build an OpenRouter-compatible client from a Model, respecting its base_url.

    On-premise endpoints (non-OpenRouter base_url) get a generous 600s timeout
    because large local models on shared servers can take several minutes to
    generate a full vulnerability report.  Cloud models keep the 120s default.
    """
    base = model.base_url or _OPENROUTER_BASE
    is_onpremise = base.rstrip("/") != _OPENROUTER_BASE
    return OpenRouter(
        api_key=model.api_key,
        default_model=model.name,
        base_url=base,
        timeout=600 if is_onpremise else 120,
    )


# ============================================================
# Helpers
# ============================================================

def _escape_literal_newlines_in_json_strings(text: str) -> str:
    """Replace literal newlines inside JSON string values with \\n.

    LLMs sometimes put real newline characters inside JSON string values
    (e.g. multi-line code snippets), which is invalid JSON.
    This regex finds every quoted string and escapes any bare newlines/tabs.
    """
    def _fix(m: re.Match) -> str:
        return (
            m.group(0)
            .replace("\r\n", "\\n")
            .replace("\r",   "\\r")
            .replace("\n",   "\\n")
            .replace("\t",   "\\t")
        )
    # Match a JSON string: opening ", then (non-quote-non-backslash chars | backslash+any), closing "
    # re.DOTALL lets [^"\\] also match newlines so we capture the whole multi-line string.
    return re.sub(r'"(?:[^"\\]|\\.)*"', _fix, text, flags=re.DOTALL)


def _extract_str(value, fallback: str = "") -> str:
    """
    Coerce an LLM result field to a plain string.

    LLMs (especially small models) sometimes return a structured dict or list
    instead of the plain string that the prompt asked for.  This helper walks
    common patterns so we never expose "[object Object]" to the frontend.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        # Try the most likely keys the model might have used for the text
        for k in ("content", "text", "report", "markdown", "summary",
                  "global_report", "body", "message"):
            v = value.get(k)
            if isinstance(v, str) and v.strip():
                return v
        # Last resort: pretty-print the dict as JSON so at least it's readable
        return json.dumps(value, ensure_ascii=False, indent=2)
    if isinstance(value, list):
        return "\n".join(str(item) for item in value)
    return str(value) if value is not None else fallback


def parse_json_response(text: str):
    """
    Robustly extract a JSON object from an LLM response.

    Handles three common failure modes:
      1. Response starts with a code fence immediately: ```json ... ```
      2. Response has a prose preamble before the fence:
             "Here is the scored evaluation:\n```json\n{...}\n```"
         (deepseek, gemini, and many instruct models do this)
      3. LLM embeds literal \\n / \\t inside JSON string values (RFC 8259 violation).
    """
    text = text.strip()

    # ── Handle code-fence wrapping (at start OR after a preamble) ──────────
    #
    # Problem: models that produce step-by-step analysis (devstral, deepseek)
    # output multiple code fences in their response:
    #   1. ```cpp   <- code examples in the analysis prose
    #   2. ```json  <- the actual JSON output at the end
    #
    # The old regex `(?:json)?` matched the FIRST fence (cpp), extracted C++
    # source code, then json.loads failed with "Expecting value at char 0".
    #
    # Fix strategy (priority order):
    #   P1. Find an explicit ```json ... ``` block anywhere in the text.
    #   P2. Find the LAST generic ``` block (models put JSON last after prose).
    #   P3. Response opens with ``` but has no closing fence (legacy).
    #   P4. No fences at all — try raw text and then {…} extraction.
    if "```" in text:
        # P1: explicit ```json fence (handles prose + code blocks before the output)
        json_fence = re.search(r"```json\s*\n([\s\S]*?)\n```", text, re.IGNORECASE)
        if json_fence:
            text = json_fence.group(1).strip()
        else:
            # P2: take the LAST ``` block — the JSON output is always at the end
            all_fences = list(re.finditer(r"```\w*\s*\n([\s\S]*?)\n```", text))
            if all_fences:
                text = all_fences[-1].group(1).strip()
            elif text.startswith("```"):
                # P3: legacy — response opens with ``` but closing fence is missing
                text = text.split("```", 2)[1]
                text = text.lstrip("json").strip()

    # ── Attempt 1: direct JSON parse ───────────────────────────────────────
    try:
        return json.loads(text)
    except Exception:
        pass

    # ── Attempt 2: escape literal newlines inside JSON strings ───────────
    try:
        return json.loads(_escape_literal_newlines_in_json_strings(text))
    except Exception:
        pass

    # ── Attempt 3: extract outermost {…} object from free-form text ───────
    # Handles models that output JSON without any code fences.
    try:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            candidate = text[start : end + 1]
            return json.loads(candidate)
    except Exception:
        pass

    try:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            candidate = _escape_literal_newlines_in_json_strings(text[start : end + 1])
            return json.loads(candidate)
    except Exception as e:
        pass

    print(f"[JSON parse error] all attempts failed: {e}")
    print(f"[JSON parse error] Raw response (first 1000 chars):\n{text[:1000]}")
    return None


def strip_before_third_slash(path: str) -> str:
    parts = path.split("/", 3)
    return parts[3] if len(parts) > 3 else path


def strip_after_first_slash(path: str) -> str:
    parts = path.split("/", 1)
    return parts[0] if len(parts) > 1 else path


def _make_model_config(model_name: str) -> ModelConfig:
    return ModelConfig(
        name=model_name,
        temperature=0.0,   # deterministic output
        top_p=1.0,
        frequency_penalty=0.0,
        presence_penalty=0.0,
    )


async def _ask_model(client: OpenRouter, prompt: str, model_name: str, label: str = "") -> Optional[dict]:
    """Run a blocking LLM call in a thread and parse JSON response."""
    import time as _time

    tag = label or "LLM call"
    is_onpremise = client.base_url.rstrip("/") != _OPENROUTER_BASE
    prefix = "[ON-PREM]" if is_onpremise else "[CLOUD]  "

    def _sync():
        t0 = _time.time()
        prompt_tokens = len(prompt) // 4   # rough estimate for the log
        print(f"{prefix} → {tag} | model={model_name} | ~{prompt_tokens} tok prompt | endpoint={client.base_url}")
        try:
            response = client.ask(prompt, config=_make_model_config(model_name))
            elapsed = _time.time() - t0
            raw = getattr(response, "content", None) if response else None
            used  = getattr(response, "tokens_used", None) if response else None
            tok_info = f"{used} tok total" if used else f"~{len(raw or '') // 4} tok resp"
            if raw:
                print(f"{prefix} ✓ {tag} | {elapsed:.1f}s | {tok_info}")
            else:
                print(f"{prefix} ✗ {tag} | {elapsed:.1f}s | empty response")
            if _DEBUG_AI:
                _ai_log(tag, model_name, prompt, raw)
            if not raw:
                print(f"[WARNING] Empty response from {model_name}")
                return None
            return parse_json_response(raw)
        except Exception as e:
            elapsed = _time.time() - t0
            print(f"{prefix} ✗ {tag} | {elapsed:.1f}s | ERROR: {e}")
            if _DEBUG_AI:
                _ai_log(tag, model_name, prompt, f"<ERROR: {e}>")
            print(f"[ERROR] {model_name}: {e}")
            return None

    return await asyncio.to_thread(_sync)


async def _fetch_cve_contexts(cves) -> dict:
    """Pre-fetch CWE classification and canonical patterns for each CVE via cloud.

    IMPORTANT: No user code is included in these prompts — only CVE IDs and
    public descriptions from NVD. This is safe to send to cloud models even
    when the code analysis itself must stay on-premise.

    Results are cached module-level by CVE ID to avoid duplicate calls.
    """
    async def _fetch_one(cve):
        if cve.id in _cve_context_cache:
            return cve.id, _cve_context_cache[cve.id]

        prompt = f"""You are a security expert. Analyze this CVE and provide structured context for static code analysis.

CVE ID: {cve.id}
Description: {cve.description}

Respond with ONLY valid JSON (no other text).
IMPORTANT: all string values must be valid JSON strings — use \\n for newlines, never real newlines inside strings.

{{
  "cwe_id": "CWE-XXX",
  "cwe_name": "Short CWE name (e.g. Heap Buffer Overflow)",
  "canonical_vulnerable_pattern": "Minimal C/C++ code showing the vulnerable pattern — use \\n for line breaks",
  "canonical_safe_pattern": "Same code but with the correct mitigation — use \\n for line breaks",
  "prerequisites": "unauthenticated_remote | authenticated_remote | local | physical | none",
  "exploitation_technique": "One sentence: how this vulnerability class is typically exploited",
  "default_behavior": "Describe the library DEFAULT behavior relevant to this CVE. Does the SAFE option require explicit opt-in? Example: 'libcurl CURLOPT_FOLLOWLOCATION defaults to 0 since 7.19.4 but was 1 before — any curl usage without explicit disable follows redirects'. Be specific about version thresholds.",
  "vulnerable_by_default": true,
  "mitigation_requires_explicit_code": "Describe the EXACT code a developer must write to be safe (e.g. 'curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L)' or 'curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L)')",
  "indirect_trigger": "Can code be affected WITHOUT directly calling the vulnerable function? Example: 'Any code that uses curl for HTTP will follow redirects to file:// unless CURLOPT_FOLLOWLOCATION=0 is set'"
}}"""

        client = _make_client(Config.model_cloud)
        async with _AI_SEMAPHORE_CLOUD:
            result = await _ask_model(client, prompt, Config.model_cloud.name, label=f"CVE context [{cve.id}]")

        ctx = result or {}
        _cve_context_cache[cve.id] = ctx
        return cve.id, ctx

    results = await asyncio.gather(*(_fetch_one(c) for c in cves))
    return dict(results)


# ============================================================
# Location / internal types
# ============================================================

@dataclass
class Location(TypedDict):
    file: str
    line: int
    column: Optional[int] = None


@dataclass
class _FunctionDef:
    name: str
    file: str
    node: object = None


@dataclass
class _FunctionCall:
    callee: str
    file: str
    line: int
    column: Optional[int] = None


# ============================================================
# CallGraphNode
# ============================================================

@dataclass
class CallGraphNode:
    func_name: Optional[str] = None
    locations: List[Location] = field(default_factory=list)
    library: Optional[LibraryInfos] = None
    children: List["CallGraphNode"] = field(default_factory=list)
    project_dir: Optional[Path] = None

    extracted_code: Optional[str] = None
    ai_report: Optional[str] = None
    ai_vulnerability_score: Optional[float] = None
    global_report: Optional[str] = None
    global_score: Optional[float] = None
    critical_nodes: Optional[List["CallGraphNode"]] = None

    cpp_files: Optional[List[str]] = None
    cmake: Optional[CMake] = None

    judge_ai_reports: Optional[Dict[str, str]] = None
    judge_ai_vulnerability_scores: Optional[Dict[str, float]] = None
    judge_ai_metric_scores: Optional[Dict[str, Dict[str, float]]] = None
    judge_global_ai_metric_scores: Optional[Dict[str, Dict[str, float]]] = None
    judge_ai_global_reports: Optional[Dict[str, str]] = None
    judge_ai_global_scores: Optional[Dict[str, float]] = None

    # ── Consensus fields (populated after the revision round) ──────────────
    # Per-model revised scores after seeing peers
    judge_revised_scores: Optional[Dict[str, float]] = None
    judge_revised_global_scores: Optional[Dict[str, float]] = None
    # Final aggregated outputs
    consensus_local_score: Optional[float] = None
    consensus_global_score: Optional[float] = None
    consensus_report: Optional[str] = None

    _functions: ClassVar[Dict[str, _FunctionDef]] = {}
    _calls: ClassVar[Dict[str, List[_FunctionCall]]] = {}
    _initialized: ClassVar[bool] = False
    _visited: ClassVar[Dict[str, "CallGraphNode"]] = {}
    _library_tasks: ClassVar[List[asyncio.Task]] = []

    # ----------------------------------------------------------
    # Construction helpers
    # ----------------------------------------------------------

    @staticmethod
    def _remap_location(loc: dict, project_dir: Path | str) -> Location:
        if isinstance(project_dir, str):
            project_dir = Path(project_dir)
        old_path = Path(loc["file"])
        new_path = project_dir / old_path.name
        return {"file": str(new_path), "line": loc["line"], "column": loc.get("column")}

    @staticmethod
    def from_dict(data: dict, project_dir: Path) -> "CallGraphNode":
        return CallGraphNode(
            func_name=data.get("func_name"),
            locations=[
                CallGraphNode._remap_location(loc, project_dir)
                for loc in data.get("locations", [])
            ],
            library=LibraryInfos.from_dict(data["library"]) if data.get("library") else None,
            children=[CallGraphNode.from_dict(c, project_dir) for c in data.get("children", [])],
            extracted_code=data.get("extracted_code"),
            ai_report=data.get("ai_report"),
            ai_vulnerability_score=data.get("ai_vulnerability_score"),
            cpp_files=data.get("cpp_files"),
            cmake=CMake.from_dict(data["cmake"], project_dir) if data.get("cmake") else None,
            global_report=data.get("global_report"),
            global_score=data.get("global_score"),
            critical_nodes=[
                CallGraphNode.from_dict(cn, project_dir)
                for cn in data.get("critical_nodes", [])
            ] if data.get("critical_nodes") else None,
            project_dir=project_dir,
        )

    def __post_init__(self):
        self._library_tasks: List[asyncio.Task] = []
        if not CallGraphNode._initialized:
            self._build_project_index()
            CallGraphNode._initialized = True

        if self.func_name in CallGraphNode._visited:
            return
        CallGraphNode._visited[self.func_name] = self

        if self.func_name not in CallGraphNode._functions:
            if self.cpp_files and self.cmake:
                task = asyncio.create_task(self._resolve_library_async_and_assign())
                CallGraphNode._library_tasks.append(task)
            return

        for call in CallGraphNode._calls.get(self.func_name, []):
            child = CallGraphNode._visited.get(call.callee)
            if not child:
                child = CallGraphNode(
                    func_name=call.callee,
                    cpp_files=self.cpp_files,
                    cmake=self.cmake,
                    project_dir=self.project_dir,
                )
            child.locations.append(
                CallGraphNode._remap_location(
                    {
                        "file": strip_before_third_slash(call.file),
                        "line": call.line,
                        "column": getattr(call, "column", None),
                    },
                    self.project_dir or Path("."),
                )
            )
            if child not in self.children:
                self.children.append(child)

            if self.func_name not in CallGraphNode._functions and self.cpp_files and self.cmake:
                task = asyncio.create_task(self._resolve_library_async_and_assign())
                CallGraphNode._library_tasks.append(task)

    # ----------------------------------------------------------
    # Library resolution
    # ----------------------------------------------------------

    async def _resolve_library_async_and_assign(self):
        lib = await self._resolve_library(self.func_name)
        self.library = lib
        if lib and not lib.checked_at:
            lib.fetch_cves()

    async def _resolve_library(self, func_name: str) -> Optional[LibraryInfos]:
        if not self.cmake or not func_name:
            return None

        dependencies: List[LibraryInfos] = self.cmake.dependencies
        # Show name and version separately so the LLM returns just the name
        dep_lines = "\n".join(
            f"  - {dep.name}" + (f"  (version: {dep.version})" if dep.version not in ("unknown", "any") else "")
            for dep in dependencies
        )
        prompt = f"""You are a C++ build system and library API expert.

Context:
- C++ project built with CMake.
- Linked external libraries:
{dep_lines}

Task:
Determine which ONE of the listed libraries most likely provides the function or symbol below.
Base your answer on known API naming conventions, namespaces, and prefixes.

Function / symbol: {func_name}

Rules:
- If the name has a recognizable namespace prefix (e.g. curl_, SSL_, EVP_, png_, zip_), use it.
- If the name matches a well-known API pattern of one of the listed libraries, use it.
- Only choose from the provided libraries.
- Return ONLY the library name as it appears in the list above (no version, no extra text).
- If no library matches with confidence ≥ 0.8, respond UNKNOWN.

Respond strictly in JSON (nothing else):
{{"library": "<exact library name from the list | UNKNOWN>", "confidence": <float 0.0–1.0>, "reason": "<one sentence>"}}
"""
        client = _make_client(Config.model_cloud)
        async with _AI_SEMAPHORE_CLOUD:
            result = await _ask_model(client, prompt, Config.model_cloud.name, label=f"Library resolution [{func_name}]")

        if not result:
            return None

        lib_name = result.get("library")
        confidence = result.get("confidence", 0.0)
        print(f"[Library resolution] '{func_name}' → {lib_name} (confidence: {confidence})")

        if lib_name == "UNKNOWN" or confidence < 0.8:
            return None

        # Match by name; also accept if the LLM included the version in its answer
        for dep in dependencies:
            if dep.name.lower() == lib_name.lower():
                return dep
            # Fallback: LLM may have included version despite instructions
            if lib_name.lower().startswith(dep.name.lower()):
                return dep
        return None

    # ----------------------------------------------------------
    # Tree-sitter index
    # ----------------------------------------------------------

    def _build_project_index(self):
        for file in self.cpp_files or []:
            path = Path(file)
            if not path.exists():
                continue
            print(path)
            code = path.read_bytes()
            tree = PARSER.parse(code)
            self._extract_functions(tree, code, file)

    def _extract_functions(self, tree, source: bytes, file: str):
        def walk(node):
            if node.type == "function_definition":
                decl = node.child_by_field_name("declarator")
                if decl:
                    ident = decl.child_by_field_name("declarator")
                    if ident:
                        name = source[ident.start_byte:ident.end_byte].decode()
                        CallGraphNode._functions[name] = _FunctionDef(name=name, file=file, node=node)
                        CallGraphNode._calls[name] = self._extract_calls(node, source, file)
            for c in node.children:
                walk(c)

        walk(tree.root_node)

    def _extract_calls(self, node, source: bytes, file: str) -> List[_FunctionCall]:
        calls: List[_FunctionCall] = []

        CAST_KEYWORDS = {"static_cast", "dynamic_cast", "reinterpret_cast", "const_cast"}
        STL_COMMON = {
            "size", "empty", "begin", "end", "cbegin", "cend",
            "push_back", "emplace_back", "insert", "erase",
            "clear", "find", "at", "operator[]",
        }

        def extract_name(fn_node) -> Optional[str]:
            if fn_node.type in {"identifier", "qualified_identifier"}:
                return source[fn_node.start_byte:fn_node.end_byte].decode()
            return None  # field_expression, pointer_expression, etc. → skip

        def is_valid(name: str) -> bool:
            if name.startswith(("operator", "~")):
                return False
            if any(name.startswith(c) for c in CAST_KEYWORDS):
                return False
            if name.split("::")[-1] in STL_COMMON:
                return False
            return True

        def walk(n):
            if n.type == "call_expression":
                fn = n.child_by_field_name("function")
                if fn:
                    name = extract_name(fn)
                    if name and is_valid(name):
                        calls.append(_FunctionCall(
                            callee=name,
                            file=file,
                            line=n.start_point[0] + 1,
                            column=n.start_point[1] + 1,
                        ))
            for c in n.children:
                walk(c)

        walk(node)
        return calls

    # ----------------------------------------------------------
    # Code extraction
    # ----------------------------------------------------------

    def extract_code(self) -> None:
        self.extracted_code = ""
        if not self.locations:
            return

        source_dir = (str(self.project_dir) if self.project_dir else ".") + "/"
        source_dir_complete = ""

        functions = {}
        for name, fdef in CallGraphNode._functions.items():
            source_dir_complete = (
                source_dir + strip_after_first_slash(strip_before_third_slash(fdef.file)) + "/"
            )
            functions[name] = {
                "file": source_dir + strip_before_third_slash(fdef.file),
                "line": fdef.node.start_point[0] + 1,
                "calls": [
                    {
                        "function": c.callee,
                        "file": source_dir + strip_before_third_slash(c.file),
                        "line": c.line,
                    }
                    for c in CallGraphNode._calls.get(name, [])
                ],
            }

        parts = []
        for loc in self.locations:
            try:
                slicer = DataFlowBackwardSlicer(
                    call_graph_path=None,
                    source_dir=source_dir_complete,
                    functions=functions,
                )
                context = slicer.slice_from_call(
                    source_dir_complete + strip_before_third_slash(loc["file"]),
                    loc["line"],
                )
                if context:
                    result = slicer.generate_output(context)
                    if result:
                        parts.append(result)
            except Exception as exc:
                print(f"[extract_code] slicer failed: {exc}")

        self.extracted_code = "\n\n".join(parts)

    # ----------------------------------------------------------
    # Vulnerability guard
    # ----------------------------------------------------------

    def _is_analyzable(self) -> bool:
        """Return True only when there is something meaningful to analyze."""
        if not self.library or not self.library.cves:
            return False
        if not self.extracted_code:
            self.extract_code()
        # Even after extraction, if code is empty there's nothing to send
        if not self.extracted_code or not self.extracted_code.strip():
            return False
        return True

    # ----------------------------------------------------------
    # Call graph topology helper
    # ----------------------------------------------------------

    @staticmethod
    def _build_call_graph_summary() -> dict:
        """Return a compact adjacency list {func_name: [callee, ...]} for all
        nodes in the current analysis session (ClassVar _visited + _calls).
        Used to give the global-synthesis prompt topological context for chain detection.
        """
        summary = {}
        for func_name in CallGraphNode._visited:
            callees = [c.callee for c in CallGraphNode._calls.get(func_name, [])
                       if c.callee in CallGraphNode._visited]
            summary[func_name] = callees
        return summary

    # ----------------------------------------------------------
    # Prompts (centralised)
    # ----------------------------------------------------------

    def _local_analysis_prompt(self, cve_contexts: dict) -> str:
        """Build the per-function analysis prompt.

        Parameters
        ----------
        cve_contexts : dict
            {cve_id: {cwe_id, cwe_name, canonical_vulnerable_pattern,
                      canonical_safe_pattern, prerequisites, exploitation_technique}}
            Fetched from cloud without user code — used to enrich the prompt
            so the small on-premise model has a reference framework.
        """
        options_json = json.dumps(self.library.options, indent=2)

        # Build enriched CVE blocks
        cve_blocks = []
        for cve in self.library.cves:
            ctx = cve_contexts.get(cve.id, {})
            affected = (
                ", ".join(str(v) for v in cve.affected_versions)
                if cve.affected_versions else "unknown"
            )

            # Truncate exploit content to keep prompt manageable
            exploit_section = ""
            if cve.exploit_db and len(cve.exploit_db.strip()) > 50:
                exploit_snippet = cve.exploit_db.strip()[:1000]
                exploit_section = f"""  ExploitDB reference (truncated):
```
{exploit_snippet}
```"""

            block = f"""  ─── {cve.id} ───
  Severity:  {cve.severity}  |  CVSS: {cve.cvss}  |  Published: {cve.published_date}
  Affected versions: {affected}
  Description: {cve.description}"""

            if ctx.get("cwe_id"):
                vuln_by_default = ctx.get('vulnerable_by_default', 'unknown')
                block += f"""
  CWE: {ctx['cwe_id']} — {ctx.get('cwe_name', '')}
  Canonical vulnerable pattern:
```c
{ctx.get('canonical_vulnerable_pattern', 'N/A')}
```
  Canonical safe pattern:
```c
{ctx.get('canonical_safe_pattern', 'N/A')}
```
  Attack prerequisites: {ctx.get('prerequisites', 'unknown')}
  Exploitation technique: {ctx.get('exploitation_technique', 'unknown')}
  ⚠ DEFAULT BEHAVIOR: {ctx.get('default_behavior', 'unknown')}
  ⚠ VULNERABLE BY DEFAULT (safe requires explicit opt-in): {vuln_by_default}
  ⚠ REQUIRED MITIGATION CODE: {ctx.get('mitigation_requires_explicit_code', 'unknown')}
  ⚠ INDIRECT TRIGGER: {ctx.get('indirect_trigger', 'unknown')}"""

            if exploit_section:
                block += f"\n{exploit_section}"

            cve_blocks.append(block)

        cves_section = "\n\n".join(cve_blocks)

        return f"""You are a senior C/C++ security researcher specializing in CVE impact analysis.

╔══════════════════════════════════════════════════════════════════╗
║  ANALYSIS PHILOSOPHY — READ BEFORE STARTING                     ║
║                                                                  ║
║  FALSE NEGATIVES ARE CRITICAL FAILURES.                         ║
║  A missed real vulnerability can cause a breach.                ║
║  An over-flagged false positive is merely noise an auditor      ║
║  can dismiss.  When uncertain → FLAG IT.                        ║
║                                                                  ║
║  GOLDEN RULE:                                                    ║
║  Version matches + library is used in code + no explicit        ║
║  mitigation visible = LIKELY_EXPLOITABLE (score ≥ 5.0)         ║
║  Do NOT assign 0.0 unless you have hard proof it is safe.       ║
║                                                                  ║
║  "I cannot see the vulnerable call" ≠ NOT_EXPLOITABLE           ║
║  It means INSUFFICIENT_INFO → score 3.0–5.0                     ║
╚══════════════════════════════════════════════════════════════════╝

==================================================
LIBRARY INFORMATION
==================================================
Name:    {self.library.name}
Vendor:  {self.library.vendor}
Version: {self.library.version}
Source:  {self.library.source}
Git:     {self.library.git_repo}
Build options / CMake configuration:
{options_json}

==================================================
KNOWN CVEs — WITH EXPLOITATION CONTEXT
==================================================
{cves_section}

==================================================
SOURCE CODE EXTRACT
(data-flow backward slice — relevant call sites and callers)
==================================================
```cpp
{self.extracted_code}
```

==================================================
STEP-BY-STEP ANALYSIS PROTOCOL
==================================================

For EACH CVE, work through ALL steps in order:

STEP 1 — VERSION CHECK
  Is the library version ({self.library.version}) in the CVE's affected range?
  If version is "unknown" → assume AFFECTED (worst-case).

STEP 2 — DEFAULT BEHAVIOR CHECK  ← CRITICAL STEP
  Read the "⚠ DEFAULT BEHAVIOR" and "⚠ VULNERABLE BY DEFAULT" fields above.
  Many vulnerabilities exist because the SAFE option requires explicit opt-in.

  KEY PRINCIPLE: If "VULNERABLE BY DEFAULT = true" for this CVE:
    → Absence of the required mitigation code IS evidence of vulnerability.
    → You do NOT need to see the vulnerable call explicitly — using the library
      at all without the mitigation is sufficient to flag as LIKELY_EXPLOITABLE.

  Check: does the code contain the exact mitigation code listed in
  "⚠ REQUIRED MITIGATION CODE"? If not → the default (vulnerable) behavior applies.

STEP 3 — INDIRECT USAGE CHECK
  Even if the CVE's vulnerable function is not directly called in this slice:
  a) Does this code use the library for the same purpose (HTTP, SSL, file ops)?
  b) Would the library's default behavior (from STEP 2) apply to this code?
  c) Could a callee (function called from here) trigger the vulnerable path?
  If any answer is YES → treat as LIKELY_EXPLOITABLE unless mitigation is present.

STEP 4 — TAINT ANALYSIS
  Trace each argument of the vulnerable function call:
  a) Is any argument derived from external/user-controlled input?
     (function parameters, network recv, file reads, env vars, config files)
  b) Are buffer sizes validated before use?
  c) Are return values checked?
  d) Does the code reach the vulnerable code path?

STEP 5 — GUARD ASSESSMENT
  Identify ALL mitigations/validations present.
  For each:
  • EFFECTIVE — actually prevents exploitation
  • BYPASSABLE — can be circumvented (integer overflow, TOCTOU, wrong comparison)
  • ABSENT — no mitigation code found

STEP 6 — VERDICT AND MANDATORY SCORING
  Choose ONE verdict + assign a score within the MANDATORY range below:

  • EXPLOITABLE              → score 7.0–10.0
    (attacker input confirmed to reach sink with no effective guard)

  • LIKELY_EXPLOITABLE       → score 5.0–8.0
    (probable, or default-behavior applies, or no mitigation visible)

  • CONDITIONALLY_EXPLOITABLE → score 3.0–6.0
    (requires specific build options or runtime conditions to trigger)

  • INSUFFICIENT_INFO        → score 3.0–5.0
    (cannot determine — NOT 0.0. Unknown ≠ safe.)

  • NOT_EXPLOITABLE          → score 0.0–2.0
    ONLY if ALL of the following are true:
    ✓ Explicit mitigation code is present in the slice
    ✓ The mitigation is effective and non-bypassable
    ✓ The vulnerable code path is demonstrably unreachable
    WARNING: "The vulnerable function is not called" alone does NOT qualify
             as NOT_EXPLOITABLE if the library is used for the same purpose.

STEP 7 — ATTACK VECTOR
  For EXPLOITABLE or LIKELY_EXPLOITABLE: describe the concrete path.
  For others: explain what evidence would change the verdict.

==================================================
⚠ OUTPUT INSTRUCTIONS — CRITICAL ⚠
==================================================

Your ENTIRE response must be a single ```json ... ``` block.
NO prose before or after. NO step-by-step analysis outside the JSON.
ALL reasoning goes INSIDE the "report" field as Markdown.

```json
{{
  "report": "<Markdown — use structure below>",
  "score": <float 0.0–10.0>,
  "exploitable_cves": ["<CVE-ID>", ...],
  "attack_surface": "<external_input | config_file | network | local | none>"
}}
```

Report structure (value of the "report" key, Markdown string):
### Executive Summary
### Library Usage Context
### CVE-by-CVE Analysis
  #### [CVE-ID] — [CWE-XXX] — [VERDICT]
  - **Version match**: yes/no/unknown
  - **Vulnerable by default**: yes/no
  - **Mitigation code present**: yes/no
  - **Taint path**: source → chain → sink (or "not directly visible")
  - **Guards**: each guard: EFFECTIVE / BYPASSABLE / ABSENT
  - **Attack vector**: step-by-step, or "default behavior triggers without explicit action"
### Chained Risk
### Score Rationale

Remember: output ONLY the ```json block. Nothing else."""

    @staticmethod
    def _global_analysis_prompt(child_reports: List[Dict], call_graph_summary: dict) -> str:
        # Identify entry points: nodes with no callers in the graph
        callers = {callee for callees in call_graph_summary.values() for callee in callees}
        entry_points = [f for f in call_graph_summary if f not in callers]

        return f"""You are a senior C/C++ security researcher performing a project-level vulnerability assessment.

You receive per-function security reports AND the project call graph topology.
Your job: synthesise a global risk picture by identifying exploit chains across function boundaries.

==================================================
CALL GRAPH TOPOLOGY
(adjacency list: {{caller: [callees]}})
==================================================
{json.dumps(call_graph_summary, indent=2)}

External entry points (reachable from outside, no callers in graph):
{json.dumps(entry_points)}

==================================================
PER-NODE VULNERABILITY REPORTS
==================================================
{json.dumps(child_reports, indent=2)}

==================================================
SYNTHESIS PROTOCOL
==================================================

1. CHAIN DETECTION
   Using the call graph topology above, trace paths from entry points to vulnerable sinks:
   - Can an attacker exploit node A to gain a primitive (arbitrary write, info leak, UAF, etc.)
     that unlocks exploitation of node B? Trace the exact call path A → ... → B.
   - Key chain patterns to look for:
     • info leak → ASLR bypass → memory corruption
     • UAF → type confusion → arbitrary R/W
     • integer overflow → wrong alloc size → heap overflow in callee
     • path traversal → arbitrary file read → secret exposure enabling further attack

2. ATTACK SURFACE AGGREGATION
   What is the MINIMUM attacker capability needed to trigger the worst-case chain end-to-end?
   (unauthenticated_remote / authenticated_remote / local / physical)

3. GLOBAL SCORE CALIBRATION
   - Start from the highest individual node score.
   - Increase ONLY if a confirmed chain amplifies exploitability beyond any single node.
   - Decrease if all exploitable nodes require high privilege or rare conditions.
   - RULE: global score may exceed max(child_scores) ONLY when a specific chain is confirmed
     with an identified call path.

4. CRITICAL NODE IDENTIFICATION
   - Rank nodes by their role in the worst-case attack path.
   - "Critical" = compromising it unlocks further exploitation or widens attack surface.

==================================================
⚠ OUTPUT INSTRUCTIONS — CRITICAL ⚠
==================================================

Your ENTIRE response must be a single ```json ... ``` block.
NO prose before or after. ALL reasoning goes inside "global_report".

```json
{{
  "global_report": "<Markdown — sections: Executive Summary / Attack Chains / Node Ranking / Score Rationale>",
  "global_score": <float 0.0–10.0>,
  "critical_nodes": [
    {{"node": "<func_name>", "score": <float>, "reason": "<role in worst-case chain>"}}
  ],
  "worst_case_attacker": "<unauthenticated_remote | authenticated_remote | local | physical | none>"
}}
```

Remember: output ONLY the ```json block. Nothing else."""

    # ----------------------------------------------------------
    # AI report generation
    # ----------------------------------------------------------

    async def _generate_local_report(
        self,
        model: Model,
        cve_contexts: Optional[dict] = None,
    ) -> Optional[Dict]:
        """
        Generate a local vulnerability report for this node.

        Parameters
        ----------
        model        : LLM to use for analysis (should be Config.model_local for Analyse module).
        cve_contexts : Pre-fetched CWE/pattern data for each CVE (keyed by CVE ID).
                       If None, fetches them inline (slower for many nodes).
        """
        if not self._is_analyzable():
            self.ai_report = ""
            self.ai_vulnerability_score = 0.0
            return None

        # Ensure CVE contexts are available (fetched via cloud without user code)
        if cve_contexts is None:
            cve_contexts = await _fetch_cve_contexts(self.library.cves)

        client = _make_client(model)
        sem = _get_semaphore(model)
        async with sem:
            result = await _ask_model(
                client,
                self._local_analysis_prompt(cve_contexts),
                model.name,
                label=f"Local analysis [{self.func_name}]",
            )

        if result:
            self.ai_report = _extract_str(result.get("report"), fallback="")
            self.ai_vulnerability_score = result.get("score", 0.0)
        else:
            self.ai_report = ""
            self.ai_vulnerability_score = 0.0

        return {
            "func_name": self.func_name,
            "library": self.library.name if self.library else "",
            "library_version": self.library.version if self.library else "",
            "ai_report": self.ai_report,
            "score": self.ai_vulnerability_score,
        }

    async def _collect_child_reports(
        self,
        model: Model,
        cve_contexts: Optional[dict] = None,
    ) -> List[Dict]:
        """Recursively collect local reports for the whole subtree, bottom-up.
        ClassVars are read-only during the report phase so children can run concurrently.
        cve_contexts is shared across all nodes to avoid duplicate cloud calls.
        """
        child_results = await asyncio.gather(
            *(child._collect_child_reports(model, cve_contexts) for child in self.children)
        )

        reports: List[Dict] = []
        for sub in child_results:
            reports.extend(sub)

        local = await self._generate_local_report(model, cve_contexts)
        if local:
            reports.append(local)

        return reports

    def _all_nodes(self, visited: Optional[Set[str]] = None) -> List["CallGraphNode"]:
        """Return self + all descendants (deduplicated by func_name)."""
        if visited is None:
            visited = set()
        if self.func_name in visited:
            return []
        visited.add(self.func_name)
        result = [self]
        for child in self.children:
            result.extend(child._all_nodes(visited))
        return result

    async def generate_global_ai_report(self, model: Model = None) -> None:
        """
        Recursively generate local reports for every node in the subtree,
        then synthesise a single global report at the root.

        Speed-up 1: extract_code() is CPU-bound — run all nodes in parallel threads.
        Speed-up 2: CVE contexts are pre-fetched in a single batch via cloud before
                    any local model calls, then shared across all nodes.
        """
        if model is None:
            model = Config.model_local

        all_nodes = self._all_nodes()

        # Pre-pass 1: extract code for all nodes concurrently (CPU-bound)
        await asyncio.gather(
            *(asyncio.to_thread(node.extract_code)
              for node in all_nodes
              if not node.extracted_code)
        )

        # Pre-pass 2: collect all unique CVEs and batch-fetch cloud context (no user code sent)
        unique_cves = {}
        for node in all_nodes:
            if node.library and node.library.cves:
                for cve in node.library.cves:
                    if cve.id not in unique_cves:
                        unique_cves[cve.id] = cve
        cve_contexts = await _fetch_cve_contexts(list(unique_cves.values()))

        # Generate per-node reports with shared CVE contexts
        child_reports = await self._collect_child_reports(model, cve_contexts)

        if not child_reports:
            self.global_report = ""
            self.global_score = 0.0
            self.critical_nodes = []
            return

        # Build call graph adjacency list for chain detection in global prompt
        call_graph_summary = CallGraphNode._build_call_graph_summary()

        client = _make_client(model)
        sem = _get_semaphore(model)
        async with sem:
            result = await _ask_model(
                client,
                self._global_analysis_prompt(child_reports, call_graph_summary),
                model.name,
                label="Global synthesis",
            )

        if result:
            self.global_report = _extract_str(result.get("global_report"), fallback="")
            self.global_score = result.get("global_score", 0.0)
            self.critical_nodes = result.get("critical_nodes", [])
        else:
            self.global_report = ""
            self.global_score = 0.0
            self.critical_nodes = []

    async def generate_targeted_ai_report(self, selected_node: "CallGraphNode" = None) -> None:
        """
        Generate a local report for a specific node only.
        If selected_node is None or matches self, analyze self.
        Otherwise recurse into children.
        """
        if selected_node and (
            selected_node.func_name != self.func_name
            or selected_node.locations != self.locations
        ):
            await asyncio.gather(*[
                child.generate_targeted_ai_report(selected_node)
                for child in self.children
            ])
            return

        cve_contexts = {}
        if self.library and self.library.cves:
            cve_contexts = await _fetch_cve_contexts(self.library.cves)
        await self._generate_local_report(Config.model_local, cve_contexts)

    # ----------------------------------------------------------
    # Judge
    # ----------------------------------------------------------

    @staticmethod
    def _make_scratch(source: "CallGraphNode") -> "CallGraphNode":
        """
        Clone a node for use as a scratch during judging WITHOUT triggering
        __post_init__ (which would pollute _visited / _library_tasks and
        re-run library resolution on an already-resolved node).

        We use object.__new__ + manual attribute assignment so the dataclass
        machinery is entirely bypassed.
        """
        s = object.__new__(CallGraphNode)
        # Instance fields — copy references (library/cmake are read-only here)
        s.func_name                    = source.func_name
        s.locations                    = source.locations
        s.library                      = source.library
        s.project_dir                  = source.project_dir
        s.extracted_code               = source.extracted_code
        s.cpp_files                    = source.cpp_files
        s.cmake                        = source.cmake
        # Give the scratch its own children clones (also bypassing __post_init__)
        s.children                     = [CallGraphNode._make_scratch(c) for c in source.children]
        # Reset mutable report fields
        s.ai_report                    = None
        s.ai_vulnerability_score       = None
        s.global_report                = None
        s.global_score                 = None
        s.critical_nodes               = None
        s.judge_ai_reports             = None
        s.judge_ai_vulnerability_scores = None
        s.judge_ai_metric_scores       = None
        s.judge_global_ai_metric_scores = None
        s.judge_ai_global_reports      = None
        s.judge_ai_global_scores       = None
        s.judge_revised_scores         = None
        s.judge_revised_global_scores  = None
        s.consensus_local_score        = None
        s.consensus_global_score       = None
        s.consensus_report             = None
        # __post_init__ normally creates this instance list — keep it empty
        s._library_tasks               = []
        return s

    # ----------------------------------------------------------
    # Consensus helpers
    # ----------------------------------------------------------

    @staticmethod
    def _weighted_median(scores: List[float], weights: Optional[List[float]] = None) -> float:
        """
        Weighted median of scores.
        Falls back to plain median when weights are None or all equal.
        """
        if not scores:
            return 0.0
        if len(scores) == 1:
            return scores[0]
        if weights is None or len(weights) != len(scores):
            weights = [1.0] * len(scores)

        total = sum(weights)
        if total == 0:
            return float(sum(scores) / len(scores))

        paired = sorted(zip(scores, weights), key=lambda x: x[0])
        cumulative = 0.0
        for s, w in paired:
            cumulative += w / total
            if cumulative >= 0.5:
                return s
        return paired[-1][0]

    @staticmethod
    def _score_spread(scores: List[float]) -> float:
        """Return max − min spread of a score list."""
        if not scores:
            return 0.0
        return max(scores) - min(scores)

    @staticmethod
    def _revision_prompt_local(
        model_name: str,
        own_report: str,
        own_score: float,
        peer_reports: List[Dict],   # [{"model": name, "report": str, "score": float}]
        tested_model_name: str,
        tested_report: str,
        tested_score: float,
    ) -> str:
        peers_json = json.dumps(peer_reports, indent=2)
        return f"""You are a senior C/C++ security analyst participating in a structured peer review.

You previously produced a local vulnerability report (your INITIAL ASSESSMENT below).
Other judge models also analyzed the same code independently. Their reports are shown as PEER REPORTS.

Your task: review the peer reports carefully, decide whether your initial assessment was correct,
and produce a REVISED score + justification.

== YOUR INITIAL ASSESSMENT (model: {model_name}) ==
Score: {own_score}
{own_report}

== PEER REPORTS ==
{peers_json}

== TESTED MODEL REPORT (model: {tested_model_name}, for context only) ==
Score: {tested_score}
{tested_report}

==================================================
REVISION INSTRUCTIONS
==================================================

1. AGREEMENT CHECK
   - Where do the peer reports agree with you? List the consensus findings.
   - Where do they disagree? List each divergence with the CVE ID or topic.

2. RE-EVALUATE DIVERGENCES
   For each divergence, determine who is correct:
   - If a peer identified an exploit path you missed, explain WHY it is or isn't valid.
   - If you identified a risk the peers missed, defend it with code evidence.
   - Do not capitulate to peer pressure without technical justification.

3. REVISED SCORE
   - If you still stand by your original score: explain why.
   - If you revise it: explain what evidence changed your mind.
   - Be precise: the score must reflect real exploitability, not average opinion.

Return ONLY valid JSON:
{{
  "revised_score": <float 0.0–10.0>,
  "score_changed": <true|false>,
  "change_reason": "<one sentence — 'no change' if unchanged>",
  "consensus_findings": ["<finding shared by ≥2 judges>", ...],
  "disagreements": [
    {{"topic": "<CVE or finding>", "your_position": "<verdict>", "peer_position": "<verdict>", "resolution": "<who is right and why>"}}
  ]
}}"""

    @staticmethod
    def _revision_prompt_global(
        model_name: str,
        own_global_report: str,
        own_global_score: float,
        peer_global_reports: List[Dict],
        tested_model_name: str,
        tested_global_report: str,
        tested_global_score: float,
    ) -> str:
        peers_json = json.dumps(peer_global_reports, indent=2)
        return f"""You are a senior C/C++ security analyst in a structured peer review of a GLOBAL vulnerability assessment.

== YOUR INITIAL GLOBAL ASSESSMENT (model: {model_name}) ==
Score: {own_global_score}
{own_global_report}

== PEER GLOBAL REPORTS ==
{peers_json}

== TESTED MODEL GLOBAL REPORT (model: {tested_model_name}, for context only) ==
Score: {tested_global_score}
{tested_global_report}

==================================================
REVISION INSTRUCTIONS
==================================================

1. CHAIN CONSENSUS — do peers agree on the worst-case exploit chain? Identify agreement and disagreement.
2. ATTACKER LEVEL — do peers agree on minimum attacker capability required? Resolve any divergence.
3. REVISED GLOBAL SCORE — adjust only if peers reveal a chain or mitigation you missed.
   The global score may only exceed the highest local score when chaining is confirmed by ≥2 judges.

Return ONLY valid JSON:
{{
  "revised_global_score": <float 0.0–10.0>,
  "score_changed": <true|false>,
  "change_reason": "<one sentence>",
  "consensus_chains": ["<chain description agreed by ≥2 judges>", ...],
  "worst_case_attacker": "<unauthenticated_remote | authenticated_remote | local | physical | none>"
}}"""

    @staticmethod
    def _consensus_synthesis_prompt(
        func_name: str,
        all_judge_reports: List[Dict],   # initial reports
        all_revised_scores: Dict[str, float],
        all_revision_data: List[Dict],   # revision JSON per model
        tested_model_name: str,
        tested_report: str,
        tested_score: float,
        is_global: bool = False,
    ) -> str:
        label = "global" if is_global else "local"
        return f"""You are a senior security analyst producing the FINAL CONSENSUS {label.upper()} vulnerability report.

You have access to:
- Independent initial reports from {len(all_judge_reports)} judge models
- Their revised scores after peer review
- The tested model's report (for comparison only)

== JUDGE INITIAL REPORTS ==
{json.dumps(all_judge_reports, indent=2)}

== REVISED SCORES AFTER PEER REVIEW ==
{json.dumps(all_revised_scores, indent=2)}

== REVISION JUSTIFICATIONS ==
{json.dumps(all_revision_data, indent=2)}

== TESTED MODEL REPORT ({tested_model_name}) ==
Score: {tested_score}
{tested_report}

==================================================
SYNTHESIS INSTRUCTIONS
==================================================

1. CONSENSUS SCORE
   Use the weighted median of the REVISED scores.
   Weight each judge by: 1.0 base + 0.5 bonus if they explicitly found consensus with ≥1 peer.
   Round to 1 decimal place.

2. CONSENSUS FINDINGS
   Include ONLY findings agreed upon by ≥2 judges (or uncontested by any judge).
   For each finding: CVE ID, verdict, taint path summary, attack vector summary.

3. CONTESTED FINDINGS
   List findings where judges disagreed after revision, with the majority position.

4. TESTED MODEL ASSESSMENT
   Briefly note where the tested model ({tested_model_name}) agreed or diverged from consensus.
   Do NOT re-score the tested model — only compare.

5. FINAL VERDICT
   Overall exploitability: EXPLOITABLE / LIKELY / CONDITIONAL / NOT_EXPLOITABLE
   Minimum attacker capability required.

Return ONLY valid JSON:
{{
  "consensus_score": <float 0.0–10.0>,
  "consensus_report": "<Markdown — sections: Executive Summary / Consensus Findings / Contested Findings / Tested Model Comparison / Final Verdict>",
  "final_verdict": "<EXPLOITABLE|LIKELY_EXPLOITABLE|CONDITIONALLY_EXPLOITABLE|NOT_EXPLOITABLE>",
  "score_spread": <float — max revised score minus min revised score>,
  "high_confidence": <true if spread ≤ 2.0, else false>
}}"""

    # ----------------------------------------------------------
    # Main judge + consensus entry point
    # ----------------------------------------------------------

    async def judge_ai_report(self, models: List[Model]) -> None:
        """
        3-phase consensus workflow:

        PHASE 1 — Independent generation
          Each judge generates its own report on a scratch clone, concurrently.

        PHASE 2 — Peer revision (1 round)
          Each judge sees all other judges' Phase-1 reports and revises its score.
          No capitulation without technical justification.

        PHASE 3 — Consensus synthesis
          The judge with the highest revised confidence writes the final consensus
          report using weighted-median scoring.

        Children run their own full consensus pipeline concurrently with this node.
        """
        if not models:
            return

        # Snapshot tested-model reports — never mutated during judging.
        ref_local_report  = self.ai_report or ""
        ref_local_score   = self.ai_vulnerability_score or 0.0
        ref_global_report = self.global_report or ""
        ref_global_score  = self.global_score or 0.0

        # Initialise all judge output dicts
        self.judge_ai_reports               = {}
        self.judge_ai_vulnerability_scores  = {}
        self.judge_ai_global_reports        = {}
        self.judge_ai_global_scores         = {}
        self.judge_ai_metric_scores         = {}
        self.judge_global_ai_metric_scores  = {}
        self.judge_revised_scores           = {}
        self.judge_revised_global_scores    = {}

        # ══════════════════════════════════════════════════════
        # PHASE 1 — independent generation (all models parallel)
        # ══════════════════════════════════════════════════════

        async def phase1_model(model: Model):
            scratch = CallGraphNode._make_scratch(self)
            await scratch.generate_global_ai_report(model=model)
            return model.name, {
                "local_report":  scratch.ai_report or "",
                "local_score":   scratch.ai_vulnerability_score or 0.0,
                "global_report": scratch.global_report or "",
                "global_score":  scratch.global_score or 0.0,
            }

        phase1_results_list = await asyncio.gather(*(phase1_model(m) for m in models))
        phase1: Dict[str, Dict] = dict(phase1_results_list)

        # Write Phase-1 results into the public dicts
        for m in models:
            d = phase1[m.name]
            self.judge_ai_reports[m.name]             = d["local_report"]
            self.judge_ai_vulnerability_scores[m.name] = d["local_score"]
            self.judge_ai_global_reports[m.name]       = d["global_report"]
            self.judge_ai_global_scores[m.name]        = d["global_score"]

        # ══════════════════════════════════════════════════════
        # PHASE 2 — peer revision (all models parallel)
        # ══════════════════════════════════════════════════════

        async def phase2_model(model: Model):
            d = phase1[model.name]
            client = _make_client(model)

            # Build peer lists (everyone except self)
            local_peers = [
                {"model": name, "report": phase1[name]["local_report"], "score": phase1[name]["local_score"]}
                for name in phase1 if name != model.name
            ]
            global_peers = [
                {"model": name, "report": phase1[name]["global_report"], "score": phase1[name]["global_score"]}
                for name in phase1 if name != model.name
            ]

            async def _revise_local():
                if not d["local_report"] or not local_peers:
                    return {"revised_score": d["local_score"], "score_changed": False,
                            "change_reason": "no peers", "consensus_findings": [], "disagreements": []}
                prompt = CallGraphNode._revision_prompt_local(
                    model.name, d["local_report"], d["local_score"],
                    local_peers, Config.model_local.name, ref_local_report, ref_local_score,
                )
                async with _AI_SEMAPHORE_CLOUD:
                    result = await _ask_model(client, prompt, model.name, label=f"Judge revision local [{model.name}]")
                return result or {"revised_score": d["local_score"], "score_changed": False,
                                  "change_reason": "parse error", "consensus_findings": [], "disagreements": []}

            async def _revise_global():
                if not d["global_report"] or not global_peers:
                    return {"revised_global_score": d["global_score"], "score_changed": False,
                            "change_reason": "no peers", "consensus_chains": [], "worst_case_attacker": "none"}
                prompt = CallGraphNode._revision_prompt_global(
                    model.name, d["global_report"], d["global_score"],
                    global_peers, Config.model_local.name, ref_global_report, ref_global_score,
                )
                async with _AI_SEMAPHORE_CLOUD:
                    result = await _ask_model(client, prompt, model.name, label=f"Judge revision global [{model.name}]")
                return result or {"revised_global_score": d["global_score"], "score_changed": False,
                                  "change_reason": "parse error", "consensus_chains": [], "worst_case_attacker": "none"}

            rev_local, rev_global = await asyncio.gather(_revise_local(), _revise_global())
            return model.name, rev_local, rev_global

        phase2_results_list = await asyncio.gather(*(phase2_model(m) for m in models))

        # Index revision data and write revised scores
        revision_local:  Dict[str, Dict] = {}
        revision_global: Dict[str, Dict] = {}

        for model_name, rev_l, rev_g in phase2_results_list:
            # Clamp revised scores to [0, 10]
            revised_local_score  = max(0.0, min(10.0, float(rev_l.get("revised_score",
                                    phase1[model_name]["local_score"]))))
            revised_global_score = max(0.0, min(10.0, float(rev_g.get("revised_global_score",
                                    phase1[model_name]["global_score"]))))

            self.judge_revised_scores[model_name]        = revised_local_score
            self.judge_revised_global_scores[model_name] = revised_global_score

            revision_local[model_name]  = rev_l
            revision_global[model_name] = rev_g

        # Also run metric scoring (Phase-1 quality vs each judge) — unchanged
        async def score_metrics(model: Model):
            client = _make_client(model)
            d = phase1[model.name]

            async def _score_local():
                if not ref_local_report:
                    return {}
                prompt = f"""You are an expert security report evaluator. Score the GENERATED report
against the GROUND TRUTH report produced by a stronger judge model.

== GROUND TRUTH (judge: {model.name}, score: {d['local_score']}) ==
{d['local_report']}

== GENERATED REPORT (model: {Config.model_local.name}, score: {ref_local_score}) ==
{ref_local_report}

Score each metric from 0.0 (poor) to 1.0 (perfect).
Use the calibration rubrics below — do not assign arbitrary values.

METRIC RUBRICS:
- vulnerability_score_accuracy
    1.0 = numeric score within ±1.5 of judge
    0.5 = within ±3.0 of judge
    0.0 = differs by more than 3.0

- taint_analysis_quality
    1.0 = source variable identified, full chain to sink traced with variable names
    0.5 = sink identified but source or intermediate steps missing
    0.0 = generic mention without any taint path

- cve_version_matching
    1.0 = correctly confirmed/denied version affectedness with evidence
    0.5 = version range noted but no explicit match decision
    0.0 = version check absent or wrong

- technical_clarity
    1.0 = specific line numbers AND variable names cited for every claim
    0.5 = function names mentioned but no line numbers or variable details
    0.0 = vague, no code references

- cwe_classification_accuracy
    1.0 = correct CWE ID cited with code-grounded justification
    0.5 = correct vulnerability class named without CWE ID
    0.0 = wrong class or absent

- attack_path_relevance
    1.0 = attack path anchored in actual code (correct function, variable, line)
    0.5 = plausible attack vector not directly proven by the code
    0.0 = generic or unrelated attack description

- technical_justification
    1.0 = every verdict backed by specific line references and variable names
    0.5 = function-level justification without specifics
    0.0 = verdict asserted without code evidence

- speculation_control
    1.0 = no attack paths invented that aren't shown in the code
    0.5 = one unsupported hypothesis clearly marked as speculative
    0.0 = multiple invented paths presented as confirmed

- exploit_completeness
    1.0 = all exploitable CVEs the judge found were also found
    0.5 = one exploitable CVE missed (false negative)
    0.0 = major exploitable CVE missed

- false_positive_rate
    1.0 = no non-exploitable CVEs incorrectly flagged
    0.5 = one minor false positive
    0.0 = significant false positives affecting score

- audit_usefulness
    1.0 = security team can immediately act (specific remediation, affected paths clear)
    0.5 = useful guidance but requires follow-up investigation
    0.0 = too vague or inaccurate to act on

- context_utilization
    1.0 = CWE patterns and canonical examples from the CVE context were explicitly used
    0.5 = CWE mentioned but canonical patterns not referenced
    0.0 = CVE context entirely ignored in analysis

Return ONLY valid JSON:
{{"metric_scores": {{}}, "strengths": ["..."], "weaknesses": ["..."]}}"""
                async with _AI_SEMAPHORE_CLOUD:
                    data = await _ask_model(client, prompt, model.name, label=f"Score local [{model.name}]")
                return data.get("metric_scores", {}) if data else {}

            async def _score_global():
                if not ref_global_report:
                    return {}
                prompt = f"""You are an expert security report evaluator. Score the GENERATED global report
against the GROUND TRUTH global report produced by a stronger judge model.

== GROUND TRUTH (judge: {model.name}, score: {d['global_score']}) ==
{d['global_report']}

== GENERATED GLOBAL REPORT (model: {Config.model_local.name}, score: {ref_global_score}) ==
{ref_global_report}

Score each metric from 0.0 (poor) to 1.0 (perfect).
Use the calibration rubrics below.

METRIC RUBRICS:
- vulnerability_score_accuracy
    1.0 = global score within ±1.5 of judge
    0.5 = within ±3.0
    0.0 = differs by more than 3.0

- exploit_chain_detection
    1.0 = same exploit chains identified with correct call path A→B→C
    0.5 = chain concept correct but path incomplete or vague
    0.0 = chains missed or fabricated

- critical_node_identification
    1.0 = top-3 critical nodes match judge's ranking exactly
    0.5 = top-3 partially correct (≥2 in common)
    0.0 = ranking unrelated to actual vulnerability distribution

- attack_surface_assessment
    1.0 = minimum attacker capability matches judge (correct category)
    0.5 = one level off (e.g. local vs authenticated_remote)
    0.0 = completely wrong or absent

- local_vs_global_risk_differentiation
    1.0 = clearly explains why global score differs from individual maximums
    0.5 = mentions chaining but doesn't justify score delta
    0.0 = no differentiation made

- vulnerability_interaction_analysis
    1.0 = analysed amplification/chaining with specific node pairs and paths
    0.5 = chaining mentioned without specifics
    0.0 = no interaction analysis

- technical_clarity
    1.0 = concrete, specific language throughout (node names, CVE IDs, paths)
    0.5 = mostly concrete with some vague sections
    0.0 = generic or imprecise throughout

- speculation_control
    1.0 = no invented chains or unverified assumptions
    0.5 = one speculative claim clearly labelled
    0.0 = speculative chains presented as confirmed

- audit_usefulness
    1.0 = actionable: critical nodes listed, attack priority clear, remediations suggested
    0.5 = useful overview but missing specific guidance
    0.0 = too abstract for a security team to act on

- call_graph_exploitation
    1.0 = call graph topology explicitly used to trace chains (specific caller→callee paths cited)
    0.5 = graph structure implied but not explicitly cited
    0.0 = chains asserted without topological evidence

Return ONLY valid JSON:
{{"metric_scores": {{}}, "strengths": ["..."], "weaknesses": ["..."]}}"""
                async with _AI_SEMAPHORE_CLOUD:
                    data = await _ask_model(client, prompt, model.name, label=f"Score global [{model.name}]")
                return data.get("metric_scores", {}) if data else {}

            local_m, global_m = await asyncio.gather(_score_local(), _score_global())
            return model.name, local_m, global_m

        metrics_list = await asyncio.gather(*(score_metrics(m) for m in models))
        for model_name, lm, gm in metrics_list:
            self.judge_ai_metric_scores[model_name]        = lm
            self.judge_global_ai_metric_scores[model_name] = gm

        # ══════════════════════════════════════════════════════
        # PHASE 3 — consensus synthesis
        # ══════════════════════════════════════════════════════

        revised_local_scores  = list(self.judge_revised_scores.values())
        revised_global_scores = list(self.judge_revised_global_scores.values())

        # Weighted median: weight = 1 + 0.5 per consensus_finding (Phase-2 signal)
        def _weights_from_revision(rev_dict: Dict[str, Dict], key: str) -> List[float]:
            w = []
            for name in [m.name for m in models]:
                findings = rev_dict.get(name, {}).get(key, [])
                w.append(1.0 + 0.5 * min(len(findings), 4))
            return w

        local_weights  = _weights_from_revision(revision_local, "consensus_findings")
        global_weights = _weights_from_revision(revision_global, "consensus_chains")

        consensus_local  = CallGraphNode._weighted_median(revised_local_scores, local_weights)
        consensus_global = CallGraphNode._weighted_median(revised_global_scores, global_weights)

        spread_local  = CallGraphNode._score_spread(revised_local_scores)
        spread_global = CallGraphNode._score_spread(revised_global_scores)

        # Pick the synthesiser: model with revised score closest to the median
        def _closest_to_median(model_scores: Dict[str, float], median: float) -> Model:
            best = min(models, key=lambda m: abs(model_scores.get(m.name, 0.0) - median))
            return best

        synthesiser_local  = _closest_to_median(self.judge_revised_scores, consensus_local)
        synthesiser_global = _closest_to_median(self.judge_revised_global_scores, consensus_global)

        all_local_initial = [
            {"model": m.name, "report": phase1[m.name]["local_report"],
             "score": phase1[m.name]["local_score"],
             "revised_score": self.judge_revised_scores[m.name]}
            for m in models
        ]
        all_global_initial = [
            {"model": m.name, "report": phase1[m.name]["global_report"],
             "score": phase1[m.name]["global_score"],
             "revised_score": self.judge_revised_global_scores[m.name]}
            for m in models
        ]

        async def _synthesise_local():
            if not any(d["local_report"] for d in phase1.values()):
                return None
            client = _make_client(synthesiser_local)
            prompt = CallGraphNode._consensus_synthesis_prompt(
                self.func_name or "",
                all_local_initial,
                self.judge_revised_scores,
                [{"model": m.name, **revision_local.get(m.name, {})} for m in models],
                Config.model_local.name, ref_local_report, ref_local_score,
                is_global=False,
            )
            async with _AI_SEMAPHORE_CLOUD:
                return await _ask_model(
                    client, prompt, synthesiser_local.name,
                    label=f"Consensus synthesis local [{synthesiser_local.name}]",
                )

        async def _synthesise_global():
            if not any(d["global_report"] for d in phase1.values()):
                return None
            client = _make_client(synthesiser_global)
            prompt = CallGraphNode._consensus_synthesis_prompt(
                self.func_name or "",
                all_global_initial,
                self.judge_revised_global_scores,
                [{"model": m.name, **revision_global.get(m.name, {})} for m in models],
                Config.model_local.name, ref_global_report, ref_global_score,
                is_global=True,
            )
            async with _AI_SEMAPHORE_CLOUD:
                return await _ask_model(
                    client, prompt, synthesiser_global.name,
                    label=f"Consensus synthesis global [{synthesiser_global.name}]",
                )

        syn_local, syn_global = await asyncio.gather(_synthesise_local(), _synthesise_global())

        # Write consensus outputs — fall back to weighted median score if synthesis fails
        if syn_local:
            self.consensus_local_score = max(0.0, min(10.0,
                float(syn_local.get("consensus_score", consensus_local))))
        else:
            self.consensus_local_score = round(consensus_local, 1)

        if syn_global:
            self.consensus_global_score = max(0.0, min(10.0,
                float(syn_global.get("consensus_score", consensus_global))))
            self.consensus_report = syn_global.get("consensus_report", "")
        else:
            self.consensus_global_score = round(consensus_global, 1)
            self.consensus_report = ""

        # ── Children run their full consensus pipeline concurrently ──────
        await asyncio.gather(*(child.judge_ai_report(models) for child in self.children))

    # ----------------------------------------------------------
    # Display
    # ----------------------------------------------------------

    def print_call_graph(self, indent: int = 0, visited: Optional[Set[str]] = None):
        if visited is None:
            visited = set()
        prefix = "│   " * indent

        if self.func_name in visited:
            print(f"{prefix}↺ {self.func_name} (already visited)")
            return
        visited.add(self.func_name)

        line = f"{prefix}├─ {self.func_name}"
        if self.library:
            line += f"  [lib: {self.library.name}"
            if self.library.version != "unknown":
                line += f" {self.library.version}"
            line += "]"
        print(line)

        for loc in self.locations:
            print(f"{prefix}│   ↳ called at {loc['file']}:{loc['line']}")

        for child in self.children:
            child.print_call_graph(indent + 1, visited)


# ============================================================
# CallGraph root
# ============================================================

@dataclass
class CallGraph(CallGraphNode):
    pass