import json
import re
from pathlib import Path
from typing import List, Set, Dict, Tuple, Optional


class DataFlowBackwardSlicer:
    def __init__(
        self,
        call_graph_path: Optional[str],
        source_dir: str,
        functions: Optional[Dict] = None,
    ):
        self.source_dir = Path(source_dir)

        if functions is not None:
            self.functions: Dict = functions
        elif call_graph_path is not None:
            with open(call_graph_path, "r") as f:
                call_graph = json.load(f)
            self.functions = call_graph.get("functions", {})
        else:
            self.functions = {}

        self.sliced_lines: Dict[str, Set[int]] = {}
        self.sliced_functions: Set[str] = set()
        self.includes: Set[str] = set()
        self.variable_dependencies: Dict = {}

    # ------------------------------------------------------------------
    # Path / file helpers
    # ------------------------------------------------------------------

    def _normalize_path(self, path: str) -> str:
        return path.replace("\\", "/").replace("//", "/")

    def _read_source_file(self, file_path: str) -> List[str]:
        filename = Path(file_path).name
        normalized = self._normalize_path(file_path)
        candidates = [
            Path(file_path),
            self.source_dir / file_path,
            self.source_dir / filename,
            self.source_dir / normalized,
            self.source_dir / Path(normalized).name,
        ]
        for candidate in candidates:
            if candidate.exists():
                try:
                    with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
                        return f.readlines()
                except Exception:
                    continue
        return []

    def _extract_includes_from_file(self, file_path: str):
        for line in self._read_source_file(file_path):
            stripped = line.strip()
            if stripped.startswith("#include"):
                self.includes.add(stripped)

    # ------------------------------------------------------------------
    # Variable / expression analysis
    # ------------------------------------------------------------------

    # Base C++ keywords — intentionally lean so we don't filter user identifiers
    _CPP_KEYWORDS = {
        "int", "char", "bool", "void", "double", "float", "long", "short",
        "unsigned", "signed", "auto", "const", "static", "volatile", "inline",
        "register", "extern", "mutable", "explicit",
        "return", "if", "else", "for", "while", "do", "switch", "case",
        "break", "continue", "new", "delete", "try", "catch", "throw",
        "true", "false", "nullptr", "NULL", "this",
        "class", "struct", "enum", "namespace", "using", "typedef",
        "template", "typename", "public", "private", "protected",
        "virtual", "override", "final",
        # STL types — don't track these as user vars
        "string", "wstring", "vector", "map", "set", "list", "deque",
        "unordered_map", "unordered_set", "pair", "tuple", "array",
        "shared_ptr", "unique_ptr", "weak_ptr", "optional",
        # Common stream/io
        "cout", "cerr", "cin", "endl", "std",
        # Common numeric literals / size
        "size_t", "ssize_t", "ptrdiff_t", "uint8_t", "uint16_t",
        "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t",
    }

    # Security-relevant patterns that should ALWAYS be included in context
    _SECURITY_PATTERNS = [
        # Memory operations
        r"\b(malloc|calloc|realloc|free|alloca)\s*\(",
        r"\b(memcpy|memmove|memset|memcmp|strcpy|strncpy|strcat|strncat|sprintf|snprintf|vsprintf|gets|fgets)\s*\(",
        # Integer / size operations that affect buffers
        r"\b(sizeof|strlen|strnlen|wcslen)\s*\(",
        # Format string sinks
        r"\b(printf|fprintf|sscanf|fscanf|scanf)\s*\(",
        # File / path operations
        r"\b(fopen|open|read|write|pread|pwrite|mmap|munmap)\s*\(",
        # Network / input
        r"\b(recv|recvfrom|recvmsg|send|sendto|accept|bind|connect)\s*\(",
        # Heap management
        r"\b(operator new|operator delete)\b",
        # C-string index / cast
        r"\[\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\]",   # array indexing with variable
        r"\(char\s*\*\)|\(uint8_t\s*\*\)|\(unsigned char\s*\*\)",  # unsafe cast
        # Integer overflow indicators
        r"\b(atoi|atol|atof|strtol|strtoul|strtoll|strtoull)\s*\(",
    ]
    _SECURITY_RE = [re.compile(p) for p in _SECURITY_PATTERNS]

    def _is_security_relevant(self, line: str) -> bool:
        """Return True if a line contains a security-sensitive operation."""
        stripped = line.strip()
        if stripped.startswith(("//", "/*", "*")):
            return False
        return any(rx.search(line) for rx in self._SECURITY_RE)

    def _extract_variables_from_expression(self, expr: str) -> Set[str]:
        # Strip string literals and char literals first
        expr = re.sub(r'"(?:[^"\\]|\\.)*"', "", expr)
        expr = re.sub(r"'(?:[^'\\]|\\.)'", "", expr)
        # Strip numeric literals
        expr = re.sub(r"\b\d+[uUlLfF]*\b", "", expr)
        tokens = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", expr)
        return {t for t in tokens if t not in self._CPP_KEYWORDS}

    def _extract_member_base(self, line: str) -> Set[str]:
        """
        Extract base objects from member access (obj.field, obj->field, obj[i]).
        These should be tracked as dependencies.
        """
        bases: Set[str] = set()
        # obj.field  or  obj->field
        for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\.|\->)\s*[a-zA-Z_]", line):
            base = m.group(1)
            if base not in self._CPP_KEYWORDS:
                bases.add(base)
        # obj[expr]
        for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\[", line):
            base = m.group(1)
            if base not in self._CPP_KEYWORDS:
                bases.add(base)
        return bases

    def _parse_assignment(self, line: str) -> Optional[Tuple[str, Set[str]]]:
        """
        Parse an assignment or declaration.
        Returns (defined_var, set_of_used_vars) or None.
        Handles:
          - Simple:    Type var = expr;
          - Compound:  var += expr;  var -= expr; etc.
          - Member:    obj.field = expr; (tracks obj)
          - Pointer:   *ptr = expr; (tracks ptr)
          - Auto:      auto [x, y] = ...
        """
        stripped = line.strip()

        _skip_prefixes = (
            "//", "/*", "if ", "if(", "else", "for ", "for(",
            "while ", "while(", "return", "break", "continue",
            "case ", "cout", "cerr", "cin", "#", "throw",
        )
        if not stripped or stripped.startswith(_skip_prefixes):
            return None

        # Compound assignment: var op= expr
        compound = re.match(
            r"([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s*"
            r"(?:\+|-|\*|/|%|&|\||\^|<<|>>)=\s*(.+);?$",
            stripped,
        )
        if compound:
            lhs = compound.group(1).split(".")[0]
            deps = self._extract_variables_from_expression(compound.group(2))
            deps |= self._extract_member_base(compound.group(1))
            return lhs, deps

        # Normal assignment with =
        if "=" in stripped and "==" not in stripped and "!=" not in stripped:
            # Avoid matching comparison in if/for guards
            left, _, right = stripped.partition("=")

            # Member write: obj.field = expr  →  track obj
            member_m = re.match(
                r"((?:[a-zA-Z_][a-zA-Z0-9_]*\s*(?:\.|\->)\s*)*[a-zA-Z_][a-zA-Z0-9_]*)\s*$",
                left.strip(),
            )
            if member_m:
                full_lhs = member_m.group(1).strip()
                base = re.split(r"\s*(?:\.|\->)\s*", full_lhs)[0].strip("*& \t")
                if base and base not in self._CPP_KEYWORDS:
                    deps = self._extract_variables_from_expression(right.rstrip(";"))
                    deps |= self._extract_member_base(right)
                    return base, deps

            left_tokens = left.strip().split()
            if left_tokens:
                var_name = left_tokens[-1].strip("*&[]()")
                if var_name and var_name not in self._CPP_KEYWORDS:
                    deps = self._extract_variables_from_expression(right.rstrip(";"))
                    deps |= self._extract_member_base(right)
                    return var_name, deps

        # Constructor / function call that defines a variable:
        # Type var(args);   or   auto var = Type{args};
        ctor = re.match(
            r"(?:[a-zA-Z_:][a-zA-Z0-9_:<>*& ,]*\s+)([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*;?$",
            stripped,
        )
        if ctor:
            var_name = ctor.group(1)
            if var_name not in self._CPP_KEYWORDS:
                deps = self._extract_variables_from_expression(ctor.group(2))
                return var_name, deps

        return None

    # ------------------------------------------------------------------
    # Function bounds
    # ------------------------------------------------------------------

    def _find_function_bounds(self, lines: List[str], start_line: int) -> Tuple[int, int]:
        """
        Return (func_start_idx, func_end_idx) in 0-based line indices.
        Walks backward past comments/blank lines to include the full signature.
        """
        start_idx = max(0, start_line - 1)

        # Walk back to capture multi-line signatures and doc comments
        func_start = start_idx
        while func_start > 0:
            prev = lines[func_start - 1].strip()
            if (
                prev.startswith(("//", "/*", "*", "*/"))
                or not prev
                or prev.endswith((",", "(", "\\"))
                or re.match(r"^[a-zA-Z_][a-zA-Z0-9_:*& <>]*$", prev)  # return type on own line
            ):
                func_start -= 1
            else:
                break

        # Find opening brace
        brace_start = start_idx
        while brace_start < len(lines) and "{" not in lines[brace_start]:
            brace_start += 1

        if brace_start >= len(lines):
            return func_start, min(start_idx + 100, len(lines) - 1)

        brace_count = 0
        func_end = brace_start

        for i in range(brace_start, len(lines)):
            # Skip braces in string literals (rough heuristic)
            line = lines[i]
            in_string = False
            for ch in line:
                if ch == '"':
                    in_string = not in_string
                if not in_string:
                    if ch == '{':
                        brace_count += 1
                    elif ch == '}':
                        brace_count -= 1
            if brace_count == 0 and i >= brace_start:
                func_end = i
                break

        return func_start, func_end

    # ------------------------------------------------------------------
    # Multi-pass dependency tracing
    # ------------------------------------------------------------------

    def _trace_variable_dependencies(
        self,
        file_path: str,
        func_start: int,
        func_end: int,
        target_vars: Set[str],
        call_line: int,
    ) -> Set[int]:
        """
        Multi-pass backward slicer:
        Pass 1 — track assignment chains for target_vars
        Pass 2 — include security-relevant lines touching any tracked var
        Pass 3 — include member accesses / array indexing on tracked vars
        Pass 4 — include buffer size declarations (sizeof, strlen, numeric literals
                 assigned to any var that feeds a tracked var)
        Always includes: function signature, all parameters, try/catch blocks,
                         #define macros near the function.
        """
        lines = self._read_source_file(file_path)
        if not lines:
            return set()

        relevant_lines: Set[int] = set()
        needed_vars = set(target_vars)  # working set

        # ── Pass 1: assignment chains (iterate until fixpoint) ──────────
        MAX_PASSES = 6
        for _ in range(MAX_PASSES):
            prev_size = len(needed_vars)
            for line_idx in range(min(call_line - 1, len(lines) - 1), func_start - 1, -1):
                line = lines[line_idx]
                line_num = line_idx + 1

                assignment = self._parse_assignment(line)
                if assignment:
                    defined_var, used_vars = assignment
                    if defined_var in needed_vars:
                        relevant_lines.add(line_num)
                        needed_vars.discard(defined_var)
                        needed_vars.update(used_vars - self._CPP_KEYWORDS)

            if len(needed_vars) == prev_size:
                break  # fixpoint reached

        # ── Pass 2: security-relevant lines touching any tracked var ────
        for line_idx in range(func_start, min(call_line, len(lines))):
            line = lines[line_idx]
            line_num = line_idx + 1
            if self._is_security_relevant(line):
                line_vars = self._extract_variables_from_expression(line)
                line_vars |= self._extract_member_base(line)
                if line_vars & needed_vars:
                    relevant_lines.add(line_num)
                    # Pull new vars introduced by this security sink into scope
                    needed_vars.update(line_vars - self._CPP_KEYWORDS)

        # ── Pass 3: member accesses & array indexing on tracked vars ────
        for line_idx in range(func_start, min(call_line, len(lines))):
            line = lines[line_idx]
            line_num = line_idx + 1
            base_vars = self._extract_member_base(line)
            if base_vars & needed_vars:
                relevant_lines.add(line_num)

        # ── Pass 4: buffer-size declarations ────────────────────────────
        # Any line with sizeof/strlen/numeric constant assigned to a var
        # that is in needed_vars, or that directly feeds the call args.
        size_pattern = re.compile(
            r"\b(sizeof|strlen|strnlen|wcslen|_countof|ARRAY_SIZE)\s*\("
            r"|\b\d+\s*(u|ul|UL|LL|ULL)?\b",
        )
        for line_idx in range(func_start, min(call_line, len(lines))):
            line = lines[line_idx]
            line_num = line_idx + 1
            if size_pattern.search(line):
                line_vars = self._extract_variables_from_expression(line)
                if line_vars & needed_vars or not line_vars:
                    # Include if it involves a tracked var or is a bare constant decl
                    assignment = self._parse_assignment(line)
                    if assignment and assignment[0] in needed_vars:
                        relevant_lines.add(line_num)

        # ── Always include: function signature lines ─────────────────────
        # The first lines up to and including the opening brace
        for line_idx in range(func_start, min(func_start + 8, len(lines))):
            line_num = line_idx + 1
            relevant_lines.add(line_num)
            if "{" in lines[line_idx]:
                break

        # ── Always include: parameter declarations (within first 15 lines) ─
        for line_idx in range(func_start, min(func_start + 15, func_end + 1)):
            line = lines[line_idx].strip()
            line_num = line_idx + 1
            # Parameter-like patterns: type identifier, or just an identifier
            if re.search(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_*&\[\]]*)\s*[,);]", line):
                relevant_lines.add(line_num)

        # ── Always include: try/catch/throw blocks near relevant lines ───
        for line_idx in range(func_start, func_end + 1):
            line_num = line_idx + 1
            line = lines[line_idx].strip()
            if re.search(r"\b(try|catch|throw)\b", line):
                if any(abs(line_num - r) < 15 for r in relevant_lines):
                    # Include the try/catch + a few lines of context
                    for offset in range(-1, 4):
                        nb = line_num + offset
                        if func_start < nb <= func_end + 1:
                            relevant_lines.add(nb)

        # ── Always include: #define / const declarations at file scope ──
        for line_idx, line in enumerate(lines[:func_start]):
            stripped = line.strip()
            if stripped.startswith("#define") or re.match(r"^(const\s+|constexpr\s+)", stripped):
                # Include if it names something used in the slice
                define_vars = self._extract_variables_from_expression(stripped)
                if define_vars & needed_vars:
                    relevant_lines.add(line_idx + 1)

        return relevant_lines

    # ------------------------------------------------------------------
    # Call info extraction (multi-line aware)
    # ------------------------------------------------------------------

    def _extract_function_call_info(self, file_path: str, call_line: int) -> Optional[Dict]:
        lines = self._read_source_file(file_path)
        if not lines or call_line > len(lines):
            return None

        # Collect potentially multi-line call (join up to 4 lines)
        raw = ""
        for offset in range(4):
            idx = call_line - 1 + offset
            if idx >= len(lines):
                break
            raw += lines[idx]
            if ";" in raw or ")" in raw:
                break
        call_line_text = lines[call_line - 1]

        # Match function name + args — handle nested parens
        match = re.search(r"([a-zA-Z_][a-zA-Z0-9_:~]*)\s*\(", raw)
        if not match:
            return None

        func_name = match.group(1)
        # Extract balanced args
        start = raw.index("(", match.start())
        depth = 0
        arg_str = ""
        for ch in raw[start:]:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            if depth > 0 and ch != "(":
                arg_str += ch

        arg_vars = self._extract_variables_from_expression(arg_str)
        arg_vars |= self._extract_member_base(arg_str)

        # Track result variable
        result_var = None
        if "=" in call_line_text and "==" not in call_line_text:
            left_part = call_line_text.split("=")[0].strip()
            tokens = left_part.split()
            if tokens:
                result_var = tokens[-1].strip("*&()")

        # Extract pointer/array arguments explicitly — they're high-value for overflow
        ptr_args: Set[str] = set()
        for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[|\+)", arg_str):
            v = m.group(1)
            if v not in self._CPP_KEYWORDS:
                ptr_args.add(v)
        arg_vars |= ptr_args

        return {
            "function": func_name,
            "arguments": arg_str.strip(),
            "arg_variables": arg_vars,
            "result_variable": result_var,
            "line_text": call_line_text.strip(),
        }

    # ------------------------------------------------------------------
    # Slicing entry point
    # ------------------------------------------------------------------

    def slice_from_call(self, file_path: str, call_line: int) -> Optional[Dict]:
        normalized_file = self._normalize_path(file_path)
        containing_func = None
        func_info = None

        for fname, finfo in self.functions.items():
            func_file_norm = self._normalize_path(finfo["file"])
            func_filename = Path(finfo["file"]).name
            target_filename = Path(file_path).name

            if func_file_norm == normalized_file or func_filename == target_filename:
                func_lines = self._read_source_file(finfo["file"])
                if not func_lines:
                    continue
                func_start, func_end = self._find_function_bounds(func_lines, finfo["line"])
                if func_start + 1 <= call_line <= func_end + 1:
                    containing_func = fname
                    func_info = finfo
                    break

        if not containing_func:
            return None

        call_info = self._extract_function_call_info(file_path, call_line)
        if not call_info:
            return None

        func_lines = self._read_source_file(func_info["file"])
        func_start, func_end = self._find_function_bounds(func_lines, func_info["line"])

        relevant_lines = self._trace_variable_dependencies(
            func_info["file"],
            func_start,
            func_end,
            call_info["arg_variables"],
            call_line,
        )
        relevant_lines.add(call_line)
        # Include a 2-line window around the call for context
        for offset in (-1, 1, 2):
            nb = call_line + offset
            if func_start < nb <= func_end + 1:
                relevant_lines.add(nb)

        if func_info["file"] not in self.sliced_lines:
            self.sliced_lines[func_info["file"]] = set()
        self.sliced_lines[func_info["file"]].update(relevant_lines)

        # Recursively include callee — full body for producers, sig for others
        called_func = call_info["function"]
        if called_func in self.functions:
            is_producer = (
                call_info["result_variable"] is not None
                and call_info["result_variable"] in call_info["arg_variables"]
            )
            if is_producer:
                self._slice_function_full(called_func)
            else:
                self._slice_function_signature_only(called_func)

        # Include all callees listed in func_info that look security-relevant
        for callee_call in func_info.get("calls", []):
            callee_name = callee_call.get("function", "")
            if any(rx.search(callee_name) for rx in self._SECURITY_RE):
                if callee_name in self.functions:
                    self._slice_function_signature_only(callee_name)

        self._extract_includes_from_file(func_info["file"])

        return {
            "containing_function": containing_func,
            "call_info": call_info,
            "relevant_lines": sorted(relevant_lines),
            "sliced_functions": list(self.sliced_functions),
        }

    # ------------------------------------------------------------------
    # Function slicing helpers
    # ------------------------------------------------------------------

    def _slice_function_signature_only(self, func_name: str):
        """Include function signature + first/last line of body."""
        if func_name in self.sliced_functions or func_name not in self.functions:
            return
        self.sliced_functions.add(func_name)
        func_info = self.functions[func_name]
        lines = self._read_source_file(func_info["file"])
        if not lines:
            return
        func_start, func_end = self._find_function_bounds(lines, func_info["line"])

        if func_info["file"] not in self.sliced_lines:
            self.sliced_lines[func_info["file"]] = set()

        # Include signature lines (up to opening brace)
        for line_num in range(func_start + 1, min(func_start + 12, func_end + 2)):
            self.sliced_lines[func_info["file"]].add(line_num)
            if "{" in lines[line_num - 1]:
                # Also include closing brace
                self.sliced_lines[func_info["file"]].add(func_end + 1)
                break

        self._extract_includes_from_file(func_info["file"])
        # Recurse shallowly into direct callees (signature only)
        for callee in func_info.get("calls", []):
            if callee["function"] in self.functions:
                self._slice_function_signature_only(callee["function"])

    def _slice_function_full(self, func_name: str):
        """Include the complete body of a producer function."""
        if func_name in self.sliced_functions or func_name not in self.functions:
            return
        self.sliced_functions.add(func_name)
        func_info = self.functions[func_name]
        lines = self._read_source_file(func_info["file"])
        if not lines:
            return
        func_start, func_end = self._find_function_bounds(lines, func_info["line"])

        if func_info["file"] not in self.sliced_lines:
            self.sliced_lines[func_info["file"]] = set()

        for line_num in range(func_start + 1, func_end + 2):
            self.sliced_lines[func_info["file"]].add(line_num)

        self._extract_includes_from_file(func_info["file"])
        # Recurse into called functions (signature only to avoid explosion)
        for callee in func_info.get("calls", []):
            if callee["function"] in self.functions:
                self._slice_function_signature_only(callee["function"])

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def generate_output(self, context: dict, output_path: Optional[str] = None) -> Optional[str]:
        if not context:
            return None

        lines_out = []
        lines_out.append("/" + "=" * 79)
        lines_out.append("// DATA-FLOW BACKWARD SLICE")
        lines_out.append(f"// Target call : {context['call_info']['function']}({context['call_info']['arguments']})")
        lines_out.append(f"// Caller      : {context['containing_function']}")
        lines_out.append(f"// Tracked vars: {', '.join(sorted(context['call_info']['arg_variables']))}")
        lines_out.append("/" + "=" * 79)
        lines_out.append("")

        for file_path in sorted(self.sliced_lines.keys()):
            lines_out.append(f"// ===== FILE: {file_path} =====")
            lines_out.append("")

            src_lines = self._read_source_file(file_path)
            relevant = sorted(self.sliced_lines[file_path])

            # Group consecutive lines; add "..." separator between non-adjacent groups
            groups: List[List[int]] = []
            current: List[int] = []
            for ln in relevant:
                if not current or ln <= current[-1] + 3:  # merge near-adjacent lines
                    current.append(ln)
                else:
                    groups.append(current)
                    current = [ln]
            if current:
                groups.append(current)

            for g_idx, group in enumerate(groups):
                if g_idx > 0:
                    lines_out.append("    // ...")
                for ln in group:
                    if 1 <= ln <= len(src_lines):
                        lines_out.append(f"/* {ln:4d} */ {src_lines[ln - 1].rstrip()}")

            lines_out.append("")
            lines_out.append("/" + "-" * 79)
            lines_out.append("")

        lines_out.append("// ===== SUMMARY =====")
        lines_out.append(f"// Target call : {context['call_info']['function']}")
        lines_out.append(f"// Tracked vars: {', '.join(sorted(context['call_info']['arg_variables']))}")
        lines_out.append(f"// Total lines  : {sum(len(s) for s in self.sliced_lines.values())}")
        lines_out.append(f"// Functions    : {len(self.sliced_functions) + 1}")
        lines_out.append("")
        lines_out.append("/" + "=" * 79)

        result = "\n".join(lines_out)
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(result)

        return result