"""
AST Context Extractor — "Best Related Neighbours."

When a deterministic fix isn't available, we fall back to an LLM. Sending
the LLM a whole file (or worse, the whole repo) as context is slow,
expensive, and actually makes the fix LESS accurate — irrelevant
surrounding code gives the model more opportunities to get confused about
what it's supposed to change.

This module extracts the *minimal* subgraph of code the LLM actually needs:

1. **Backward taint trace.** Starting at the vulnerable AST node, walk
   backward through the data-flow graph to find every variable, call, or
   import that the vulnerable expression's value actually depends on.
   Concretely: if the sink is `cursor.execute(query)`, we need to know
   that `query` was built from `username`, so we walk back through every
   assignment until we hit a fixed point (no new names get pulled in).

2. **Lexical enclosure.** Walk outward from the vulnerable line through its
   enclosing scopes — function, then class — so the LLM can see the
   function signature and any class-level state the code references, but
   NOT unrelated sibling functions/methods in the same file.

3. **Minimal subgraph assembly.** The union of (1) and (2) plus the
   necessary import statements is unparsed back into a small, syntactically
   valid Python snippet. Unrelated code is never included.

Implementation note: this uses Python's built-in `ast` module exclusively
(no tree-sitter dependency) since the benchmark fixture and the rules so
far are Python-only; the design generalizes to other languages but the
concrete walker here is Python-specific. `ast.unparse` requires Python 3.9+.
"""

import ast
from dataclasses import dataclass, field


@dataclass
class ExtractedContext:
    source: str  # the minimal, re-parseable snippet
    target_line_in_snippet: (
        int  # where the vulnerable line ended up, 1-indexed within `source`
    )
    included_names: set[str] = field(default_factory=set)
    enclosing_function: str | None = None
    enclosing_class: str | None = None
    truncated: bool = False  # True if a size cap kicked in (see MAX_SNIPPET_LINES)


MAX_SNIPPET_LINES = (
    120  # safety cap so a pathological case can't blow up the LLM context
)


class _ScopeFinder(ast.NodeVisitor):
    """
    First pass: locates the smallest enclosing FunctionDef/AsyncFunctionDef
    (and its enclosing ClassDef, if any) that contains the target line, and
    records the node at the target line itself.
    """

    def __init__(self, target_line: int):
        self.target_line = target_line
        self.target_node: ast.AST | None = None
        self.enclosing_function: ast.FunctionDef | ast.AsyncFunctionDef | None = None
        self.enclosing_class: ast.ClassDef | None = None
        self._class_stack: list[ast.ClassDef] = []
        self._func_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node)
        self.generic_visit(node)
        self._class_stack.pop()

    def _visit_func(self, node) -> None:
        self._func_stack.append(node)
        if self._node_contains_line(node, self.target_line):
            self.enclosing_function = node
            self.enclosing_class = self._class_stack[-1] if self._class_stack else None
        self.generic_visit(node)
        self._func_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def generic_visit(self, node: ast.AST) -> None:
        if (
            hasattr(node, "lineno")
            and getattr(node, "lineno", None) == self.target_line
        ):
            if self.target_node is None or self._is_more_specific(node):
                self.target_node = node
        super().generic_visit(node)

    @staticmethod
    def _node_contains_line(node: ast.AST, line: int) -> bool:
        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", start)
        return start is not None and start <= line <= (end or start)

    def _is_more_specific(self, node: ast.AST) -> bool:
        # Prefer Call/Assign/Expr nodes over bare statements when several
        # nodes share the same starting line (common: `x = f(g(y))` puts
        # Assign, Call, and Name all on the same lineno).
        preferred_types = (ast.Call, ast.Assign, ast.Expr)
        return isinstance(node, preferred_types) and not isinstance(
            self.target_node, preferred_types
        )


class _NameCollector(ast.NodeVisitor):
    """Collects every identifier referenced (Name nodes) within a subtree."""

    def __init__(self):
        self.names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        self.names.add(node.id)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # for `module.func(...)`, also capture `module` as a referenced name
        self.generic_visit(node)


def _collect_names(node: ast.AST) -> set[str]:
    collector = _NameCollector()
    collector.visit(node)
    return collector.names


def _backward_taint_trace(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    target_node: ast.AST,
) -> tuple[list[ast.AST], set[str]]:
    """
    Walks the function body in statement order up to (and including) the
    statement containing target_node, tracking which assignments feed into
    the names referenced by target_node — iterating to a fixed point so
    transitive dependencies are captured (x depends on y, y depends on z).

    Returns (list of relevant statement nodes in original order, set of
    all names that ended up "tainted"/relevant).
    """
    body_statements = function_node.body
    target_line = getattr(target_node, "lineno", None)

    # Find index of the statement containing the target line
    target_stmt_index = len(body_statements) - 1
    for i, stmt in enumerate(body_statements):
        stmt_start = getattr(stmt, "lineno", None)
        stmt_end = getattr(stmt, "end_lineno", stmt_start)
        if stmt_start is not None and stmt_start <= target_line <= (
            stmt_end or stmt_start
        ):
            target_stmt_index = i
            break

    relevant_statements: list[ast.AST] = []
    relevant_names: set[str] = _collect_names(target_node)

    # Always include function args as "seed" relevant names — taint
    # tracing should recognize parameters as sources even if the target
    # line doesn't directly mention every parameter by name yet (it might
    # depend on one transitively through an intermediate variable).
    arg_names = {a.arg for a in function_node.args.args}

    changed = True
    while changed:
        changed = False
        for i in range(target_stmt_index, -1, -1):
            stmt = body_statements[i]
            if stmt in relevant_statements:
                continue

            stmt_names = _collect_names(stmt)
            targets_relevant_name = False

            if isinstance(stmt, ast.Assign):
                assigned_names = set()
                for tgt in stmt.targets:
                    assigned_names |= _collect_names(tgt)
                value_names = _collect_names(stmt.value)
                # This assignment is relevant if EITHER its target is
                # something we already care about (so we now need to know
                # what feeds it), OR its value mentions a name we already
                # care about indirectly through reuse.
                if assigned_names & relevant_names:
                    targets_relevant_name = True
                    if not value_names.issubset(relevant_names):
                        relevant_names |= value_names
                        changed = True
            elif i == target_stmt_index:
                targets_relevant_name = (
                    True  # the target statement itself is always included
                )

            if targets_relevant_name and stmt not in relevant_statements:
                relevant_statements.append(stmt)
                changed = True

    relevant_statements.sort(key=lambda s: getattr(s, "lineno", 0))
    relevant_names |= relevant_names & arg_names
    return relevant_statements, relevant_names


def extract_minimal_context(
    source_code: str, target_line: int
) -> ExtractedContext | None:
    """
    Main entry point. Parses `source_code`, locates the vulnerable node at
    `target_line`, and returns the minimal reconstructed subgraph as a
    standalone, re-parseable snippet.

    Returns None if the source doesn't parse (e.g. a syntax error in the
    target file — in that case the caller should fall back to a fixed
    window of raw lines instead, since we can't build an AST-based context
    for code that isn't valid Python).
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return None

    finder = _ScopeFinder(target_line)
    finder.visit(tree)

    if finder.target_node is None:
        return None

    if finder.enclosing_function is None:
        # Target line is at module level (not inside any function) — just
        # return a small fixed window around it rather than attempting
        # function-scope taint tracing, which doesn't apply here.
        return _module_level_fallback(source_code, target_line)

    relevant_statements, relevant_names = _backward_taint_trace(
        finder.enclosing_function, finder.target_node
    )

    # Build a synthetic FunctionDef containing only the relevant statements,
    # preserving the original signature and decorators so the snippet is
    # still syntactically meaningful to a reader/LLM.
    synthetic_func = ast.FunctionDef(
        name=finder.enclosing_function.name,
        args=finder.enclosing_function.args,
        body=relevant_statements if relevant_statements else [ast.Pass()],
        decorator_list=[],
        returns=None,
        lineno=finder.enclosing_function.lineno,
    )
    ast.fix_missing_locations(synthetic_func)

    # Collect import statements at module level that are referenced by
    # names used anywhere in the relevant statements — this is what lets
    # the LLM see `import subprocess` etc. without including the whole file.
    all_referenced_names: set[str] = set()
    for stmt in relevant_statements:
        all_referenced_names |= _collect_names(stmt)
    relevant_imports = _find_relevant_imports(tree, all_referenced_names)

    if finder.enclosing_class is not None:
        synthetic_class = ast.ClassDef(
            name=finder.enclosing_class.name,
            bases=[],
            keywords=[],
            body=[synthetic_func],
            decorator_list=[],
            lineno=finder.enclosing_class.lineno,
        )
        ast.fix_missing_locations(synthetic_class)
        body_nodes: list[ast.AST] = [*relevant_imports, synthetic_class]
    else:
        body_nodes = [*relevant_imports, synthetic_func]

    module = ast.Module(body=body_nodes, type_ignores=[])
    ast.fix_missing_locations(module)

    try:
        unparsed = ast.unparse(module)
    except Exception:
        return _module_level_fallback(source_code, target_line)

    lines = unparsed.splitlines()
    truncated = False
    if len(lines) > MAX_SNIPPET_LINES:
        lines = lines[:MAX_SNIPPET_LINES]
        truncated = True
        unparsed = "\n".join(lines)

    # locate which output line corresponds to the original target line —
    # best-effort: find the first line containing source text from the
    # target node's unparsed form.
    target_snippet_line = _find_target_line_in_unparsed(unparsed, finder.target_node)

    return ExtractedContext(
        source=unparsed,
        target_line_in_snippet=target_snippet_line,
        included_names=relevant_names,
        enclosing_function=finder.enclosing_function.name,
        enclosing_class=finder.enclosing_class.name if finder.enclosing_class else None,
        truncated=truncated,
    )


def _find_relevant_imports(
    tree: ast.Module, referenced_names: set[str]
) -> list[ast.AST]:
    """
    Scans module-level Import/ImportFrom statements and keeps only the ones
    that bind a name actually used by the extracted subgraph — e.g. if the
    subgraph references `subprocess.run(...)`, keep `import subprocess` but
    not an unrelated `import json` elsewhere in the file.
    """
    relevant: list[ast.AST] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            bound_names = {
                alias.asname or alias.name.split(".")[0] for alias in node.names
            }
            if bound_names & referenced_names:
                relevant.append(node)
        elif isinstance(node, ast.ImportFrom):
            bound_names = {alias.asname or alias.name for alias in node.names}
            if bound_names & referenced_names:
                relevant.append(node)
    return relevant


def _find_target_line_in_unparsed(unparsed: str, target_node: ast.AST) -> int:
    """
    Best-effort line locator: ast.unparse() doesn't preserve original line
    numbers, so we approximate by unparsing the target node alone and
    searching for that text within the full unparsed snippet.
    """
    try:
        target_text = ast.unparse(target_node).strip()
    except Exception:
        return 1
    for i, line in enumerate(unparsed.splitlines(), start=1):
        if target_text and target_text in line:
            return i
    return 1


def _module_level_fallback(
    source_code: str, target_line: int, window: int = 6
) -> ExtractedContext:
    """
    For module-level findings (not inside any function — e.g. `DEBUG =
    True` or a hardcoded secret assignment), AST taint-tracing doesn't
    apply since there's no function scope to trace through. Just return a
    small fixed window of raw source lines around the target.
    """
    lines = source_code.splitlines()
    start = max(0, target_line - window // 2 - 1)
    end = min(len(lines), target_line + window // 2)
    snippet_lines = lines[start:end]
    return ExtractedContext(
        source="\n".join(snippet_lines),
        target_line_in_snippet=target_line - start,
        included_names=set(),
        enclosing_function=None,
        enclosing_class=None,
        truncated=False,
    )
