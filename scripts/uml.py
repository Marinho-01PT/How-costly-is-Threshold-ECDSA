"""Draw src/twoparty as a UML class diagram (Mermaid), before and after a session.

    python scripts/uml.py --before ce76a3b --out docs/uml/2026-10-23.md

Every module is one box with its public functions and classes; an arrow
A ..> B means "A uses B" (imports inside the package). The "after" diagram
colours what is new (green) and what changed (yellow) compared to --before,
and a table sums it up, so two states can be compared without reading code.
--before is read straight from git, --after is the working tree unless a
git ref is given. GitHub and Obsidian both draw Mermaid.
"""
import argparse
import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = "src/twoparty"
NEW_STYLE = "fill:#d8f5d0,stroke:#2e7d32"
CHANGED_STYLE = "fill:#fff1c2,stroke:#b8860b"


def read_files(ref: str | None, folder: str) -> dict[str, str]:
    """{file name: source} of the .py files in folder, at a git ref or on disk."""
    if ref is None:
        return {p.name: p.read_text() for p in sorted((ROOT / folder).glob("*.py"))}
    names = subprocess.run(["git", "ls-tree", "--name-only", f"{ref}:{folder}"], cwd=ROOT,
                           capture_output=True, text=True, check=True).stdout.split()
    return {name: subprocess.run(["git", "show", f"{ref}:{folder}/{name}"], cwd=ROOT,
                                 capture_output=True, text=True, check=True).stdout
            for name in names if name.endswith(".py")}


def _body_dump(node) -> str:
    """The code of a function or class, without its docstring (docs alone are no change)."""
    body = node.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    return "".join(ast.dump(b) for b in body) + ast.dump(node.args) if hasattr(node, "args") \
        else "".join(ast.dump(b) for b in body)


def parse(source: str) -> tuple[dict[str, tuple[str, str]], set[str]]:
    """Public members {name: (label, code)} and the package modules it imports."""
    tree = ast.parse(source)
    members, deps = {}, set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            args = [a.arg for a in node.args.args]
            if len(args) > 4:  # keep the boxes narrow
                args = args[:4] + ["…"]
            members[node.name] = (f"+{node.name}({', '.join(args)})", _body_dump(node))
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            members[node.name] = (f"+class {node.name}", _body_dump(node))
        elif isinstance(node, ast.ImportFrom) and node.level == 1:
            if node.module:  # from .x import y
                deps.add(node.module)
            else:            # from . import x, y
                deps.update(alias.name for alias in node.names)
    return members, deps


def box_id(module: str) -> str:
    return module.strip("_") or "init"


def diagram(modules: dict, status: dict | None = None) -> str:
    """Mermaid classDiagram. status: {module: (module_state, {member: state})}."""
    lines = ["```mermaid", "classDiagram", "direction LR"]
    for mod, (members, _) in sorted(modules.items()):
        mstate = status[mod] if status else ("same", {})
        lines.append(f'class {box_id(mod)}["{mod}.py"] {{')
        for name, (label, _) in members.items():
            mark = {"new": " (new)", "changed": " (changed)"}.get(mstate[1].get(name), "")
            lines.append(f"  {label}{mark}")
        lines.append("}")
    for mod, (_, deps) in sorted(modules.items()):
        for dep in sorted(deps):
            if dep in modules:
                lines.append(f"{box_id(mod)} ..> {box_id(dep)}")
    if status:
        for mod, (state, _) in status.items():
            if state in ("new", "changed") and mod in modules:
                style = NEW_STYLE if state == "new" else CHANGED_STYLE
                lines.append(f"style {box_id(mod)} {style}")
    lines.append("```")
    return "\n".join(lines)


def compare(before: dict, after: dict) -> dict:
    status = {}
    for mod, (members, deps) in after.items():
        if mod not in before:
            status[mod] = ("new", {name: "new" for name in members})
            continue
        old_members, old_deps = before[mod]
        states = {}
        for name, (_, code) in members.items():
            if name not in old_members:
                states[name] = "new"
            elif old_members[name][1] != code:
                states[name] = "changed"
        removed = set(old_members) - set(members)
        changed = states or removed or deps != old_deps
        status[mod] = ("changed" if changed else "same", states)
    return status


def count_tests(ref: str | None) -> int:
    return sum(src.count("\ndef test_") + src.startswith("def test_")
               for src in read_files(ref, "tests").values())


def summary(before: dict, after: dict, status: dict) -> str:
    rows = ["| Module | before | after | what changed |", "|---|---|---|---|"]
    for mod in sorted(set(before) | set(after)):
        b = len(before[mod][0]) if mod in before else "–"
        a = len(after[mod][0]) if mod in after else "deleted"
        if mod not in after:
            what = "deleted"
        else:
            state, members = status[mod]
            new = [n for n, s in members.items() if s == "new"]
            changed = [n for n, s in members.items() if s == "changed"]
            removed = sorted(set(before[mod][0]) - set(after[mod][0])) if mod in before else []
            parts = []
            if state == "new":
                parts.append("**new module**")
            if new and state != "new":
                parts.append("new: " + ", ".join(f"`{n}`" for n in new))
            if changed:
                parts.append("changed: " + ", ".join(f"`{n}`" for n in changed))
            if removed:
                parts.append("removed: " + ", ".join(f"`{n}`" for n in removed))
            if state == "changed" and not parts:
                parts.append("imports only")
            what = "; ".join(parts) or "unchanged"
        rows.append(f"| `{mod}.py` | {b} | {a} | {what} |")
    return "\n".join(rows)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--before", required=True, help="git ref of the old state, e.g. ce76a3b")
    p.add_argument("--after", help="git ref of the new state (default: working tree)")
    p.add_argument("--title", default="UML before / after")
    p.add_argument("--out", help="write the Markdown here instead of printing it")
    a = p.parse_args(argv)

    def load(ref):
        modules = {name[:-3]: parse(src) for name, src in read_files(ref, PKG).items()}
        return {m: v for m, v in modules.items() if v[0] or v[1]}  # skip an empty __init__.py

    before, after = load(a.before), load(a.after)
    status = compare(before, after)
    after_label = a.after or "working tree"
    text = "\n\n".join([
        f"# {a.title}",
        "Made from the code with `python scripts/uml.py`, not drawn by hand. "
        "Each box is a module in `src/twoparty` with its public functions and "
        "classes; an arrow `A ..> B` means \"A uses B\". In the after picture "
        "**green = new module**, **yellow = changed module**, and single functions "
        "are marked (new) or (changed).",
        f"Tests: {count_tests(a.before)} before → {count_tests(a.after)} after "
        "(test functions, not counting parameter variants).",
        "## What changed\n\n" + summary(before, after, status),
        f"## Before (`{a.before}`)\n\n" + diagram(before),
        f"## After ({after_label})\n\n" + diagram(after, status),
    ]) + "\n"
    if a.out:
        out = ROOT / a.out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text)
        print(f"wrote {a.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
