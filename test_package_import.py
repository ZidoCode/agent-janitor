#!/usr/bin/env python3
"""test_package_import.py — load agent-janitor the way Hermes does.

Hermes loads plugin directories as packages (hermes_plugins.<slug>) WITHOUT
adding the plugin dir to sys.path. Relative-import mistakes surface only in
that mode, so we reproduce it exactly: importlib.util.spec_from_file_location
with submodule_search_locations, plugin dir NOT on sys.path.
"""
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.path.join(HERE, "__init__.py")

results = []


def check(name, ok):
    results.append((name, ok))


# plugin dir must NOT be importable as a top-level path
saved = sys.path[:]
tmp = tempfile.mkdtemp()
sys.path = [p for p in sys.path if os.path.abspath(p or ".") != HERE]
try:
    sys.path.insert(0, tmp)
    spec = importlib.util.spec_from_file_location(
        "hermes_plugins.agent_janitor", PLUGIN,
        submodule_search_locations=[HERE])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)

    check("package-import: module loads outside plugin-dir sys.path",
          mod.__version__ == "0.1.0")
    check("package-import: register(ctx) exists", callable(mod.register))
    check("package-import: data_dir is profile-aware helper",
          callable(mod.data_dir))

    # ctx double: record hook registrations
    class Ctx:
        def __init__(self):
            self.hooks = []

        def register_hook(self, name, fn):
            self.hooks.append((name, fn))

    ctx = Ctx()
    ret = mod.register(ctx)
    check("package-import: register hooks via ctx API",
          any(h[0] == "post_tool_call" for h in ctx.hooks))
    check("package-import: register returns hook manifest",
          isinstance(ret, dict) and "post_tool_call" in ret.get("hooks", []))

    # enforce-mode gate: data_dir() follows hermes home, not hardcoded ~/.hermes
    src = open(PLUGIN).read()
    check("package-import: no hardcoded ~/.hermes data path",
          '"~/.hermes' not in src and "'~/.hermes" not in src)
    check("package-import: uses get_hermes_home",
          "get_hermes_home" in src)

    # hook function itself is exception-safe with garbage input
    try:
        mod.on_post_tool_call(None, None, result=None)
        check("package-import: hook survives None args", True)
    except Exception:
        check("package-import: hook survives None args", False)
finally:
    sys.path = saved

passed = sum(1 for _, ok in results if ok)
for name, ok in results:
    print(("PASS  " if ok else "FAIL  ") + name)
print(f"RESULT: {'PASS ✅' if passed == len(results) else 'FAIL ❌'} "
      f"({passed}/{len(results)})")
sys.exit(0 if passed == len(results) else 1)
