"""Config-policy contract for the kubernetes terminal backend.

Upstream PR #37591 was closed for exposing user-facing ``TERMINAL_KUBERNETES_*``
environment variables while the project's AGENTS.md states that ``.env`` is for
secrets only and all behavioral configuration belongs in ``config.yaml``. These
tests are that policy, expressed as executable contracts:

  1. the schema is enumerated in DEFAULT_CONFIG (so `hermes config set`
     validation, `config show` and the desktop settings schema can walk it),
     and it matches the backend's own defaults;
  2. the whole block is bridged through all three config→env paths as ONE
     internal env var;
  3. no per-setting ``TERMINAL_KUBERNETES_*`` name exists anywhere;
  4. `hermes config set` can never mirror the block into .env.
"""

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Directories a tree-wide scan must not descend into (build output, vendored
#: dependencies, virtualenvs) — none of them is Hermes source.
_SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".ruff_cache",
    ".pytest_cache", "dist", "build", ".mypy_cache", "site-packages",
}


def _tracked_files(*suffixes: str):
    """Every repo file with one of *suffixes*, skipping build/vendor trees."""
    wanted = set(suffixes)
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in wanted:
            continue
        if _SKIP_DIRS & set(path.relative_to(REPO_ROOT).parts):
            continue
        yield path


def test_default_config_mirrors_the_backend_schema():
    """hermes_cli/config_defaults.py must carry a literal copy of the backend's
    DEFAULT_KUBERNETES_CONFIG.

    A literal is required there (the validation walker and the desktop schema
    read DEFAULT_CONFIG, not the backend module), so the two can drift. This is
    the pin.
    """
    from hermes_cli.config_defaults import DEFAULT_CONFIG
    from tools.environments.kubernetes import DEFAULT_KUBERNETES_CONFIG

    assert DEFAULT_CONFIG["terminal"]["kubernetes"] == DEFAULT_KUBERNETES_CONFIG


def test_the_web_settings_provisioner_enum_cannot_drift():
    """The `direct` -> `pod` rename had to touch a SECOND Python-side copy of
    the enum, held in sync by nothing but a comment. When the two drift the web
    settings dropdown offers a value validate_kubernetes_config rejects, and the
    operator learns about it as a ValueError at first session rather than at
    config time.

    Asserted as derivation, not as equality-today: equality passes trivially
    while the copy is still a literal. Patching the source of truth and
    re-reading the options proves the schema FOLLOWS it."""
    import tools.environments.kubernetes as k8s
    from hermes_cli.web_server import (
        _SCHEMA_OVERRIDES,
        _kubernetes_provisioner_options,
    )

    assert (_SCHEMA_OVERRIDES["terminal.kubernetes.provisioner"]["options"]
            == list(k8s.VALID_PROVISIONERS))

    saved = k8s.VALID_PROVISIONERS
    try:
        k8s.VALID_PROVISIONERS = ("pod", "sandbox", "kata-vm")
        assert _kubernetes_provisioner_options() == ["pod", "sandbox", "kata-vm"]
    finally:
        k8s.VALID_PROVISIONERS = saved


def test_kubernetes_is_bridged_by_all_three_config_paths():
    """terminal_tool reads os.environ only; three independent code paths bridge
    terminal.* into env vars (CLI, gateway, config helper). A key missing from
    any one of them silently does nothing for that entry point.

    Asserted from what each path DOES, not from its source text: a
    source-substring test freezes the shape of the code rather than its
    behaviour and breaks on any refactor that keeps the bridge intact."""
    import cli
    import gateway.run as gateway_run
    from hermes_cli.config import TERMINAL_CONFIG_ENV_MAP, apply_terminal_config_to_env

    assert TERMINAL_CONFIG_ENV_MAP["kubernetes"] == "TERMINAL_KUBERNETES"

    config = {"terminal": {"backend": "kubernetes",
                           "kubernetes": {"namespace": "hermes-agents"}}}
    bridged = apply_terminal_config_to_env(env={}, config=config, override=True)
    assert json.loads(bridged["TERMINAL_KUBERNETES"])["namespace"] == "hermes-agents"

    # cli.py and gateway/run.py hold their own literal maps. Extract the
    # MAPPING (data, not code shape) so the pin survives a refactor.
    assert _extract_terminal_env_map(cli, "load_cli_config").get(
        "kubernetes") == "TERMINAL_KUBERNETES"
    assert _extract_terminal_env_map(gateway_run, None).get(
        "kubernetes") == "TERMINAL_KUBERNETES"


def _extract_terminal_env_map(module, func_name):
    """Collect every {"<terminal key>": "TERMINAL_*"} literal in *module*."""
    import ast as _ast
    import inspect as _inspect
    import textwrap

    source = textwrap.dedent(_inspect.getsource(
        getattr(module, func_name) if func_name else module
    ))
    found: dict[str, str] = {}
    for node in _ast.walk(_ast.parse(source)):
        if not isinstance(node, _ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if (isinstance(key, _ast.Constant) and isinstance(key.value, str)
                    and isinstance(value, _ast.Constant)
                    and isinstance(value.value, str)
                    and value.value.startswith("TERMINAL_")):
                found[key.value] = value.value
    return found


def test_no_per_setting_kubernetes_env_vars_exist():
    """The exact policy violation that closed PR #37591: no user-facing
    TERMINAL_KUBERNETES_<SETTING> names anywhere in the tree."""
    pattern = re.compile(r"TERMINAL_KUBERNETES_[A-Z0-9_]+")
    offenders = []
    # A hardcoded file list does not cover "anywhere in the tree" — this
    # refactor ADDED tools/environments/kubernetes_sandbox.py and changed
    # hermes_cli/web_server.py, none of which the old list named. Walk the
    # tracked files instead, so new modules are covered by construction.
    exempt = {
        # Names them as DEPRECATED so anyone who copied PR #37591's .env block
        # gets a diagnosis instead of silence (the assertion below says so).
        "hermes_cli/doctor.py",
        # These tests quote the forbidden names in order to forbid them.
        "tests/tools/test_kubernetes_config_schema.py",
        "tests/tools/test_kubernetes_environment.py",
    }
    for path in _tracked_files(".py", ".md", ".yaml", ".yml", ".example", ".ts",
                              ".tsx", ".json"):
        relative = path.relative_to(REPO_ROOT).as_posix()
        if relative in exempt:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for match in pattern.findall(text):
            offenders.append(f"{relative}: {match}")

    assert not offenders, (
        "Kubernetes settings must live in config.yaml under terminal.kubernetes.*, "
        "not in per-setting environment variables. Found: " + ", ".join(offenders)
        + " (hermes_cli/doctor.py is allowed to name them as DEPRECATED.)"
    )


def test_env_example_has_no_kubernetes_block():
    """.env is for secrets. This backend contributes nothing to it."""
    env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    assert "TERMINAL_KUBERNETES" not in env_example
    assert "kubernetes" not in env_example.lower()


def test_kubernetes_settings_are_not_optional_env_vars():
    """OPTIONAL_ENV_VARS is the .env registry — secrets only."""
    from hermes_cli.config import OPTIONAL_ENV_VARS

    assert not any("KUBERNETES" in str(name).upper() for name in OPTIONAL_ENV_VARS)


def test_config_set_cannot_mirror_the_block_into_dotenv():
    """`hermes config set` mirrors bridged terminal keys into .env. The
    kubernetes block must be excluded, or the policy erodes via the CLI."""
    from hermes_cli.config import (
        _TERMINAL_ENV_MIRROR_EXCLUDED,
        terminal_config_env_var_for_key,
    )

    assert "terminal.kubernetes" in _TERMINAL_ENV_MIRROR_EXCLUDED
    # Nested paths never resolve to an env var at all.
    assert terminal_config_env_var_for_key("terminal.kubernetes.namespace") is None
    assert terminal_config_env_var_for_key("terminal.kubernetes.container_name") is None


def test_nested_kubernetes_keys_validate_as_known_config_keys():
    """`hermes config set terminal.kubernetes.namespace foo` must be accepted,
    which requires every scalar to be enumerated in DEFAULT_CONFIG.

    `pod_template` is deliberately NOT in this list: it is a free-form
    PodTemplateSpec, not dotted-scalar surface, and is edited in config.yaml
    directly."""
    from hermes_cli.config import _validate_config_key

    for key in (
        "terminal.kubernetes.namespace",
        "terminal.kubernetes.provisioner",
        "terminal.kubernetes.container_name",
        "terminal.kubernetes.mount_path",
        "terminal.kubernetes.active_deadline_seconds",
        "terminal.kubernetes.ready_timeout_seconds",
        "terminal.kubernetes.owner_reference",
        "terminal.kubernetes.sandbox.warm_pool",
        "terminal.kubernetes.trusted_sandbox",
    ):
        is_known, suggestion = _validate_config_key(key)
        assert is_known, (
            f"{key} is not recognised as a config key "
            f"(suggestion: {suggestion}). Every scalar must be enumerated in "
            "DEFAULT_CONFIG['terminal']['kubernetes']."
        )


def test_deleted_kubernetes_keys_are_not_recognised():
    """Hard cut: no aliases, no compatibility shim. The old keys must not
    validate, or the collapse is cosmetic."""
    from hermes_cli.config import _validate_config_key

    for key in (
        "terminal.kubernetes.runtime_class_name",
        "terminal.kubernetes.service_account",
        "terminal.kubernetes.security_context.run_as_user",
        "terminal.kubernetes.resources.limits.memory",
        "terminal.kubernetes.sandbox.template_ref",
        "terminal.kubernetes.pod_template_overrides",
        # The stateless / claim-based cut (v36):
        "terminal.kubernetes.image",
        "terminal.kubernetes.persistent",
        "terminal.kubernetes.volume.storage_class_name",
        "terminal.kubernetes.sandbox.api_group",
        "terminal.kubernetes.sandbox.api_version",
    ):
        is_known, _ = _validate_config_key(key)
        assert not is_known, f"{key} was hard-cut but still validates"


def test_deprecated_upstream_env_vars_are_diagnosed():
    """Anyone who copied PR #37591's .env.example block should get a diagnosis
    from `hermes doctor`, not silence."""
    from hermes_cli.doctor import collect_deprecated_env_vars

    findings = collect_deprecated_env_vars(
        {"TERMINAL_KUBERNETES_NAMESPACE": "hermes",
         "TERMINAL_KUBERNETES_POD_SA": "sa"}
    )
    names = {name for name, _ in findings}
    assert "TERMINAL_KUBERNETES_NAMESPACE" in names
    assert "TERMINAL_KUBERNETES_POD_SA" in names


def test_cli_config_example_documents_the_yaml_block():
    text = (REPO_ROOT / "cli-config.yaml.example").read_text(encoding="utf-8")
    assert "backend: \"kubernetes\"" in text
    assert "kubernetes:" in text
    assert "provisioner:" in text
    assert "pod_template:" in text


def test_user_facing_docs_do_not_advertise_deleted_keys():
    """Every one of these was a first-class key. Leaving them in the shipped
    docs sends operators to a knob that no longer exists."""
    gone = ("pod_template_overrides", "spec_overrides", "template_ref",
            "use_claim", "runtime_class_name", "security_context")
    for relative in ("cli-config.yaml.example",
                     "website/docs/user-guide/configuration.md"):
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        for key in gone:
            assert key not in text, f"{relative} still documents {key}"


def test_backend_modules_import_without_the_kubernetes_sdk():
    """Every `kubernetes` SDK import must be function-local so the modules (and
    their manifest builders) load on a machine without the client.

    Executed, not AST-inspected: an import-shape test covers only the one file
    path it names and cannot see whether the module actually loads."""
    import builtins
    import importlib
    import sys

    modules = ("tools.environments.kubernetes",
               "tools.environments.kubernetes_sandbox")
    saved_modules = {
        name: sys.modules.pop(name)
        for name in list(sys.modules)
        if name in modules or name == "kubernetes"
        or name.startswith("kubernetes.")
    }
    real_import = builtins.__import__

    def _blocked(name, *args, **kwargs):
        if name == "kubernetes" or name.startswith("kubernetes."):
            raise ImportError("kubernetes client is not installed")
        return real_import(name, *args, **kwargs)

    builtins.__import__ = _blocked
    try:
        k8s = importlib.import_module(modules[0])
        importlib.import_module(modules[1])
        template = k8s.render_pod_template(k8s.merge_kubernetes_config({}))
        assert template["spec"]["containers"][0]["image"] == k8s.DEFAULT_SESSION_IMAGE
    finally:
        builtins.__import__ = real_import
        for name in modules:
            sys.modules.pop(name, None)
        sys.modules.update(saved_modules)
