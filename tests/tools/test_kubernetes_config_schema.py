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

import ast
import inspect
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


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


def test_kubernetes_is_bridged_by_all_three_config_paths():
    """terminal_tool reads os.environ only; three independent code paths bridge
    terminal.* into env vars (CLI, gateway, config helper). A key missing from
    any one of them silently does nothing for that entry point."""
    import cli
    import gateway.run as gateway_run
    from hermes_cli.config import TERMINAL_CONFIG_ENV_MAP

    assert TERMINAL_CONFIG_ENV_MAP["kubernetes"] == "TERMINAL_KUBERNETES"

    cli_source = inspect.getsource(cli.load_cli_config)
    assert '"kubernetes": "TERMINAL_KUBERNETES"' in cli_source

    gateway_source = inspect.getsource(gateway_run)
    assert '"kubernetes": "TERMINAL_KUBERNETES"' in gateway_source


def test_no_per_setting_kubernetes_env_vars_exist():
    """The exact policy violation that closed PR #37591: no user-facing
    TERMINAL_KUBERNETES_<SETTING> names anywhere in the tree."""
    pattern = re.compile(r"TERMINAL_KUBERNETES_[A-Z0-9_]+")
    offenders = []
    scanned = [
        REPO_ROOT / "tools" / "terminal_tool.py",
        REPO_ROOT / "tools" / "environments" / "kubernetes.py",
        REPO_ROOT / "hermes_cli" / "config.py",
        REPO_ROOT / "hermes_cli" / "config_defaults.py",
        REPO_ROOT / "hermes_cli" / "setup.py",
        REPO_ROOT / "hermes_cli" / "status.py",
        REPO_ROOT / "cli.py",
        REPO_ROOT / "gateway" / "run.py",
        REPO_ROOT / "cli-config.yaml.example",
        REPO_ROOT / ".env.example",
        REPO_ROOT / "k8s" / "README.md",
    ]
    for path in scanned:
        if not path.exists():
            continue
        for match in pattern.findall(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(REPO_ROOT)}: {match}")

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
    assert terminal_config_env_var_for_key("terminal.kubernetes.image") is None


def test_nested_kubernetes_keys_validate_as_known_config_keys():
    """`hermes config set terminal.kubernetes.namespace foo` must be accepted,
    which requires every scalar to be enumerated in DEFAULT_CONFIG."""
    from hermes_cli.config import _validate_config_key

    for key in (
        "terminal.kubernetes.namespace",
        "terminal.kubernetes.provisioner",
        "terminal.kubernetes.image",
        "terminal.kubernetes.runtime_class_name",
        "terminal.kubernetes.security_context.run_as_user",
        "terminal.kubernetes.resources.limits.memory",
        "terminal.kubernetes.volume.storage_class_name",
        "terminal.kubernetes.sandbox.template_ref",
    ):
        is_known, suggestion = _validate_config_key(key)
        assert is_known, (
            f"{key} is not recognised as a config key "
            f"(suggestion: {suggestion}). Every scalar must be enumerated in "
            "DEFAULT_CONFIG['terminal']['kubernetes']."
        )


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
    assert "runtime_class_name" in text


def test_backend_module_imports_without_the_kubernetes_sdk():
    """Every `kubernetes` SDK import must be function-local so the module (and
    its manifest builders) load on a machine without the client."""
    source = (REPO_ROOT / "tools" / "environments" / "kubernetes.py").read_text()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Module):
            for stmt in node.body:
                if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                    module = getattr(stmt, "module", None) or ""
                    names = [a.name for a in stmt.names]
                    assert not module.startswith("kubernetes"), (
                        f"module-level `from {module} import ...` breaks import "
                        "without the SDK installed"
                    )
                    assert not any(n.startswith("kubernetes") for n in names), (
                        "module-level `import kubernetes` breaks import without "
                        "the SDK installed"
                    )
