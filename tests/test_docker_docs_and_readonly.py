"""Regression tests for the Docker docs+readonly hygiene PR (post v0.51.83).

Pins three invariants:

1. The `hermes-agent-src` named volume is mounted READ-ONLY on the WebUI
   service in both multi-container compose files. The WebUI only reads it to
   install agent Python deps at startup; this is defence-in-depth against a
   compromised WebUI writing into the agent's source tree (Concern raised by
   RustyLopez on #2453 and #1416).

2. The workspace bind-mount default uses `${HOME}/workspace` (not `~/workspace`)
   in both multi-container compose files, matching the single-container
   convention so `~`/`${HOME}` doesn't disagree across Linux, macOS, WSL2, and
   Docker Desktop on Windows.

3. `docs/docker.md` documents the agent-image upgrade procedure (`docker volume
   rm hermes-agent-src`) — the root cause of #1416.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


# ── 1: hermes-agent-src must be read-only on the WebUI mount ────────────────


def test_two_container_webui_mounts_agent_src_readonly():
    """The WebUI only reads the agent source to install Python deps. Mounting
    read-only enforces that at the kernel layer — a compromised WebUI process
    cannot rewrite the agent source it then imports."""
    src = (REPO / "docker-compose.two-container.yml").read_text(encoding="utf-8")
    assert (
        "hermes-agent-src:/home/hermeswebui/.hermes/hermes-agent:ro" in src
    ), (
        "two-container: the WebUI must mount hermes-agent-src with :ro. "
        "Without :ro, a compromised WebUI process can rewrite the agent's "
        "Python source tree."
    )


def test_three_container_webui_mounts_agent_src_readonly():
    src = (REPO / "docker-compose.three-container.yml").read_text(encoding="utf-8")
    assert (
        "hermes-agent-src:/home/hermeswebui/.hermes/hermes-agent:ro" in src
    ), (
        "three-container: the WebUI must mount hermes-agent-src with :ro."
    )


def test_agent_service_keeps_writable_agent_src_mount():
    """The agent SERVICE writes the source tree to the volume on first up.
    It must stay read-write — only the WebUI side is read-only."""
    for fn in ("docker-compose.two-container.yml", "docker-compose.three-container.yml"):
        src = (REPO / fn).read_text(encoding="utf-8")
        # The agent's mount is `hermes-agent-src:/opt/hermes` (no :ro suffix).
        # Look for the line that has /opt/hermes without :ro.
        agent_lines = [
            line for line in src.splitlines()
            if "hermes-agent-src:/opt/hermes" in line
        ]
        assert agent_lines, f"{fn}: agent must mount hermes-agent-src at /opt/hermes"
        for line in agent_lines:
            assert not line.rstrip().endswith(":ro"), (
                f"{fn}: agent's hermes-agent-src mount must be writable "
                f"(it populates /opt/hermes on first run): {line!r}"
            )


# ── 2: ${HOME} (not ~) in workspace bind defaults ───────────────────────────


def test_two_container_workspace_uses_home_env_var():
    """Compose v2 expands `~` differently than `${HOME}` under sudo, on Docker
    Desktop on Windows, and on some NAS appliances. Use `${HOME}` to match the
    single-container `docker-compose.yml` and avoid platform drift."""
    src = (REPO / "docker-compose.two-container.yml").read_text(encoding="utf-8")
    assert "${HERMES_WORKSPACE:-${HOME}/workspace}:/workspace" in src, (
        "two-container: workspace default must use ${HOME}/workspace, not ~/workspace, "
        "to match docker-compose.yml's single-container convention."
    )
    assert "${HERMES_WORKSPACE:-~/workspace}" not in src, (
        "two-container: tilde-form workspace default still present — change to ${HOME}/workspace."
    )


def test_three_container_workspace_uses_home_env_var():
    src = (REPO / "docker-compose.three-container.yml").read_text(encoding="utf-8")
    assert "${HERMES_WORKSPACE:-${HOME}/workspace}:/workspace" in src, (
        "three-container: workspace default must use ${HOME}/workspace, not ~/workspace."
    )
    assert "${HERMES_WORKSPACE:-~/workspace}" not in src


def test_single_container_workspace_already_uses_home_env_var():
    """Sanity: the single-container file has used ${HOME} all along; pin it
    so it doesn't drift back."""
    src = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    assert "${HERMES_WORKSPACE:-${HOME}/workspace}:/workspace" in src


# ── 3: docs/docker.md documents the agent-image upgrade procedure ──────────


def test_docker_md_documents_agent_image_upgrade():
    """The `hermes-agent-src` named volume caches the agent source on first
    `up` and is reused verbatim on every subsequent `up`, even after a fresh
    `docker pull` of the agent image. This is the root cause of #1416. The
    docs must give users the explicit `docker volume rm` recipe so they don't
    misdiagnose 'missing entrypoint' errors."""
    docs = (REPO / "docs" / "docker.md").read_text(encoding="utf-8")
    assert "Upgrading the agent container" in docs, (
        "docs/docker.md must have an 'Upgrading the agent container' section."
    )
    assert "docker volume rm" in docs, (
        "docs/docker.md must show the `docker volume rm` step in the upgrade recipe."
    )
    assert "hermes-agent-src" in docs
    # Cross-reference to the original issue so users searching for the
    # symptom land in the right place
    assert "#1416" in docs


def test_compose_files_point_to_docker_md_for_upgrades():
    """Both multi-container compose files should reference docs/docker.md
    near the named-volumes block so anyone reading the compose file directly
    finds the upgrade procedure."""
    for fn in ("docker-compose.two-container.yml", "docker-compose.three-container.yml"):
        src = (REPO / fn).read_text(encoding="utf-8")
        assert "docs/docker.md" in src, (
            f"{fn}: must reference docs/docker.md so users reading the compose "
            f"file see the agent upgrade pointer."
        )
        assert "docker volume rm" in src, (
            f"{fn}: must show the `docker volume rm` upgrade step inline."
        )


# ── 4: docs/docker.md frames the isolation model honestly ──────────────────


def test_docker_md_documents_isolation_model():
    """The multi-container setups give process + network + resource isolation
    but NOT filesystem isolation. Document that explicitly so users don't
    reach for multi-container expecting a trust boundary it doesn't provide
    (RustyLopez's concern on #2453)."""
    docs = (REPO / "docs" / "docker.md").read_text(encoding="utf-8")
    assert "What the multi-container setup isolates" in docs, (
        "docs/docker.md must have a section calibrating multi-container "
        "isolation expectations — process/network/resource isolation, NOT "
        "filesystem isolation."
    )


# ── 5: docker_init.bash stages agent source to a writable build dir ─────────
#
# The :ro mount fixed in PR #2470 broke a second, less obvious surface:
# `uv pip install "$_agent_src[all]"` invokes setuptools' egg_info build step,
# which touches `hermes_agent.egg-info/` *inside the source tree* even under
# PEP 517 build isolation. On a `:ro` mount this returns `EROFS` and (under
# `set -e`) kills container startup. The fix: copy the source tree into a
# writable tmpfs build dir, run the install against THAT, then clean up.
#
# This was caught the first time the Docker smoke gate ran on its own PR — a
# real regression that 5800+ source-level pytests had no way to surface
# because none of them invoked `docker_init.bash` against a real :ro mount.


def test_docker_init_stages_agent_source_for_writable_install():
    """docker_init.bash must NOT pass the raw _agent_src path to `uv pip
    install` — that hits the :ro mount and fails. It must stage the source
    into a writable build dir first (the staged path is used in the install
    invocation)."""
    src = (REPO / "docker_init.bash").read_text(encoding="utf-8")

    # The fix uses a /tmp staging path that's clearly distinct from the
    # mounted source path. Pin the staging marker.
    assert "_stage_src=" in src, (
        "docker_init.bash must declare a _stage_src writable build dir "
        "before invoking `uv pip install` against the (potentially :ro) "
        "hermes-agent source."
    )

    # The install line must reference the staged path, NOT the raw _agent_src
    # path. The pre-fix code was:
    #   uv pip install "$_agent_src[all]" ...
    # The fixed code is:
    #   uv pip install "$_stage_src[all]" ...
    install_lines = [
        line for line in src.splitlines()
        if "uv pip install" in line and "[all]" in line
    ]
    assert install_lines, "expected an `uv pip install ...[all]` line in docker_init.bash"
    for line in install_lines:
        assert '"$_agent_src[all]"' not in line, (
            "docker_init.bash invokes `uv pip install $_agent_src[all]` "
            "directly — this fails with EROFS when the hermes-agent volume "
            "is mounted :ro (the production multi-container default). "
            "Use the writable $_stage_src path instead. "
            f"Offending line: {line!r}"
        )
        assert "_stage_src" in line, (
            "the `uv pip install ...[all]` line must use the staged writable "
            f"path. Offending line: {line!r}"
        )


def test_docker_init_excludes_egg_info_during_staging():
    """The staging copy must exclude pre-baked *.egg-info / build / dist
    directories. setuptools takes a different (timestamp-update) code path
    when one is already present in the source tree, which itself hits the
    :ro mount through stat/utime calls. Excluding them keeps the build
    happily on the fresh-build code path."""
    src = (REPO / "docker_init.bash").read_text(encoding="utf-8")
    # Either rsync --exclude= form or the cp-fallback's explicit rm -rf —
    # accept either provided the egg-info exclusion exists.
    assert "egg-info" in src, (
        "docker_init.bash staging must exclude *.egg-info from the copy "
        "to avoid setuptools' timestamp-update code path."
    )

