set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Create .venv and install the package with the dev dependency group (expects uv).
setup:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{justfile_directory()}}"
    if ! command -v uv >/dev/null 2>&1; then
        echo "uv is required on PATH" >&2
        exit 1
    fi
    uv sync --group dev

# Run the test suite (pass extra pytest args after --).
test *args:
    cd "{{justfile_directory()}}" && uv run pytest {{args}}

# Host-only: run pytest (or a Lima guest) and tee debug.log for scripts/debug-loop.
debug-log *args:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{justfile_directory()}}"
    uv run python scripts/vm debug-log {{args}} 2>&1 | tee debug.log

# Start (or create) a Lima --plain guest: debian (default), archlinux|arch, ubuntu-26.04|ubuntu, all.
vm-up guest="debian":
    cd "{{justfile_directory()}}" && uv run python scripts/vm up {{guest}}

vm-down guest="debian":
    cd "{{justfile_directory()}}" && uv run python scripts/vm down {{guest}}

# Delete a guest. Required after editing vm/lima/*.yaml (Lima copies the template at create).
vm-rm guest="debian":
    cd "{{justfile_directory()}}" && uv run python scripts/vm rm {{guest}}

# SSH into a guest. Extra remote command after -- (just vm-ssh debian -- uname -a).
vm-ssh guest="debian" *args:
    cd "{{justfile_directory()}}" && uv run python scripts/vm ssh {{guest}} {{args}}

vm-sync guest="debian":
    cd "{{justfile_directory()}}" && uv run python scripts/vm sync {{guest}}

# up + rsync + remote pytest. Extra pytest args after --.
vm-test guest="debian" *args:
    cd "{{justfile_directory()}}" && uv run python scripts/vm test {{guest}} {{args}}

# Stopped-VM qcow2 snapshot tag=golden / restore. Do not snapshot a running guest.
vm-snapshot guest="debian":
    cd "{{justfile_directory()}}" && uv run python scripts/vm snapshot {{guest}}

vm-restore guest="debian":
    cd "{{justfile_directory()}}" && uv run python scripts/vm restore {{guest}}

# Lint with ruff (pass extra ruff args after --).
lint *args:
    cd "{{justfile_directory()}}" && uv run ruff check src tests scripts {{args}}

# Typecheck with ty (pass extra ty args after --).
typecheck *args:
    cd "{{justfile_directory()}}" && uv run ty check src {{args}}

# Tag and build the next release candidate (omit version to be prompted).
rc *args:
    "{{justfile_directory()}}/scripts/release" --rc {{args}}

# Tag and build a Python pre-release from any branch (not pushed).
pre *args:
    "{{justfile_directory()}}/scripts/release" --pre {{args}}

# Tag and build a release (omit version to be prompted; return accepts the guess).
release *args:
    "{{justfile_directory()}}/scripts/release" {{args}}
