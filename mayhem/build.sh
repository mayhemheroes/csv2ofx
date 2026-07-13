#!/usr/bin/env bash
#
# mayhem/build.sh — build the csv2ofx Atheris fuzz harness + its standalone reproducer,
# and prepare the project's own pytest suite. Runs inside the commit image (mayhem/Dockerfile)
# as `mayhem` in /mayhem. Python adaptation of the C/C++ template.
#
# Idempotent + air-gapped on re-run (SPEC §6.2 item 9 / §6.5):
#   1. Populate / reuse an in-image wheelhouse under /opt/toolchains/python (HOME-independent),
#      then install atheris + the project deps + test deps OFFLINE from that wheelhouse into a
#      fixed site dir. The first (online) build fills the wheelhouse; the air-gapped PATCH
#      re-run resolves entirely from it (pip --no-index --find-links).
#   2. Compile launcher.c -> the ELF Mayhem target `fuzz-csv` (Atheris is a Python script;
#      Mayhem needs an ELF cmd, and the gate needs DWARF < 4 — hence a compiled wrapper).
#   3. Build the same launcher as the standalone (run-once) reproducer `fuzz-csv-standalone`.
#   4. Compile the run_tests ELF wrapper the pytest oracle (test.sh) runs through.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# The launcher is a thin C exec wrapper — Atheris instruments the Python under test at import
# time; $SANITIZER_FLAGS still applies to the compiled wrapper (empty override builds it plain).
: "${SANITIZER_FLAGS=}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${MAYHEM_JOBS:=$(nproc)}"
export DEBUG_FLAGS CC MAYHEM_JOBS

SRC="${SRC:-/mayhem}"
cd "$SRC"

# ── Python toolchain caches at a FIXED, $HOME-independent prefix (SPEC §6.2 item 8) ──
PY_PREFIX=/opt/toolchains/python
WHEELHOUSE="$PY_PREFIX/wheelhouse"
SITE="$PY_PREFIX/site"
mkdir -p "$WHEELHOUSE" "$SITE"

PY="$(command -v python3)"

# 1) Wheelhouse: download every runtime/test dependency ONCE (online). On the air-gapped re-run
#    the directory is already populated, so pip never reaches the network. Runtime deps come from
#    pyproject [project.dependencies]; test deps from the `test` extra (pytest-enabler/pytest-ruff
#    are lint plugins the suite tolerates absent — we ship the functional ones).
PKGS=(atheris pytest freezegun "python-dateutil>=2.7.2,<3.0.0" "requests>=2.18.4,<3.0.0" "meza>=0.47.0,<0.48.0" setuptools wheel)
need_download=0
"$PY" -c "import os,glob,sys; sys.exit(0 if glob.glob(os.path.join('$WHEELHOUSE','atheris-*.whl')) else 1)" || need_download=1
if [ "$need_download" -eq 1 ]; then
  echo ">> populating wheelhouse (online) at $WHEELHOUSE"
  "$PY" -m pip download --dest "$WHEELHOUSE" "${PKGS[@]}"
else
  echo ">> wheelhouse already populated — reusing $WHEELHOUSE (air-gapped re-run path)"
fi

# 2) Install the deps into the fixed site dir, OFFLINE from the wheelhouse. Idempotent: once the
#    site dir holds atheris+pytest we skip the reinstall. csv2ofx itself stays the editable source
#    tree ($SRC on PYTHONPATH, FIRST, so a PATCH agent's edits take effect with no reinstall);
#    a tiny console-script shim for `csv2ofx` (used by the CLI tests) is generated below.
if "$PY" -c "import os,glob,sys; sys.exit(0 if (glob.glob(os.path.join('$SITE','atheris*')) and glob.glob(os.path.join('$SITE','pytest*'))) else 1)"; then
  echo ">> deps already installed in $SITE — skipping (idempotent re-run)"
else
  echo ">> installing deps (offline) into $SITE"
  "$PY" -m pip install --no-index --find-links="$WHEELHOUSE" --target "$SITE" "${PKGS[@]}"
fi

PYRUN="$SRC:$SITE"

# Console script `csv2ofx` (tests/test_cli.py invokes it via subprocess). It resolves the package
# through PYTHONPATH, so the editable source tree wins.
mkdir -p "$PY_PREFIX/bin"
cat > "$PY_PREFIX/bin/csv2ofx" <<EOF
#!$PY
import sys
from csv2ofx.main import run
if __name__ == "__main__":
    sys.exit(run())
EOF
chmod +x "$PY_PREFIX/bin/csv2ofx"

# Record the env for test.sh / the launcher to consume.
cat > "$PY_PREFIX/env.sh" <<EOF
export PYTHONPATH="$PYRUN\${PYTHONPATH:+:\$PYTHONPATH}"
export PYTHON_BIN="$PY"
export PATH="$PY_PREFIX/bin:\$PATH"
EOF

# Sanity: the harness + suite imports must resolve offline now.
PYTHONPATH="$PYRUN" "$PY" -c 'import atheris, pytest, freezegun, meza, csv2ofx; print("imports OK:", csv2ofx.__name__)'

# 3) Compile the ELF launcher target + the standalone reproducer (DWARF < 4 via $DEBUG_FLAGS).
HARNESS="$SRC/mayhem/fuzz_csv.py"
echo ">> compiling fuzz-csv (+ standalone) with DEBUG_FLAGS=$DEBUG_FLAGS"
$CC $DEBUG_FLAGS $SANITIZER_FLAGS -DPYTHON="\"$PY\"" -DHARNESS="\"$HARNESS\"" \
    "$SRC/mayhem/launcher.c" -o "$SRC/fuzz-csv"
# The standalone reproducer is the same launcher: libFuzzer runs a single input file once when
# given a file path (no fuzzing loop) — exactly the run-once reproducer contract.
$CC $DEBUG_FLAGS -DPYTHON="\"$PY\"" -DHARNESS="\"$HARNESS\"" \
    "$SRC/mayhem/launcher.c" -o "$SRC/fuzz-csv-standalone"

# 4) The pytest oracle runs through a compiled NON-system ELF wrapper so the gate's
#    anti-reward-hack sabotage check (which neuters non-system binaries to exit(0)) bites the suite.
$CC $DEBUG_FLAGS -DPYTHON="\"$PY\"" "$SRC/mayhem/run_tests.c" -o "$SRC/csv2ofx_run_tests"

echo ">> build.sh complete"
ls -la "$SRC/fuzz-csv" "$SRC/fuzz-csv-standalone" "$SRC/csv2ofx_run_tests"
