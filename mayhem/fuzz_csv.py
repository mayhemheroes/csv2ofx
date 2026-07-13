#!/usr/bin/env python3
"""Atheris fuzz harness for csv2ofx (ported from the original integration).

Feeds fuzzed CSV text through the full csv2ofx pipeline (meza read_csv ->
OFX/QIF group/transaction generation -> body rendering), so Atheris records
coverage over the csv2ofx package itself.

Run modes (driven by the compiled launcher `fuzz-csv` / `fuzz-csv-standalone`):
  * fuzzing      — `python3 fuzz_csv.py [libFuzzer args]`
  * single input — `python3 fuzz_csv.py <file>` (libFuzzer runs it once)
"""
import io
import itertools as it
import os
import sys
from contextlib import contextmanager

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fuzz_helpers

with atheris.instrument_imports(include=["csv2ofx", "meza.io"]):
    from meza.io import IterStringIO, read_csv

    from csv2ofx import utils
    from csv2ofx.mappings.default import mapping
    from csv2ofx.ofx import OFX
    from csv2ofx.qif import QIF


@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        yield
    finally:
        sys.stdout = save_stdout
        sys.stderr = save_stderr


def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with nostdout():
            if fdp.ConsumeBool():
                dst = OFX(mapping)
            else:
                dst = QIF(mapping)
            with fdp.ConsumeMemoryFile(all_data=True, as_bytes=False) as f:
                records = read_csv(f)
                groups = dst.gen_groups(records)
                trxns = dst.gen_trxns(groups)
                cleaned_trxns = dst.clean_trxns(trxns)
                data = utils.gen_data(cleaned_trxns)
                content = it.chain([dst.gen_body(data), dst.footer()])
                for _ in IterStringIO(content):
                    pass
    except (RuntimeError, ValueError, KeyError):
        return -1
    except TypeError as e:
        if "without an encoding" in str(e):
            return -1
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
