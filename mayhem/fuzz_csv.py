#!/usr/bin/env python3
import random

import atheris
import sys
import fuzz_helpers
from contextlib import contextmanager
import io
import random

import itertools as it
with atheris.instrument_imports(include=['csv2ofx', 'meza.io']):
    from meza.io import read_csv, IterStringIO
    from csv2ofx import utils
    from csv2ofx.ofx import OFX
    from csv2ofx.qif import QIF
    from csv2ofx.mappings.default import mapping

@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    yield
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
    except (RuntimeError, ValueError):
        return -1
    except TypeError as e:
        if "without an encoding" in str(e):
            return -1
        raise
    except KeyError:
        if random.random() > 0.99:
            raise
        return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
