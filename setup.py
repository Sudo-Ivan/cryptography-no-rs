# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import sys
from pathlib import Path

# Add src to path for imports
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir))

from _cffi_src.build_openssl import ffi as openssl_ffi  # noqa: E402

if __name__ == "__main__":
    from setuptools import setup

    setup(
        ext_modules=[openssl_ffi.distutils_extension()],
    )

