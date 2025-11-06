# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

try:
    from cryptography.hazmat.bindings.openssl import binding
except ImportError:
    raise ImportError(
        "cryptography requires the _openssl CFFI module to be built. "
        "Please install cryptography with a proper build system."
    )

lib = binding.Binding.lib
ffi = binding.Binding.ffi

