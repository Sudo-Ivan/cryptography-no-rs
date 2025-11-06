# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import typing

from cryptography.hazmat.bindings._rust import _openssl
from cryptography.hazmat.bindings._rust.openssl import (
    aead,
    ciphers,
    cmac,
    dh,
    dsa,
    ec,
    ed448,
    ed25519,
    hashes,
    hmac,
    kdf,
    keys,
    poly1305,
    rsa,
    x448,
    x25519,
)

__all__ = [
    "aead",
    "ciphers",
    "cmac",
    "dh",
    "dsa",
    "ec",
    "ed448",
    "ed25519",
    "hashes",
    "hmac",
    "kdf",
    "keys",
    "openssl_version",
    "openssl_version_text",
    "poly1305",
    "raise_openssl_error",
    "rsa",
    "x448",
    "x25519",
]

lib = _openssl.lib
ffi = _openssl.ffi

CRYPTOGRAPHY_IS_LIBRESSL = getattr(lib, "Cryptography_HAS_LIBRESSL", False)
CRYPTOGRAPHY_IS_BORINGSSL = getattr(lib, "Cryptography_HAS_BORINGSSL", False)
CRYPTOGRAPHY_IS_AWSLC = getattr(lib, "Cryptography_HAS_AWSLC", False)

openssl_version_num = lib.OpenSSL_version_num()
CRYPTOGRAPHY_OPENSSL_309_OR_GREATER = openssl_version_num >= 0x300090000
CRYPTOGRAPHY_OPENSSL_320_OR_GREATER = openssl_version_num >= 0x302000000
CRYPTOGRAPHY_OPENSSL_330_OR_GREATER = openssl_version_num >= 0x303000000
CRYPTOGRAPHY_OPENSSL_350_OR_GREATER = openssl_version_num >= 0x305000000


class Providers:
    pass


_legacy_provider_loaded = False
_providers = Providers()


def openssl_version() -> int:
    return int(lib.OpenSSL_version_num())


def openssl_version_text() -> str:
    return ffi.string(lib.OpenSSL_version(0)).decode("ascii")


def raise_openssl_error() -> typing.NoReturn:
    from cryptography.exceptions import InternalError

    errors = capture_error_stack()
    raise InternalError(
        "Unknown OpenSSL error. This error is commonly encountered when "
        "another library is not cleaning up the OpenSSL error stack. If "
        "you are using cryptography with another library that uses "
        "OpenSSL try disabling it before reporting a bug. Otherwise "
        "please file an issue at https://github.com/pyca/cryptography/"
        "issues with information on how to reproduce "
        f"this. ({errors!r})",
        errors,
    )


class OpenSSLError:
    def __init__(self, lib_code: int, reason_code: int, reason_text: bytes):
        self._lib = lib_code
        self._reason = reason_code
        self._reason_text = reason_text

    @property
    def lib(self) -> int:
        return self._lib

    @property
    def reason(self) -> int:
        return self._reason

    @property
    def reason_text(self) -> bytes:
        return self._reason_text


def capture_error_stack() -> list[OpenSSLError]:
    errors = []
    while True:
        error = lib.ERR_get_error()
        if error == 0:
            break
        lib_code = lib.ERR_GET_LIB(error)
        reason_code = lib.ERR_GET_REASON(error)
        reason_text_bytes = ffi.string(lib.ERR_reason_error_string(error))
        errors.append(OpenSSLError(lib_code, reason_code, reason_text_bytes))
    return errors


def is_fips_enabled() -> bool:
    if CRYPTOGRAPHY_OPENSSL_309_OR_GREATER:
        return bool(lib.EVP_default_properties_is_fips_enabled(ffi.NULL))
    else:
        return bool(lib.FIPS_mode())


def enable_fips(providers: Providers) -> None:
    if not CRYPTOGRAPHY_OPENSSL_309_OR_GREATER:
        lib.FIPS_mode_set(1)
    else:
        raise NotImplementedError("FIPS enablement requires OpenSSL 3.0+ provider setup")

