# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import typing

from cryptography.hazmat.bindings._rust import _openssl
from cryptography.hazmat.primitives import hashes
from cryptography.utils import Buffer

lib = _openssl.lib
ffi = _openssl.ffi


def _get_openssl_digest_name(algorithm: hashes.HashAlgorithm) -> str:
    name = algorithm.name
    if name in ("blake2b", "blake2s"):
        digest_size = algorithm.digest_size
        return f"{name}{digest_size * 8}"
    return name


def hash_supported(algorithm: hashes.HashAlgorithm) -> bool:
    try:
        name = _get_openssl_digest_name(algorithm)
        md = lib.EVP_get_digestbyname(name.encode("ascii"))
        return md != ffi.NULL
    except Exception:
        return False


class Hash(hashes.HashContext):
    def __init__(
        self, algorithm: hashes.HashAlgorithm, backend: typing.Any = None
    ) -> None:
        self._algorithm = algorithm
        self._ctx = None
        self._finalized = False

        name = _get_openssl_digest_name(algorithm)
        md = lib.EVP_get_digestbyname(name.encode("ascii"))
        if md == ffi.NULL:
            from cryptography.exceptions import UnsupportedAlgorithm

            raise UnsupportedAlgorithm(
                f"{algorithm.name} is not a supported hash on this backend",
                _Reasons.UNSUPPORTED_HASH,
            )

        self._md = md
        self._ctx = lib.EVP_MD_CTX_new()
        if self._ctx == ffi.NULL:
            from cryptography.exceptions import InternalError

            raise InternalError("EVP_MD_CTX_new failed")

        res = lib.EVP_DigestInit_ex(self._ctx, self._md, ffi.NULL)
        if res != 1:
            lib.EVP_MD_CTX_free(self._ctx)
            self._ctx = None
            from cryptography.exceptions import InternalError

            raise InternalError("EVP_DigestInit_ex failed")

    @property
    def algorithm(self) -> hashes.HashAlgorithm:
        return self._algorithm

    def update(self, data: Buffer) -> None:
        if self._finalized or self._ctx is None:
            from cryptography.exceptions import AlreadyFinalized

            raise AlreadyFinalized("Context was already finalized.")

        if isinstance(data, bytes):
            data_bytes = data
        else:
            data_bytes = bytes(data)

        res = lib.EVP_DigestUpdate(self._ctx, data_bytes, len(data_bytes))
        if res != 1:
            from cryptography.exceptions import InternalError

            raise InternalError("EVP_DigestUpdate failed")

    def finalize(self) -> bytes:
        if self._finalized or self._ctx is None:
            from cryptography.exceptions import AlreadyFinalized

            raise AlreadyFinalized("Context was already finalized.")

        digest_size = lib.EVP_MD_size(self._md)
        digest_buf = ffi.new("unsigned char[]", digest_size)
        outlen = ffi.new("unsigned int *")

        if isinstance(self._algorithm, hashes.ExtendableOutputFunction):
            res = lib.EVP_DigestFinalXOF(self._ctx, digest_buf, digest_size)
        else:
            res = lib.EVP_DigestFinal_ex(self._ctx, digest_buf, outlen)

        if res != 1:
            lib.EVP_MD_CTX_free(self._ctx)
            self._ctx = None
            self._finalized = True
            from cryptography.exceptions import InternalError

            raise InternalError("EVP_DigestFinal_ex failed")

        digest = bytes(ffi.buffer(digest_buf, digest_size))
        lib.EVP_MD_CTX_free(self._ctx)
        self._ctx = None
        self._finalized = True
        return digest

    def copy(self) -> Hash:
        if self._finalized or self._ctx is None:
            from cryptography.exceptions import AlreadyFinalized

            raise AlreadyFinalized("Context was already finalized.")

        new_hash = Hash.__new__(Hash)
        new_hash._algorithm = self._algorithm
        new_hash._md = self._md
        new_hash._finalized = False

        new_hash._ctx = lib.EVP_MD_CTX_new()
        if new_hash._ctx == ffi.NULL:
            from cryptography.exceptions import InternalError

            raise InternalError("EVP_MD_CTX_new failed")

        res = lib.EVP_MD_CTX_copy_ex(new_hash._ctx, self._ctx)
        if res != 1:
            lib.EVP_MD_CTX_free(new_hash._ctx)
            new_hash._ctx = None
            from cryptography.exceptions import InternalError

            raise InternalError("EVP_MD_CTX_copy_ex failed")

        return new_hash


class XOFHash:
    def __init__(self, algorithm: hashes.ExtendableOutputFunction) -> None:
        self._algorithm = algorithm
        self._ctx = None
        self._finalized = False

        name = algorithm.name
        md = lib.EVP_get_digestbyname(name.encode("ascii"))
        if md == ffi.NULL:
            from cryptography.exceptions import UnsupportedAlgorithm

            raise UnsupportedAlgorithm(
                f"{algorithm.name} is not a supported hash on this backend",
                _Reasons.UNSUPPORTED_HASH,
            )

        self._md = md
        self._ctx = lib.EVP_MD_CTX_new()
        if self._ctx == ffi.NULL:
            from cryptography.exceptions import InternalError

            raise InternalError("EVP_MD_CTX_new failed")

        res = lib.EVP_DigestInit_ex(self._ctx, self._md, ffi.NULL)
        if res != 1:
            lib.EVP_MD_CTX_free(self._ctx)
            self._ctx = None
            from cryptography.exceptions import InternalError

            raise InternalError("EVP_DigestInit_ex failed")

    @property
    def algorithm(self) -> hashes.ExtendableOutputFunction:
        return self._algorithm

    def update(self, data: Buffer) -> None:
        if self._finalized or self._ctx is None:
            from cryptography.exceptions import AlreadyFinalized

            raise AlreadyFinalized("Context was already finalized.")

        if isinstance(data, bytes):
            data_bytes = data
        else:
            data_bytes = bytes(data)

        res = lib.EVP_DigestUpdate(self._ctx, data_bytes, len(data_bytes))
        if res != 1:
            from cryptography.exceptions import InternalError

            raise InternalError("EVP_DigestUpdate failed")

    def squeeze(self, length: int) -> bytes:
        if self._finalized or self._ctx is None:
            from cryptography.exceptions import AlreadyFinalized

            raise AlreadyFinalized("Context was already finalized.")

        digest_buf = ffi.new("unsigned char[]", length)
        res = lib.EVP_DigestFinalXOF(self._ctx, digest_buf, length)
        if res != 1:
            lib.EVP_MD_CTX_free(self._ctx)
            self._ctx = None
            self._finalized = True
            from cryptography.exceptions import InternalError

            raise InternalError("EVP_DigestFinalXOF failed")

        digest = bytes(ffi.buffer(digest_buf, length))
        lib.EVP_MD_CTX_free(self._ctx)
        self._ctx = None
        self._finalized = True
        return digest

    def copy(self) -> XOFHash:
        if self._finalized or self._ctx is None:
            from cryptography.exceptions import AlreadyFinalized

            raise AlreadyFinalized("Context was already finalized.")

        new_hash = XOFHash.__new__(XOFHash)
        new_hash._algorithm = self._algorithm
        new_hash._md = self._md
        new_hash._finalized = False

        new_hash._ctx = lib.EVP_MD_CTX_new()
        if new_hash._ctx == ffi.NULL:
            from cryptography.exceptions import InternalError

            raise InternalError("EVP_MD_CTX_new failed")

        res = lib.EVP_MD_CTX_copy_ex(new_hash._ctx, self._ctx)
        if res != 1:
            lib.EVP_MD_CTX_free(new_hash._ctx)
            new_hash._ctx = None
            from cryptography.exceptions import InternalError

            raise InternalError("EVP_MD_CTX_copy_ex failed")

        return new_hash


class _Reasons:
    UNSUPPORTED_HASH = "UNSUPPORTED_HASH"

