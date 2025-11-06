# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/evp.h>
"""

TYPES = """
typedef ... EVP_CIPHER;
typedef ... EVP_MD;
typedef ... EVP_MD_CTX;

typedef ... EVP_PKEY;
static const int EVP_PKEY_RSA;
static const int EVP_PKEY_DSA;
static const int EVP_PKEY_DH;
static const int EVP_PKEY_EC;
static const int EVP_MAX_MD_SIZE;

static const int Cryptography_HAS_EVP_PKEY_DHX;
"""

FUNCTIONS = """
const EVP_CIPHER *EVP_get_cipherbyname(const char *);

const EVP_MD *EVP_get_digestbyname(const char *);
int EVP_MD_size(const EVP_MD *);
const char *EVP_MD_name(const EVP_MD *);

EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *);
int EVP_MD_CTX_copy_ex(EVP_MD_CTX *, const EVP_MD_CTX *);
int EVP_DigestInit_ex(EVP_MD_CTX *, const EVP_MD *, void *);
int EVP_DigestUpdate(EVP_MD_CTX *, const void *, size_t);
int EVP_DigestFinal_ex(EVP_MD_CTX *, unsigned char *, unsigned int *);
int EVP_DigestFinalXOF(EVP_MD_CTX *, unsigned char *, size_t);

EVP_PKEY *EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *);
int EVP_PKEY_type(int);
RSA *EVP_PKEY_get1_RSA(EVP_PKEY *);

int EVP_PKEY_set1_DSA(EVP_PKEY *, DSA *);

int EVP_PKEY_id(const EVP_PKEY *);

int EVP_PKEY_bits(const EVP_PKEY *);

int EVP_PKEY_assign_RSA(EVP_PKEY *, RSA *);
"""

CUSTOMIZATIONS = """
#ifdef EVP_PKEY_DHX
const long Cryptography_HAS_EVP_PKEY_DHX = 1;
#else
const long Cryptography_HAS_EVP_PKEY_DHX = 0;
#endif
"""
