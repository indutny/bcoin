/**
 * bcrypto.cc - fast native bindings to crypto functions.
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License)
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <node.h>
#include <nan.h>

#include "common.h"
#include "compat.h"
#include "aead.h"
#include "aes.h"
#include "base58.h"
#include "bech32.h"
#include "blake2b.h"
#include "blake2s.h"
#ifdef BCRYPTO_HAS_GMP
#include "bn.h"
#endif
#include "cash32.h"
#include "chacha20.h"
#include "cipherbase.h"
#include "dsa.h"
#include "ecdsa.h"
#include "ed25519.h"
#include "ed448.h"
#include "hash160.h"
#include "hash256.h"
#include "keccak.h"
#include "md4.h"
#include "md5.h"
#include "murmur3.h"
#include "poly1305.h"
#include "pbkdf2.h"
#include "random.h"
#include "ripemd160.h"
#include "rsa.h"
#include "salsa20.h"
#include "scrypt.h"
#include "secp256k1.h"
#include "sha1.h"
#include "sha224.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"
#include "siphash.h"
#include "whirlpool.h"
#include "x25519.h"
#include "x448.h"

#include "bcrypto.h"

// For "cleanse"
#include "openssl/crypto.h"

NAN_METHOD(cleanse) {
  if (info.Length() < 1)
    return Nan::ThrowError("cleanse() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  OPENSSL_cleanse((void *)data, len);
}

NAN_MODULE_INIT(init) {
  Nan::Set(target, Nan::New("major").ToLocalChecked(),
           Nan::New<v8::Uint32>(NODE_MAJOR_VERSION));
  Nan::Set(target, Nan::New("minor").ToLocalChecked(),
           Nan::New<v8::Uint32>(NODE_MINOR_VERSION));
  Nan::Set(target, Nan::New("patch").ToLocalChecked(),
           Nan::New<v8::Uint32>(NODE_PATCH_VERSION));

  BAEAD::Init(target);
  BAES::Init(target);
  BBase58::Init(target);
  BBech32::Init(target);
  BBLAKE2b::Init(target);
  BBLAKE2s::Init(target);
#ifdef BCRYPTO_HAS_GMP
  BBN::Init(target);
#endif
  BCash32::Init(target);
  BChaCha20::Init(target);
  BCipherBase::Init(target);
  Nan::Export(target, "cleanse", cleanse);
#ifdef BCRYPTO_HAS_DSA
  BDSA::Init(target);
#endif
#ifdef BCRYPTO_HAS_ECDSA
  BECDSA::Init(target);
#endif
  BED25519::Init(target);
  BED448::Init(target);
  BHash160::Init(target);
  BHash256::Init(target);
  BKeccak::Init(target);
  BMD4::Init(target);
  BMD5::Init(target);
  BMurmur3::Init(target);
  BPoly1305::Init(target);
  BPBKDF2::Init(target);
  BRandom::Init(target);
  BRIPEMD160::Init(target);
#ifdef BCRYPTO_HAS_RSA
  BRSA::Init(target);
#endif
  BSalsa20::Init(target);
  BScrypt::Init(target);
  BSecp256k1::Init(target);
  BSHA1::Init(target);
  BSHA224::Init(target);
  BSHA256::Init(target);
  BSHA384::Init(target);
  BSHA512::Init(target);
  BSiphash::Init(target);
  BWhirlpool::Init(target);
  BX25519::Init(target);
  BX448::Init(target);
}

#if NODE_MAJOR_VERSION >= 10
NAN_MODULE_WORKER_ENABLED(bcrypto, init)
#else
NODE_MODULE(bcrypto, init)
#endif
