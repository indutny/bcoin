#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "ed448/ed448.h"
#include "ed448.h"
#include "openssl/crypto.h"

void
BED448::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "privateKeyExpand", BED448::PrivateKeyExpand);
  Nan::Export(obj, "privateKeyConvert", BED448::PrivateKeyConvert);
  Nan::Export(obj, "scalarIsZero", BED448::ScalarIsZero);
  Nan::Export(obj, "scalarTweakAdd", BED448::ScalarTweakAdd);
  Nan::Export(obj, "scalarTweakMul", BED448::ScalarTweakMul);
  Nan::Export(obj, "scalarReduce", BED448::ScalarReduce);
  Nan::Export(obj, "scalarNegate", BED448::ScalarNegate);
  Nan::Export(obj, "scalarInvert", BED448::ScalarInvert);
  Nan::Export(obj, "publicKeyCreate", BED448::PublicKeyCreate);
  Nan::Export(obj, "publicKeyFromScalar", BED448::PublicKeyFromScalar);
  Nan::Export(obj, "publicKeyConvert", BED448::PublicKeyConvert);
  Nan::Export(obj, "publicKeyFromUniform", BED448::PublicKeyFromUniform);
  Nan::Export(obj, "publicKeyToUniform", BED448::PublicKeyToUniform);
  Nan::Export(obj, "publicKeyFromHash", BED448::PublicKeyFromHash);
  Nan::Export(obj, "publicKeyToHash", BED448::PublicKeyToHash);
  Nan::Export(obj, "publicKeyVerify", BED448::PublicKeyVerify);
  Nan::Export(obj, "publicKeyIsInfinity", BED448::PublicKeyIsInfinity);
  Nan::Export(obj, "publicKeyIsSmall", BED448::PublicKeyIsSmall);
  Nan::Export(obj, "publicKeyHasTorsion", BED448::PublicKeyHasTorsion);
  Nan::Export(obj, "publicKeyTweakAdd", BED448::PublicKeyTweakAdd);
  Nan::Export(obj, "publicKeyTweakMul", BED448::PublicKeyTweakMul);
  Nan::Export(obj, "publicKeyAdd", BED448::PublicKeyAdd);
  Nan::Export(obj, "publicKeyCombine", BED448::PublicKeyCombine);
  Nan::Export(obj, "publicKeyNegate", BED448::PublicKeyNegate);
  Nan::Export(obj, "sign", BED448::Sign);
  Nan::Export(obj, "signWithScalar", BED448::SignWithScalar);
  Nan::Export(obj, "signTweakAdd", BED448::SignTweakAdd);
  Nan::Export(obj, "signTweakMul", BED448::SignTweakMul);
  Nan::Export(obj, "verify", BED448::Verify);
  Nan::Export(obj, "verifySingle", BED448::VerifySingle);
  Nan::Export(obj, "derive", BED448::Derive);
  Nan::Export(obj, "deriveWithScalar", BED448::DeriveWithScalar);

  Nan::Set(target, Nan::New("ed448").ToLocalChecked(), obj);
}

NAN_METHOD(BED448::PrivateKeyExpand) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.privateKeyExpand() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *secret = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t secret_len = node::Buffer::Length(pbuf);

  if (secret_len != BCRYPTO_EDDSA_448_PRIVATE_BYTES)
    return Nan::ThrowRangeError("Invalid secret size.");

  uint8_t out[BCRYPTO_EDDSA_448_PRIVATE_BYTES * 2];

  if (!bcrypto_c448_ed448_expand_private_key(out, secret))
    return Nan::ThrowError("Could not expand.");

  uint8_t *key = &out[0];
  size_t key_len = BCRYPTO_X448_PRIVATE_BYTES;

  uint8_t *pre = &out[BCRYPTO_EDDSA_448_PRIVATE_BYTES];
  size_t pre_len = BCRYPTO_EDDSA_448_PRIVATE_BYTES;

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)key, key_len).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)pre, pre_len).ToLocalChecked());

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BED448::PrivateKeyConvert) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.privateKeyConvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *secret = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t secret_len = node::Buffer::Length(pbuf);

  if (secret_len != BCRYPTO_EDDSA_448_PRIVATE_BYTES)
    return Nan::ThrowRangeError("Invalid secret size.");

  uint8_t out[BCRYPTO_X448_PRIVATE_BYTES];

  if (!bcrypto_c448_ed448_convert_private_key_to_x448(out, secret))
    return Nan::ThrowError("Could not convert.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
                    BCRYPTO_X448_PRIVATE_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::ScalarIsZero) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.scalarIsZero() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t key_len = node::Buffer::Length(kbuf);

  if (key_len != BCRYPTO_C448_SCALAR_BYTES)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = (bool)bcrypto_c448_ed448_scalar_is_zero(key);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BED448::ScalarTweakAdd) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed448.scalarTweakAdd() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t key_len = node::Buffer::Length(kbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (key_len != BCRYPTO_C448_SCALAR_BYTES)
    return Nan::ThrowRangeError("Invalid scalar size.");

  if (tweak_len != BCRYPTO_C448_SCALAR_BYTES)
    return Nan::ThrowRangeError("Invalid tweak size.");

  uint8_t out[BCRYPTO_C448_SCALAR_BYTES];

  if (!bcrypto_c448_ed448_scalar_tweak_add(out, key, tweak))
    return Nan::ThrowError("Invalid scalar.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
      BCRYPTO_C448_SCALAR_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::ScalarTweakMul) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed448.scalarTweakMul() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t key_len = node::Buffer::Length(kbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (key_len != BCRYPTO_C448_SCALAR_BYTES)
    return Nan::ThrowRangeError("Invalid scalar size.");

  if (tweak_len != BCRYPTO_C448_SCALAR_BYTES)
    return Nan::ThrowRangeError("Invalid tweak size.");

  uint8_t out[BCRYPTO_C448_SCALAR_BYTES];

  if (!bcrypto_c448_ed448_scalar_tweak_mul(out, key, tweak))
    return Nan::ThrowError("Invalid scalar.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
      BCRYPTO_C448_SCALAR_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::ScalarReduce) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.scalarReduce() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t key_len = node::Buffer::Length(kbuf);

  if (key_len > BCRYPTO_C448_SCALAR_BYTES)
    key_len = BCRYPTO_C448_SCALAR_BYTES;

  uint8_t in[BCRYPTO_C448_SCALAR_BYTES];

  memset(&in[0], 0x00, BCRYPTO_C448_SCALAR_BYTES);
  memcpy(&in[0], key, key_len);

  uint8_t out[BCRYPTO_C448_SCALAR_BYTES];

  if (!bcrypto_c448_ed448_scalar_reduce(out, in))
    return Nan::ThrowError("Invalid scalar.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
      BCRYPTO_C448_SCALAR_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::ScalarNegate) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.scalarNegate() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t key_len = node::Buffer::Length(kbuf);

  if (key_len != BCRYPTO_C448_SCALAR_BYTES)
    return Nan::ThrowRangeError("Invalid scalar size.");

  uint8_t out[BCRYPTO_C448_SCALAR_BYTES];

  if (!bcrypto_c448_ed448_scalar_negate(out, key))
    return Nan::ThrowError("Invalid scalar.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
      BCRYPTO_C448_SCALAR_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::ScalarInvert) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.scalarInvert() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t key_len = node::Buffer::Length(kbuf);

  if (key_len != BCRYPTO_C448_SCALAR_BYTES)
    return Nan::ThrowRangeError("Invalid scalar size.");

  uint8_t out[BCRYPTO_C448_SCALAR_BYTES];

  if (!bcrypto_c448_ed448_scalar_invert(out, key))
    return Nan::ThrowError("Invalid scalar.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
      BCRYPTO_C448_SCALAR_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::PublicKeyCreate) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.publicKeyCreate() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *secret = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t secret_len = node::Buffer::Length(sbuf);

  if (secret_len != BCRYPTO_EDDSA_448_PRIVATE_BYTES)
    return Nan::ThrowRangeError("Invalid secret size.");

  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_c448_ed448_derive_public_key(out, secret))
    return Nan::ThrowError("Could not create public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
                    BCRYPTO_EDDSA_448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::PublicKeyFromScalar) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.publicKeyFromScalar() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t scalar_len = node::Buffer::Length(sbuf);

  if (scalar_len != BCRYPTO_C448_SCALAR_BYTES)
    return Nan::ThrowRangeError("Invalid scalar size.");

  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_c448_ed448_derive_public_key_with_scalar(out, scalar))
    return Nan::ThrowError("Could not create public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
                    BCRYPTO_EDDSA_448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::PublicKeyConvert) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.publicKeyConvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  uint8_t out[BCRYPTO_X448_PUBLIC_BYTES];

  if (!bcrypto_curve448_convert_public_key_to_x448(out, pub))
    return Nan::ThrowError("Could not convert public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], BCRYPTO_X448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::PublicKeyFromUniform) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.publicKeyFromUniform() requires arguments.");

  v8::Local<v8::Object> dbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(dbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(dbuf);
  size_t data_len = node::Buffer::Length(dbuf);

  if (data_len != 56)
    return Nan::ThrowRangeError("Invalid field element size.");

  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  bcrypto_curve448_public_key_from_uniform(out, data);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], BCRYPTO_EDDSA_448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::PublicKeyToUniform) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed448.publicKeyToUniform() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  unsigned int hint = (unsigned int)Nan::To<uint32_t>(info[1]).FromJust();

  uint8_t out[56];

  if (!bcrypto_curve448_public_key_to_uniform(out, pub, hint))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 56).ToLocalChecked());
}

NAN_METHOD(BED448::PublicKeyFromHash) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed448.publicKeyFromHash() requires arguments.");

  v8::Local<v8::Object> dbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(dbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsBoolean())
    return Nan::ThrowTypeError("Second argument must be a boolean.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(dbuf);
  size_t data_len = node::Buffer::Length(dbuf);

  if (data_len != 112)
    return Nan::ThrowRangeError("Invalid hash size.");

  int pake = (int)Nan::To<bool>(info[1]).FromJust();

  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  bcrypto_curve448_public_key_from_hash(out, data, pake);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], BCRYPTO_EDDSA_448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::PublicKeyToHash) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.publicKeyToHash() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  uint8_t out[112];

  if (!bcrypto_curve448_public_key_to_hash(out, pub))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 112).ToLocalChecked());
}

NAN_METHOD(BED448::PublicKeyVerify) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bcrypto_curve448_point_t p;

  if (!bcrypto_curve448_point_decode_like_eddsa_and_mul_by_ratio(p, pub))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = (bool)bcrypto_curve448_point_valid(p);

  bcrypto_curve448_point_destroy(p);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BED448::PublicKeyIsInfinity) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.publicKeyIsInfinity() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = (bool)bcrypto_curve448_public_key_is_infinity(pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BED448::PublicKeyIsSmall) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.publicKeyIsSmall() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = (bool)bcrypto_curve448_public_key_is_small(pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BED448::PublicKeyHasTorsion) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.publicKeyHasTorsion() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = (bool)bcrypto_curve448_public_key_has_torsion(pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BED448::PublicKeyTweakAdd) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed448.publicKeyTweakAdd() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (tweak_len != BCRYPTO_C448_SCALAR_BYTES)
    return Nan::ThrowRangeError("Invalid tweak size.");

  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_c448_ed448_public_key_tweak_add(out, pub, tweak))
    return Nan::ThrowError("Could not create public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
                    BCRYPTO_EDDSA_448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::PublicKeyTweakMul) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed448.publicKeyTweakMul() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  if (pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (tweak_len != BCRYPTO_C448_SCALAR_BYTES)
    return Nan::ThrowRangeError("Invalid tweak size.");

  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_c448_ed448_public_key_tweak_mul(out, pub, tweak))
    return Nan::ThrowError("Could not create public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
                    BCRYPTO_EDDSA_448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::PublicKeyAdd) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed448.publicKeyAdd() requires arguments.");

  v8::Local<v8::Object> p1buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> p2buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(p1buf)
      || !node::Buffer::HasInstance(p2buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub1 = (const uint8_t *)node::Buffer::Data(p1buf);
  size_t pub1_len = node::Buffer::Length(p1buf);

  const uint8_t *pub2 = (const uint8_t *)node::Buffer::Data(p2buf);
  size_t pub2_len = node::Buffer::Length(p2buf);

  if (pub1_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (pub2_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_c448_ed448_public_key_add(out, pub1, pub2))
    return Nan::ThrowError("Could not create public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
                    BCRYPTO_EDDSA_448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::PublicKeyCombine) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.publicKeyCombine() requires arguments.");

  if (!info[0]->IsArray())
    return Nan::ThrowTypeError("First argument must be an array.");

  v8::Local<v8::Array> batch = info[0].As<v8::Array>();

  size_t len = (size_t)batch->Length();

  bcrypto_c448_ed448_public_key *pubs =
    (bcrypto_c448_ed448_public_key *)malloc(len * sizeof(bcrypto_c448_ed448_public_key));

  if (pubs == NULL && len != 0)
    return Nan::ThrowError("Allocation failed.");

  for (size_t i = 0; i < len; i++) {
    v8::Local<v8::Object> pbuf = Nan::Get(batch, i).ToLocalChecked()
                                                   .As<v8::Object>();

    if (!node::Buffer::HasInstance(pbuf)) {
      free(pubs);
      return Nan::ThrowTypeError("Public key must be a buffer.");
    }

    const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
    size_t pub_len = node::Buffer::Length(pbuf);

    if (pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES) {
      free(pubs);
      return Nan::ThrowError("Invalid point.");
    }

    memcpy(pubs[i], pub, pub_len);
  }

  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_c448_ed448_public_key_combine(out, pubs, len)) {
    free(pubs);
    return Nan::ThrowError("Invalid point.");
  }

  free(pubs);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
                    BCRYPTO_EDDSA_448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::PublicKeyNegate) {
  if (info.Length() < 1)
    return Nan::ThrowError("ed448.publicKeyNegate() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_c448_ed448_public_key_negate(out, pub))
    return Nan::ThrowError("Could not create public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
                    BCRYPTO_EDDSA_448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::Sign) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed448.sign() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *secret = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t secret_len = node::Buffer::Length(sbuf);

  uint8_t ph = 0;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    ph = (uint8_t)Nan::To<bool>(info[2]).FromJust();
  }

  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    v8::Local<v8::Object> cbuf = info[3].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (secret_len != BCRYPTO_EDDSA_448_PRIVATE_BYTES)
    return Nan::ThrowRangeError("Invalid secret size.");

  uint8_t pub[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_c448_ed448_derive_public_key(pub, secret))
    return Nan::ThrowError("Could not create public key.");

  uint8_t sig[BCRYPTO_EDDSA_448_SIGNATURE_BYTES];

  if (!bcrypto_c448_ed448_sign(sig, secret, pub,
                               msg, msg_len,
                               ph, ctx, ctx_len)) {
    return Nan::ThrowError("Could not sign.");
  }

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&sig[0],
                    BCRYPTO_EDDSA_448_SIGNATURE_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::SignWithScalar) {
  if (info.Length() < 3)
    return Nan::ThrowError("ed448.signWithScalar() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t scalar_len = node::Buffer::Length(sbuf);

  const uint8_t *prefix = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t prefix_len = node::Buffer::Length(pbuf);

  uint8_t ph = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    ph = (uint8_t)Nan::To<bool>(info[3]).FromJust();
  }

  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fifth argument must be a buffer.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (scalar_len != BCRYPTO_C448_SCALAR_BYTES)
    return Nan::ThrowRangeError("Invalid scalar size.");

  if (prefix_len != BCRYPTO_EDDSA_448_PRIVATE_BYTES)
    return Nan::ThrowRangeError("Invalid prefix size.");

  uint8_t pub[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_c448_ed448_derive_public_key_with_scalar(pub, scalar))
    return Nan::ThrowError("Could not create public key.");

  uint8_t expanded[BCRYPTO_EDDSA_448_PRIVATE_BYTES * 2];

  memcpy(&expanded[0], &scalar[0], scalar_len);
  expanded[scalar_len] = 0;
  memcpy(&expanded[prefix_len], &prefix[0], prefix_len);

  uint8_t sig[BCRYPTO_EDDSA_448_SIGNATURE_BYTES];

  if (!bcrypto_c448_ed448_sign_with_scalar(sig, expanded, pub,
                                           msg, msg_len,
                                           ph, ctx, ctx_len)) {
    OPENSSL_cleanse(expanded, sizeof(expanded));
    return Nan::ThrowError("Could not sign.");
  }

  OPENSSL_cleanse(expanded, sizeof(expanded));

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&sig[0],
                    BCRYPTO_EDDSA_448_SIGNATURE_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::SignTweakAdd) {
  if (info.Length() < 3)
    return Nan::ThrowError("ed448.signTweakAdd() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *secret = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t secret_len = node::Buffer::Length(sbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  uint8_t ph = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    ph = (uint8_t)Nan::To<bool>(info[3]).FromJust();
  }

  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fifth argument must be a buffer.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (secret_len != BCRYPTO_EDDSA_448_PRIVATE_BYTES)
    return Nan::ThrowRangeError("Invalid secret size.");

  if (tweak_len != BCRYPTO_C448_SCALAR_BYTES)
    return Nan::ThrowRangeError("Invalid tweak size.");

  uint8_t pub[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_c448_ed448_derive_public_key(pub, secret))
    return Nan::ThrowError("Could not create public key.");

  uint8_t sig[BCRYPTO_EDDSA_448_SIGNATURE_BYTES];

  if (!bcrypto_c448_ed448_sign_tweak_add(sig, secret, pub,
                                         tweak, msg, msg_len,
                                         ph, ctx, ctx_len)) {
    return Nan::ThrowError("Could not sign.");
  }

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&sig[0],
                    BCRYPTO_EDDSA_448_SIGNATURE_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::SignTweakMul) {
  if (info.Length() < 3)
    return Nan::ThrowError("ed448.signTweakMul() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *secret = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t secret_len = node::Buffer::Length(sbuf);

  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);

  uint8_t ph = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    ph = (uint8_t)Nan::To<bool>(info[3]).FromJust();
  }

  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fifth argument must be a buffer.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (secret_len != BCRYPTO_EDDSA_448_PRIVATE_BYTES)
    return Nan::ThrowRangeError("Invalid secret size.");

  if (tweak_len != BCRYPTO_C448_SCALAR_BYTES)
    return Nan::ThrowRangeError("Invalid tweak size.");

  uint8_t pub[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_c448_ed448_derive_public_key(pub, secret))
    return Nan::ThrowError("Could not create public key.");

  uint8_t sig[BCRYPTO_EDDSA_448_SIGNATURE_BYTES];

  if (!bcrypto_c448_ed448_sign_tweak_mul(sig, secret, pub,
                                         tweak, msg, msg_len,
                                         ph, ctx, ctx_len)) {
    return Nan::ThrowError("Could not sign.");
  }

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&sig[0],
                    BCRYPTO_EDDSA_448_SIGNATURE_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::Verify) {
  if (info.Length() < 3)
    return Nan::ThrowError("ed448.verify() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  uint8_t ph = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    ph = (uint8_t)Nan::To<bool>(info[3]).FromJust();
  }

  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fifth argument must be a buffer.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
  }

  if (sig_len != BCRYPTO_EDDSA_448_SIGNATURE_BYTES
      || pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES) {
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
  }

  bool result = (bool)bcrypto_c448_ed448_verify(sig, pub,
                                                msg, msg_len,
                                                ph, ctx, ctx_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BED448::VerifySingle) {
  if (info.Length() < 3)
    return Nan::ThrowError("ed448.verifySingle() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  uint8_t ph = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    ph = (uint8_t)Nan::To<bool>(info[3]).FromJust();
  }

  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fifth argument must be a buffer.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
  }

  if (sig_len != BCRYPTO_EDDSA_448_SIGNATURE_BYTES
      || pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES) {
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
  }

  bool result = (bool)bcrypto_c448_ed448_verify_single(sig, pub,
                                                       msg, msg_len,
                                                       ph, ctx, ctx_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BED448::Derive) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed448.derive() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  const uint8_t *secret = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t secret_len = node::Buffer::Length(sbuf);

  if (pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (secret_len != BCRYPTO_EDDSA_448_PRIVATE_BYTES)
    return Nan::ThrowRangeError("Invalid secret size.");

  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_c448_ed448_derive(out, pub, secret))
    return Nan::ThrowError("Could not derive secret.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
                    BCRYPTO_EDDSA_448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BED448::DeriveWithScalar) {
  if (info.Length() < 2)
    return Nan::ThrowError("ed448.deriveWithScalar() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t scalar_len = node::Buffer::Length(sbuf);

  if (pub_len != BCRYPTO_EDDSA_448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (scalar_len != BCRYPTO_C448_SCALAR_BYTES)
    return Nan::ThrowRangeError("Invalid scalar size.");

  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_c448_ed448_derive_with_scalar(out, pub, scalar))
    return Nan::ThrowError("Could not derive secret.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
                    BCRYPTO_EDDSA_448_PUBLIC_BYTES).ToLocalChecked());
}
