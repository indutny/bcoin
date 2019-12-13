#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "ed448/ed448.h"
#include "x448.h"
#include "openssl/crypto.h"

void
BX448::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "publicKeyCreate", BX448::PublicKeyCreate);
  Nan::Export(obj, "publicKeyConvert", BX448::PublicKeyConvert);
  Nan::Export(obj, "publicKeyFromUniform", BX448::PublicKeyFromUniform);
  Nan::Export(obj, "publicKeyToUniform", BX448::PublicKeyToUniform);
  Nan::Export(obj, "publicKeyFromHash", BX448::PublicKeyFromHash);
  Nan::Export(obj, "publicKeyToHash", BX448::PublicKeyToHash);
  Nan::Export(obj, "publicKeyVerify", BX448::PublicKeyVerify);
  Nan::Export(obj, "publicKeyIsSmall", BX448::PublicKeyIsSmall);
  Nan::Export(obj, "publicKeyHasTorsion", BX448::PublicKeyHasTorsion);
  Nan::Export(obj, "derive", BX448::Derive);

  Nan::Set(target, Nan::New("x448").ToLocalChecked(), obj);
}

NAN_METHOD(BX448::PublicKeyCreate) {
  if (info.Length() < 1)
    return Nan::ThrowError("x448.publicKeyCreate() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t key_len = node::Buffer::Length(kbuf);

  if (key_len != BCRYPTO_X448_PRIVATE_BYTES)
    return Nan::ThrowRangeError("Invalid private key size.");

  uint8_t out[BCRYPTO_X448_PUBLIC_BYTES];

  bcrypto_x448_derive_public_key(out, key);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
                    BCRYPTO_X448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BX448::PublicKeyConvert) {
  if (info.Length() < 2)
    return Nan::ThrowError("x448.publicKeyConvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsBoolean())
    return Nan::ThrowTypeError("Second argument must be a boolean.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_X448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  int sign = (int)Nan::To<bool>(info[1]).FromJust();

  uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES];

  if (!bcrypto_x448_convert_public_key_to_eddsa(out, pub, sign))
    return Nan::ThrowError("Could not convert public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
                    BCRYPTO_EDDSA_448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BX448::PublicKeyFromUniform) {
  if (info.Length() < 1)
    return Nan::ThrowError("x448.publicKeyFromUniform() requires arguments.");

  v8::Local<v8::Object> dbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(dbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(dbuf);
  size_t data_len = node::Buffer::Length(dbuf);

  if (data_len != 56)
    return Nan::ThrowRangeError("Invalid field element size.");

  uint8_t out[BCRYPTO_X448_PUBLIC_BYTES];

  bcrypto_x448_public_key_from_uniform(out, data);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], BCRYPTO_X448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BX448::PublicKeyToUniform) {
  if (info.Length() < 2)
    return Nan::ThrowError("x448.publicKeyToUniform() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_X448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  unsigned int hint = (unsigned int)Nan::To<uint32_t>(info[1]).FromJust();

  uint8_t out[56];

  if (!bcrypto_x448_public_key_to_uniform(out, pub, hint))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 56).ToLocalChecked());
}

NAN_METHOD(BX448::PublicKeyFromHash) {
  if (info.Length() < 2)
    return Nan::ThrowError("x448.publicKeyFromHash() requires arguments.");

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

  uint8_t out[BCRYPTO_X448_PUBLIC_BYTES];

  if (!bcrypto_x448_public_key_from_hash(out, data, pake))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], BCRYPTO_X448_PUBLIC_BYTES).ToLocalChecked());
}

NAN_METHOD(BX448::PublicKeyToHash) {
  if (info.Length() < 1)
    return Nan::ThrowError("x448.publicKeyToHash() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_X448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  uint8_t out[112];

  if (!bcrypto_x448_public_key_to_hash(out, pub))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 112).ToLocalChecked());
}

NAN_METHOD(BX448::PublicKeyVerify) {
  if (info.Length() < 1)
    return Nan::ThrowError("x448.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_X448_PUBLIC_BYTES)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = (bool)bcrypto_x448_verify_public_key(pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BX448::PublicKeyIsSmall) {
  if (info.Length() < 1)
    return Nan::ThrowError("x448.publicKeyIsSmall() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_X448_PUBLIC_BYTES)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = (bool)bcrypto_x448_public_key_is_small(pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BX448::PublicKeyHasTorsion) {
  if (info.Length() < 1)
    return Nan::ThrowError("x448.publicKeyHasTorsion() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != BCRYPTO_X448_PUBLIC_BYTES)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = (bool)bcrypto_x448_public_key_has_torsion(pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BX448::Derive) {
  if (info.Length() < 2)
    return Nan::ThrowError("x448.derive() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t priv_len = node::Buffer::Length(sbuf);

  if (pub_len != BCRYPTO_X448_PUBLIC_BYTES)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (priv_len != BCRYPTO_X448_PRIVATE_BYTES)
    return Nan::ThrowRangeError("Invalid private key size.");

  uint8_t out[BCRYPTO_X448_PUBLIC_BYTES];

  if (!bcrypto_x448_int(out, pub, priv))
    return Nan::ThrowError("Could not derive secret.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0],
                    BCRYPTO_X448_PUBLIC_BYTES).ToLocalChecked());
}
