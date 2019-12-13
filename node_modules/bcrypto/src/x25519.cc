#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "ed25519/ed25519.h"
#include "x25519.h"
#include "openssl/crypto.h"

void
BX25519::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "publicKeyCreate", BX25519::PublicKeyCreate);
  Nan::Export(obj, "publicKeyConvert", BX25519::PublicKeyConvert);
  Nan::Export(obj, "publicKeyFromUniform", BX25519::PublicKeyFromUniform);
  Nan::Export(obj, "publicKeyToUniform", BX25519::PublicKeyToUniform);
  Nan::Export(obj, "publicKeyFromHash", BX25519::PublicKeyFromHash);
  Nan::Export(obj, "publicKeyToHash", BX25519::PublicKeyToHash);
  Nan::Export(obj, "publicKeyVerify", BX25519::PublicKeyVerify);
  Nan::Export(obj, "publicKeyIsSmall", BX25519::PublicKeyIsSmall);
  Nan::Export(obj, "publicKeyHasTorsion", BX25519::PublicKeyHasTorsion);
  Nan::Export(obj, "derive", BX25519::Derive);

  Nan::Set(target, Nan::New("x25519").ToLocalChecked(), obj);
}

NAN_METHOD(BX25519::PublicKeyCreate) {
  if (info.Length() < 1)
    return Nan::ThrowError("x25519.publicKeyCreate() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t key_len = node::Buffer::Length(kbuf);

  if (key_len != 32)
    return Nan::ThrowRangeError("Invalid private key size.");

  bcrypto_x25519_pubkey_t out;

  if (!bcrypto_x25519_pubkey_create(out, key))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BX25519::PublicKeyConvert) {
  if (info.Length() < 2)
    return Nan::ThrowError("x25519.publicKeyConvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsBoolean())
    return Nan::ThrowTypeError("Second argument must be a boolean.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != 32)
    return Nan::ThrowRangeError("Invalid public key size.");

  int sign = (int)Nan::To<bool>(info[1]).FromJust();

  bcrypto_ed25519_pubkey_t out;

  if (!bcrypto_x25519_pubkey_convert(out, pub, sign))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BX25519::PublicKeyFromUniform) {
  if (info.Length() < 1)
    return Nan::ThrowError("x25519.publicKeyFromUniform() requires arguments.");

  v8::Local<v8::Object> dbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(dbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(dbuf);
  size_t data_len = node::Buffer::Length(dbuf);

  if (data_len != 32)
    return Nan::ThrowRangeError("Invalid field element size.");

  bcrypto_x25519_pubkey_t out;
  bcrypto_x25519_pubkey_from_uniform(out, data);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BX25519::PublicKeyToUniform) {
  if (info.Length() < 2)
    return Nan::ThrowError("x25519.publicKeyToUniform() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != 32)
    return Nan::ThrowRangeError("Invalid public key size.");

  unsigned int hint = (unsigned int)Nan::To<uint32_t>(info[1]).FromJust();

  uint8_t out[32];

  if (!bcrypto_x25519_pubkey_to_uniform(out, pub, hint))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BX25519::PublicKeyFromHash) {
  if (info.Length() < 2)
    return Nan::ThrowError("x25519.publicKeyFromHash() requires arguments.");

  v8::Local<v8::Object> dbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(dbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsBoolean())
    return Nan::ThrowTypeError("Second argument must be a boolean.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(dbuf);
  size_t data_len = node::Buffer::Length(dbuf);

  if (data_len != 64)
    return Nan::ThrowRangeError("Invalid hash size.");

  int pake = (int)Nan::To<bool>(info[1]).FromJust();

  uint8_t out[32];

  if (!bcrypto_x25519_pubkey_from_hash(out, data, pake))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BX25519::PublicKeyToHash) {
  if (info.Length() < 1)
    return Nan::ThrowError("x25519.publicKeyToHash() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != 32)
    return Nan::ThrowRangeError("Invalid public key size.");

  uint8_t out[64];

  if (!bcrypto_x25519_pubkey_to_hash(out, pub))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 64).ToLocalChecked());
}

NAN_METHOD(BX25519::PublicKeyVerify) {
  if (info.Length() < 1)
    return Nan::ThrowError("x25519.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != 32)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = bcrypto_x25519_pubkey_verify(pub) == 1;

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BX25519::PublicKeyIsSmall) {
  if (info.Length() < 1)
    return Nan::ThrowError("x25519.publicKeyIsSmall() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != 32)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = bcrypto_x25519_pubkey_is_small(pub) == 1;

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BX25519::PublicKeyHasTorsion) {
  if (info.Length() < 1)
    return Nan::ThrowError("x25519.publicKeyHasTorsion() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != 32)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  bool result = bcrypto_x25519_pubkey_has_torsion(pub) == 1;

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BX25519::Derive) {
  if (info.Length() < 2)
    return Nan::ThrowError("x25519.derive() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t key_len = node::Buffer::Length(sbuf);

  if (pub_len != 32)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (key_len != 32)
    return Nan::ThrowRangeError("Invalid private key size.");

  bcrypto_x25519_pubkey_t out;

  if (!bcrypto_x25519_derive(out, pub, key))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}
