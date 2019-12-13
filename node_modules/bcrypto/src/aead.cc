#include "common.h"
#include "aead/aead.h"
#include "aead.h"

// For "cleanse"
#include "openssl/crypto.h"

static Nan::Persistent<v8::FunctionTemplate> aead_constructor;

BAEAD::BAEAD() {
  bcrypto_aead_init(&ctx);
}

BAEAD::~BAEAD() {
  OPENSSL_cleanse(&ctx, sizeof(bcrypto_aead_ctx));
}

void
BAEAD::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BAEAD::New);

  aead_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("AEAD").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BAEAD::Init);
  Nan::SetPrototypeMethod(tpl, "aad", BAEAD::AAD);
  Nan::SetPrototypeMethod(tpl, "encrypt", BAEAD::Encrypt);
  Nan::SetPrototypeMethod(tpl, "decrypt", BAEAD::Decrypt);
  Nan::SetPrototypeMethod(tpl, "auth", BAEAD::Auth);
  Nan::SetPrototypeMethod(tpl, "final", BAEAD::Final);
  Nan::SetPrototypeMethod(tpl, "destroy", BAEAD::Destroy);
  Nan::SetPrototypeMethod(tpl, "verify", BAEAD::Verify);
  Nan::SetMethod(tpl, "encrypt", BAEAD::StaticEncrypt);
  Nan::SetMethod(tpl, "decrypt", BAEAD::StaticDecrypt);
  Nan::SetMethod(tpl, "auth", BAEAD::StaticAuth);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(aead_constructor);

  Nan::Set(target, Nan::New("AEAD").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BAEAD::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create AEAD instance.");

  BAEAD *aead = new BAEAD();
  aead->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BAEAD::Init) {
  BAEAD *aead = ObjectWrap::Unwrap<BAEAD>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("aead.init() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Value> iv_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(iv_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);

  if (key_len < 32)
    return Nan::ThrowRangeError("Invalid key size.");

  const uint8_t *iv = (const uint8_t *)node::Buffer::Data(iv_buf);
  size_t iv_len = node::Buffer::Length(iv_buf);

  if (iv_len != 8 && iv_len != 12 && iv_len != 16
      && iv_len != 24 && iv_len != 28 && iv_len != 32) {
    return Nan::ThrowRangeError("Invalid IV size.");
  }

  bcrypto_aead_init(&aead->ctx);
  bcrypto_aead_setup(&aead->ctx, key, iv, iv_len);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BAEAD::AAD) {
  BAEAD *aead = ObjectWrap::Unwrap<BAEAD>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("aead.aad() requires arguments.");

  v8::Local<v8::Object> aad_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(aad_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (aead->ctx.mode == -1)
    return Nan::ThrowError("Context is not initialized.");

  if (aead->ctx.mode != 0)
    return Nan::ThrowError("Invalid state for aad.");

  const uint8_t *aad = (const uint8_t *)node::Buffer::Data(aad_buf);
  size_t aad_len = node::Buffer::Length(aad_buf);

  bcrypto_aead_aad(&aead->ctx, aad, aad_len);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BAEAD::Encrypt) {
  BAEAD *aead = ObjectWrap::Unwrap<BAEAD>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("aead.encrypt() requires arguments.");

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (aead->ctx.mode == -1)
    return Nan::ThrowError("Context is not initialized.");

  if (aead->ctx.mode != 0 && aead->ctx.mode != 1)
    return Nan::ThrowError("Invalid state for aad.");

  uint8_t *msg = (uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  bcrypto_aead_encrypt(&aead->ctx, msg, msg, msg_len);

  info.GetReturnValue().Set(msg_buf);
}

NAN_METHOD(BAEAD::Decrypt) {
  BAEAD *aead = ObjectWrap::Unwrap<BAEAD>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("aead.decrypt() requires arguments.");

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (aead->ctx.mode == -1)
    return Nan::ThrowError("Context is not initialized.");

  if (aead->ctx.mode != 0 && aead->ctx.mode != 2)
    return Nan::ThrowError("Invalid state for decrypt.");

  uint8_t *msg = (uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  bcrypto_aead_decrypt(&aead->ctx, msg, msg, msg_len);

  info.GetReturnValue().Set(msg_buf);
}

NAN_METHOD(BAEAD::Auth) {
  BAEAD *aead = ObjectWrap::Unwrap<BAEAD>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("aead.auth() requires arguments.");

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (aead->ctx.mode == -1)
    return Nan::ThrowError("Context is not initialized.");

  if (aead->ctx.mode != 0 && aead->ctx.mode != 3)
    return Nan::ThrowError("Invalid state for auth.");

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  bcrypto_aead_auth(&aead->ctx, msg, msg_len);

  info.GetReturnValue().Set(msg_buf);
}

NAN_METHOD(BAEAD::Final) {
  BAEAD *aead = ObjectWrap::Unwrap<BAEAD>(info.Holder());

  if (aead->ctx.mode == -1)
    return Nan::ThrowError("Context is not initialized.");

  uint8_t mac[16];

  bcrypto_aead_final(&aead->ctx, &mac[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&mac[0], 16).ToLocalChecked());
}

NAN_METHOD(BAEAD::Destroy) {
  BAEAD *aead = ObjectWrap::Unwrap<BAEAD>(info.Holder());

  aead->ctx.mode = -1;

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BAEAD::Verify) {
  BAEAD *aead = ObjectWrap::Unwrap<BAEAD>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("aead.verify() requires arguments.");

  v8::Local<v8::Object> tag_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(tag_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (aead->ctx.mode == -1)
    return Nan::ThrowError("Context is not initialized.");

  const uint8_t *tag = (const uint8_t *)node::Buffer::Data(tag_buf);
  size_t tag_len = node::Buffer::Length(tag_buf);

  if (tag_len != 16)
    return Nan::ThrowRangeError("Invalid key size.");

  uint8_t mac[16];

  bcrypto_aead_final(&aead->ctx, &mac[0]);

  int result = bcrypto_aead_verify(&mac[0], tag);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BAEAD::StaticEncrypt) {
  if (info.Length() < 3)
    return Nan::ThrowError("AEAD.encrypt() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Value> iv_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(iv_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  v8::Local<v8::Value> msg_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);

  if (key_len < 32)
    return Nan::ThrowRangeError("Invalid key size.");

  const uint8_t *iv = (const uint8_t *)node::Buffer::Data(iv_buf);
  size_t iv_len = node::Buffer::Length(iv_buf);

  if (iv_len != 8 && iv_len != 12 && iv_len != 16
      && iv_len != 24 && iv_len != 28 && iv_len != 32) {
    return Nan::ThrowRangeError("Invalid IV size.");
  }

  uint8_t *msg = (uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  const uint8_t *aad = NULL;
  size_t aad_len = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    v8::Local<v8::Object> aad_buf = info[3].As<v8::Object>();

    if (!node::Buffer::HasInstance(aad_buf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer.");

    aad = (const uint8_t *)node::Buffer::Data(aad_buf);
    aad_len = node::Buffer::Length(aad_buf);
  }

  bcrypto_aead_ctx ctx;
  bcrypto_aead_init(&ctx);
  bcrypto_aead_setup(&ctx, key, iv, iv_len);

  if (aad)
    bcrypto_aead_aad(&ctx, aad, aad_len);

  bcrypto_aead_encrypt(&ctx, msg, msg, msg_len);

  uint8_t out[16];

  bcrypto_aead_final(&ctx, &out[0]);

  OPENSSL_cleanse(&ctx, sizeof(bcrypto_aead_ctx));

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 16).ToLocalChecked());
}

NAN_METHOD(BAEAD::StaticDecrypt) {
  if (info.Length() < 4)
    return Nan::ThrowError("AEAD.decrypt() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Value> iv_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(iv_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  v8::Local<v8::Value> msg_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  v8::Local<v8::Value> tag_buf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(tag_buf))
    return Nan::ThrowTypeError("Fourth argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);

  if (key_len < 32)
    return Nan::ThrowRangeError("Invalid key size.");

  const uint8_t *iv = (const uint8_t *)node::Buffer::Data(iv_buf);
  size_t iv_len = node::Buffer::Length(iv_buf);

  if (iv_len != 8 && iv_len != 12 && iv_len != 16
      && iv_len != 24 && iv_len != 28 && iv_len != 32) {
    return Nan::ThrowRangeError("Invalid IV size.");
  }

  uint8_t *msg = (uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  const uint8_t *tag = (const uint8_t *)node::Buffer::Data(tag_buf);
  size_t tag_len = node::Buffer::Length(tag_buf);

  if (tag_len < 16)
    return Nan::ThrowRangeError("Invalid tag size.");

  const uint8_t *aad = NULL;
  size_t aad_len = 0;

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> aad_buf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(aad_buf))
      return Nan::ThrowTypeError("Fifth argument must be a buffer.");

    aad = (const uint8_t *)node::Buffer::Data(aad_buf);
    aad_len = node::Buffer::Length(aad_buf);
  }

  bcrypto_aead_ctx ctx;
  bcrypto_aead_init(&ctx);
  bcrypto_aead_setup(&ctx, key, iv, iv_len);

  if (aad)
    bcrypto_aead_aad(&ctx, aad, aad_len);

  bcrypto_aead_decrypt(&ctx, msg, msg, msg_len);

  uint8_t out[16];

  bcrypto_aead_final(&ctx, &out[0]);

  OPENSSL_cleanse(&ctx, sizeof(bcrypto_aead_ctx));

  int result = bcrypto_aead_verify(&out[0], tag);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BAEAD::StaticAuth) {
  if (info.Length() < 4)
    return Nan::ThrowError("AEAD.decrypt() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Value> iv_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(iv_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  v8::Local<v8::Value> msg_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  v8::Local<v8::Value> tag_buf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(tag_buf))
    return Nan::ThrowTypeError("Fourth argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);

  if (key_len < 32)
    return Nan::ThrowRangeError("Invalid key size.");

  const uint8_t *iv = (const uint8_t *)node::Buffer::Data(iv_buf);
  size_t iv_len = node::Buffer::Length(iv_buf);

  if (iv_len != 8 && iv_len != 12 && iv_len != 16
      && iv_len != 24 && iv_len != 28 && iv_len != 32) {
    return Nan::ThrowRangeError("Invalid IV size.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  const uint8_t *tag = (const uint8_t *)node::Buffer::Data(tag_buf);
  size_t tag_len = node::Buffer::Length(tag_buf);

  if (tag_len < 16)
    return Nan::ThrowRangeError("Invalid tag size.");

  const uint8_t *aad = NULL;
  size_t aad_len = 0;

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> aad_buf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(aad_buf))
      return Nan::ThrowTypeError("Fifth argument must be a buffer.");

    aad = (const uint8_t *)node::Buffer::Data(aad_buf);
    aad_len = node::Buffer::Length(aad_buf);
  }

  bcrypto_aead_ctx ctx;
  bcrypto_aead_init(&ctx);
  bcrypto_aead_setup(&ctx, key, iv, iv_len);

  if (aad)
    bcrypto_aead_aad(&ctx, aad, aad_len);

  bcrypto_aead_auth(&ctx, msg, msg_len);

  uint8_t out[16];

  bcrypto_aead_final(&ctx, &out[0]);

  OPENSSL_cleanse(&ctx, sizeof(bcrypto_aead_ctx));

  int result = bcrypto_aead_verify(&out[0], tag);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
