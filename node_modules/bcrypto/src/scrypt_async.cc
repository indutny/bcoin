#include "common.h"
#include "scrypt/scrypt.h"
#include "scrypt_async.h"

BScryptWorker::BScryptWorker (
  v8::Local<v8::Object> &passHandle,
  v8::Local<v8::Object> &saltHandle,
  const uint8_t *pass,
  const size_t passlen,
  const uint8_t *salt,
  size_t saltlen,
  uint64_t N,
  uint32_t r,
  uint32_t p,
  size_t keylen,
  Nan::Callback *callback
) : Nan::AsyncWorker(callback, "bcrypto:scrypt")
  , pass(pass)
  , passlen(passlen)
  , salt(salt)
  , saltlen(saltlen)
  , N(N)
  , r(r)
  , p(p)
  , key(NULL)
  , keylen(keylen)
{
  Nan::HandleScope scope;
  SaveToPersistent("pass", passHandle);
  SaveToPersistent("salt", saltHandle);
}

BScryptWorker::~BScryptWorker() {}

void
BScryptWorker::Execute() {
  key = (uint8_t *)malloc(keylen);

  if (key == NULL) {
    SetErrorMessage("Scrypt failed.");
    return;
  }

  if (!bcrypto_scrypt(key, pass, passlen, salt, saltlen, N, r, p, keylen)) {
    free(key);
    key = NULL;
    SetErrorMessage("Scrypt failed.");
  }
}

void
BScryptWorker::HandleOKCallback() {
  Nan::HandleScope scope;

  assert(key);

  v8::Local<v8::Value> keyBuffer =
    Nan::NewBuffer((char *)key, keylen).ToLocalChecked();

  v8::Local<v8::Value> argv[] = { Nan::Null(), keyBuffer };

  key = NULL;

  callback->Call(2, argv, async_resource);
}
