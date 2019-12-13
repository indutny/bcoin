#include "common.h"
#include "pbkdf2/pbkdf2.h"
#include "pbkdf2_async.h"

BPBKDF2Worker::BPBKDF2Worker (
  v8::Local<v8::Object> &passHandle,
  v8::Local<v8::Object> &saltHandle,
  char *name,
  const uint8_t *pass,
  size_t passlen,
  const uint8_t *salt,
  size_t saltlen,
  uint32_t iter,
  size_t keylen,
  Nan::Callback *callback
) : Nan::AsyncWorker(callback, "bcrypto:pbkdf2")
  , name(name)
  , pass(pass)
  , passlen(passlen)
  , salt(salt)
  , saltlen(saltlen)
  , iter(iter)
  , key(NULL)
  , keylen(keylen)
{
  Nan::HandleScope scope;
  SaveToPersistent("pass", passHandle);
  SaveToPersistent("salt", saltHandle);
}

BPBKDF2Worker::~BPBKDF2Worker() {
  if (name) {
    free(name);
    name = NULL;
  }
}

void
BPBKDF2Worker::Execute() {
  key = (uint8_t *)malloc(keylen);

  if (key == NULL) {
    SetErrorMessage("PBKDF2 failed.");
    return;
  }

  if (!bcrypto_pbkdf2(key, name, pass, passlen, salt, saltlen, iter, keylen)) {
    free(key);
    key = NULL;
    SetErrorMessage("PBKDF2 failed.");
  }
}

void
BPBKDF2Worker::HandleOKCallback() {
  Nan::HandleScope scope;

  assert(key);

  v8::Local<v8::Value> keyBuffer =
    Nan::NewBuffer((char *)key, keylen).ToLocalChecked();

  v8::Local<v8::Value> argv[] = { Nan::Null(), keyBuffer };

  key = NULL;

  callback->Call(2, argv, async_resource);
}
