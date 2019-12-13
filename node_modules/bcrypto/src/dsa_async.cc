#include "compat.h"

#ifdef BCRYPTO_HAS_DSA

#include <assert.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "dsa/dsa.h"
#include "dsa_async.h"

BDSAWorker::BDSAWorker (
  int bits,
  Nan::Callback *callback
) : Nan::AsyncWorker(callback, "bcrypto:dsa_params_generate")
  , bits(bits)
  , key(NULL)
{
  Nan::HandleScope scope;
}

BDSAWorker::~BDSAWorker() {}

void
BDSAWorker::Execute() {
  key = bcrypto_dsa_params_generate(bits);

  if (key == NULL)
    SetErrorMessage("Could not generate key.");
}

void
BDSAWorker::HandleOKCallback() {
  Nan::HandleScope scope;

  bcrypto_dsa_key_t *k = key;
  assert(k);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->pd, k->pl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->qd, k->ql).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->gd, k->gl).ToLocalChecked());

  v8::Local<v8::Value> argv[] = { Nan::Null(), ret };

  bcrypto_dsa_key_free(k);
  key = NULL;

  callback->Call(2, argv, async_resource);
}
#endif
