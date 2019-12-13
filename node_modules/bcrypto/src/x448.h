#ifndef _BCRYPTO_X448_HH
#define _BCRYPTO_X448_HH

#include <node.h>
#include <nan.h>

class BX448 {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(PublicKeyCreate);
  static NAN_METHOD(PublicKeyConvert);
  static NAN_METHOD(PublicKeyFromUniform);
  static NAN_METHOD(PublicKeyToUniform);
  static NAN_METHOD(PublicKeyFromHash);
  static NAN_METHOD(PublicKeyToHash);
  static NAN_METHOD(PublicKeyVerify);
  static NAN_METHOD(PublicKeyIsSmall);
  static NAN_METHOD(PublicKeyHasTorsion);
  static NAN_METHOD(Derive);
};

#endif
