#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>
#include <limits>

#include "common.h"
#include "random/random.h"
#include "random.h"

void
BRandom::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "randomBytes", BRandom::RandomBytes);
  Nan::Export(obj, "randomFill", BRandom::RandomFill);
  Nan::Export(obj, "randomInt", BRandom::RandomInt);
  Nan::Export(obj, "randomRange", BRandom::RandomRange);

  Nan::Set(target, Nan::New("random").ToLocalChecked(), obj);
}

NAN_METHOD(BRandom::RandomBytes) {
  if (info.Length() < 1)
    return Nan::ThrowError("random.randomBytes() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  size_t size = (size_t)Nan::To<uint32_t>(info[0]).FromJust();
  size_t max = (size_t)std::numeric_limits<int32_t>::max();

  if (size > max)
    return Nan::ThrowRangeError("Invalid size requested.");

  uint8_t *data = (uint8_t *)malloc(size);

  if (data == NULL)
    return Nan::ThrowError("Allocation failed.");

  if (!bcrypto_random((void *)data, size))
    return Nan::ThrowError("Could not get random bytes.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)data, size).ToLocalChecked());
}

NAN_METHOD(BRandom::RandomFill) {
  if (info.Length() < 3)
    return Nan::ThrowError("random.randomFill() requires arguments.");

  if (!node::Buffer::HasInstance(info[0]))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> bdata = info[0].As<v8::Object>();

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  uint8_t *data = (uint8_t *)node::Buffer::Data(bdata);
  size_t len = node::Buffer::Length(bdata);

  size_t pos = (size_t)Nan::To<uint32_t>(info[1]).FromJust();
  size_t size = (size_t)Nan::To<uint32_t>(info[2]).FromJust();
  size_t max = (size_t)std::numeric_limits<int32_t>::max();

  if (len > max || pos > max || size > max)
    return Nan::ThrowRangeError("Invalid range.");

  if (pos + size > len)
    return Nan::ThrowRangeError("Size exceeds length.");

  if (!bcrypto_random((void *)(data + pos), size))
    return Nan::ThrowError("Could not get random bytes.");

  info.GetReturnValue().Set(bdata);
}

NAN_METHOD(BRandom::RandomInt) {
  uint32_t num;

  if (!bcrypto_random((void *)&num, sizeof(uint32_t)))
    return Nan::ThrowError("Could not get random bytes.");

  info.GetReturnValue().Set(Nan::New<v8::Uint32>(num));
}

NAN_METHOD(BRandom::RandomRange) {
  if (info.Length() < 2)
    return Nan::ThrowError("random.randomRange() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  uint32_t min = (uint32_t)Nan::To<uint32_t>(info[0]).FromJust();
  uint32_t max = (uint32_t)Nan::To<uint32_t>(info[1]).FromJust();

  if (min > max)
    return Nan::ThrowRangeError("Minimum cannot exceed maximum.");

  uint32_t space = max - min;
  uint32_t num = min;

  if (space > 0) {
    uint32_t x, r;

    do {
      if (!bcrypto_random((void *)&x, sizeof(uint32_t)))
        return Nan::ThrowError("Could not get random bytes.");

      r = x % space;
    } while (x - r > (-space));

    num += r;
  }

  info.GetReturnValue().Set(Nan::New<v8::Uint32>(num));
}
