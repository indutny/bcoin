{
  "targets": [{
    "target_name": "bcrypto",
    "sources": [
      "./src/aead/aead.c",
      "./src/aes/aes.c",
      "./src/base58/base58.c",
      "./src/bech32/bech32.c",
      "./src/blake2b/blake2b.c",
      "./src/blake2s/blake2s.c",
      "./src/cash32/cash32.c",
      "./src/chacha20/chacha20.c",
      "./src/dsa/dsa.c",
      "./src/ecdsa/ecdsa.c",
      "./src/ed25519/ed25519.c",
      "./src/ed448/arch_32/f_impl.c",
      "./src/ed448/curve448.c",
      "./src/ed448/curve448_tables.c",
      "./src/ed448/eddsa.c",
      "./src/ed448/f_generic.c",
      "./src/ed448/scalar.c",
      "./src/murmur3/murmur3.c",
      "./src/pbkdf2/pbkdf2.c",
      "./src/poly1305/poly1305.c",
      "./src/random/random.c",
      "./src/rsa/rsa.c",
      "./src/salsa20/salsa20.c",
      "./src/scrypt/insecure_memzero.c",
      "./src/scrypt/sha256.c",
      "./src/scrypt/scrypt.c",
      "./src/secp256k1/src/secp256k1.c",
      "./src/secp256k1/contrib/lax_der_parsing.c",
      "./src/secp256k1/contrib/lax_der_privatekey_parsing.c",
      "./src/siphash/siphash.c",
      "./src/keccak/keccak.c",
      "./src/aead.cc",
      "./src/aes.cc",
      "./src/base58.cc",
      "./src/bech32.cc",
      "./src/bcrypto.cc",
      "./src/blake2b.cc",
      "./src/blake2s.cc",
      "./src/cash32.cc",
      "./src/chacha20.cc",
      "./src/cipherbase.cc",
      "./src/dsa.cc",
      "./src/dsa_async.cc",
      "./src/ecdsa.cc",
      "./src/ed25519.cc",
      "./src/ed448.cc",
      "./src/hash160.cc",
      "./src/hash256.cc",
      "./src/keccak.cc",
      "./src/md4.cc",
      "./src/md5.cc",
      "./src/murmur3.cc",
      "./src/pbkdf2.cc",
      "./src/pbkdf2_async.cc",
      "./src/poly1305.cc",
      "./src/random.cc",
      "./src/ripemd160.cc",
      "./src/rsa.cc",
      "./src/rsa_async.cc",
      "./src/salsa20.cc",
      "./src/scrypt.cc",
      "./src/scrypt_async.cc",
      "./src/secp256k1.cc",
      "./src/sha1.cc",
      "./src/sha224.cc",
      "./src/sha256.cc",
      "./src/sha384.cc",
      "./src/sha512.cc",
      "./src/siphash.cc",
      "./src/whirlpool.cc",
      "./src/x25519.cc",
      "./src/x448.cc"
    ],
    "cflags": [
      "-Wall",
      "-Wextra",
      "-Wno-implicit-fallthrough",
      "-Wno-nonnull-compare",
      "-Wno-unknown-warning",
      "-Wno-unused-function",
      "-O3"
    ],
    "cflags_c": [
      "-std=c99"
    ],
    "cflags_cc+": [
      "-std=c++0x",
      "-Wno-cast-function-type",
      "-Wno-unused-parameter"
    ],
    "include_dirs": [
      "<!(node -e \"require('nan')\")"
    ],
    "defines": [
      "USE_ENDOMORPHISM",
      "ENABLE_MODULE_ECDH",
      "ENABLE_MODULE_ELLIGATOR",
      "ENABLE_MODULE_EXTRA",
      "ENABLE_MODULE_RECOVERY",
      "ENABLE_MODULE_SCHNORRLEG"
    ],
    "variables": {
      "conditions": [
        ["OS=='win'", {
          "conditions": [
            ["target_arch=='ia32'", {
              "openssl_root%": "C:/OpenSSL-Win32"
            }, {
              "openssl_root%": "C:/OpenSSL-Win64"
            }]
          ]
        }],
        ["OS=='win'", {
          "with_gmp%": "false"
        }, {
          "with_gmp%": "<!(./utils/has_gmp.sh)"
        }]
      ]
    },
    "conditions": [
      ["node_byteorder=='big'", {
        "defines": [
          "WORDS_BIGENDIAN"
        ]
      }],
      ["target_arch=='x64' and OS!='win'", {
        "defines": [
          "BCRYPTO_POLY1305_64BIT",
          "BCRYPTO_SIPHASH_64BIT",
          "BCRYPTO_USE_ASM",
          "BCRYPTO_USE_SSE",
          "HAVE___INT128",
          "USE_ASM_X86_64",
          "USE_FIELD_5X52",
          "USE_FIELD_5X52_INT128",
          "USE_SCALAR_4X64"
        ],
        "cflags": [
          "-msse4.1"
        ]
      }, {
        "defines": [
          "BCRYPTO_POLY1305_32BIT",
          "BCRYPTO_ED25519_NO_INLINE_ASM",
          "USE_FIELD_10X26",
          "USE_SCALAR_8X32"
        ]
      }],
      ["with_gmp=='true'", {
        "defines": [
          "HAVE_LIBGMP",
          "USE_NUM_GMP",
          "USE_FIELD_INV_NUM",
          "USE_SCALAR_INV_NUM"
        ],
        "libraries": [
          "-lgmp"
        ]
      }, {
        "defines": [
          "USE_NUM_NONE",
          "USE_FIELD_INV_BUILTIN",
          "USE_SCALAR_INV_BUILTIN"
        ]
      }],
      ["OS=='win'", {
        "libraries": [
          "-l<(openssl_root)/lib/libeay32.lib"
        ],
        "include_dirs": [
          "<(openssl_root)/include"
        ],
        "msbuild_settings": {
          "ClCompile": {
            "ObjectFileName": "$(IntDir)/%(Directory)/%(Filename)"
          },
          "Link": {
            "ImageHasSafeExceptionHandlers": "false"
          }
        }
      }, {
        "include_dirs": [
          "<(node_root_dir)/deps/openssl/openssl/include"
        ]
      }],
      ["OS=='mac'", {
        "include_dirs": [
          "/usr/local/include"
        ],
        "libraries": [
          "-L/usr/local/lib"
        ],
        "xcode_settings": {
          "MACOSX_DEPLOYMENT_TARGET": "10.7",
          "OTHER_CPLUSPLUSFLAGS": [
            "-stdlib=libc++"
          ]
        }
      }]
    ]
  }]
}
