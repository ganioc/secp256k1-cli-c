#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "secp256k1.c"
#include "include/secp256k1.h"
#include "testrand_impl.h"

void printArrHex(unsigned char *input, unsigned int len)
{
  int i;
  for (i = 0; i < len; i++)
    {
      printf("%02x ", input[i]);
      if (((i + 1) % 16 == 0) && (i != 0))
	{
	  printf("\n");
	}
    }
  printf("\n");
}

void random_scalar_order_test(secp256k1_scalar *num) {
  do {
    unsigned char b32[32];
    int overflow = 0;
    secp256k1_rand256_test(b32);
    secp256k1_scalar_set_b32(num, b32, &overflow);
    if (overflow || secp256k1_scalar_is_zero(num)) {
      continue;
    }
    break;
  } while(1);
}

int quick_sha256(unsigned char *input, unsigned int len, unsigned char *output)
{
  secp256k1_sha256 hasher;
  secp256k1_sha256_initialize(&hasher);
  secp256k1_sha256_write(&hasher, (const unsigned char *)(input), len);
  secp256k1_sha256_finalize(&hasher, output);

  return 0;
}

int main()
{

  printf("It is my tests now\n");
  secp256k1_pubkey zero_pubkey;
  secp256k1_pubkey pubkey2;
  secp256k1_pubkey pubkey;
  secp256k1_ge pub;
  secp256k1_scalar msg, key, nonce;
  secp256k1_scalar sigr, sigs;
  secp256k1_ecdsa_signature signature;
  int fb, i;
  unsigned char input[] = "abc";
  unsigned char inputKey[] = {
    0xda, 0x6f, 0xea , 0xe3 , 0xca , 0x24 , 0x9c , 0x35 ,
    0x92 , 0x00 , 0x48 , 0x79 , 0x34 , 0x21 , 0x6f , 0x45 ,
    0xdd , 0x1c , 0x21 , 0x59 , 0x11 , 0x6c , 0x3e , 0xec ,
    0xc3 , 0x48 , 0xa7 , 0x4a , 0x3c , 0x7d , 0x16 , 0xba
  };
  unsigned char sha256Out[32], sha256Out2[32];
  unsigned char privkey[32];
  unsigned char message[32];
  unsigned char pubkeyc[65];
  size_t pubkeyclen = 65;

  
  if (quick_sha256(input, strlen((const char *)input), sha256Out) == 0)
    {
      printf("sha256 1st finished\n");
      printArrHex(sha256Out, 32);
    }

  if (quick_sha256(sha256Out, 32, sha256Out2) == 0)
    {
      printf("sha256 2nd finished\n");
      printArrHex(sha256Out2, 32);
    }
  
  memset(&zero_pubkey, 0, sizeof(zero_pubkey));
  memset(&pubkey, 0, sizeof(pubkey));
  
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  /* init */
  random_scalar_order_test(&msg);
  random_scalar_order_test(&key);
  secp256k1_scalar_get_b32(privkey, &key);
  secp256k1_scalar_get_b32(message, &msg);

  printf("\nprivkey:\n");
  printArrHex(inputKey,32);

  printf("\nmessage:\n");
  printArrHex(sha256Out2,32);

  
  fb = secp256k1_ecdsa_sign(ctx, &signature, sha256Out2, inputKey, NULL, NULL);
  printf("fb of sign:%d\n", fb);
  
  printf("\nsignature:\n");
  
  for(i=0; i<64;i++){
    printf("%02x ", signature.data[i]);

  }
  printf("\n");

  fb = secp256k1_ecdsa_signature_normalize(ctx, NULL, &signature);
  printf("\nsignature normalized: %d\n", fb);
  
  for(i=0; i<64;i++){
    printf("%02x ", signature.data[i]);

  }
  printf("\n");
  
  fb = secp256k1_ec_seckey_verify(ctx, inputKey);
  printf("fb of seckey verify: %d\n", fb);
  
  fb = secp256k1_ec_pubkey_create(ctx, &pubkey2, inputKey);
  printf("create pubkey from privkey: %d\n", fb);

  for(i=0; i<64;i++){
    printf("%02x ", pubkey2.data[i]);

  }

  fb = secp256k1_ec_pubkey_serialize(ctx, pubkeyc, &pubkeyclen, &pubkey2, SECP256K1_EC_COMPRESSED);
  printf("\npubkey serialize:\n");
  for(i=0; i<65; i++){
    printf("%02x ", pubkeyc[i]);
  }
  printf("\n");

  fb = secp256k1_ec_pubkey_parse(ctx, &pubkey2, pubkeyc, pubkeyclen);
  printf("pubkey2 after parse:\n");
  for(i=0; i<64;i++){
    printf("%02x ", pubkey2.data[i]);
  }
  
  /* fb = memcmp(&pubkey, &pubkey2, sizeof(pubkey)); */
  /* printf("memcmp pubkey pubkey2 : %d\n", fb); */

  fb = secp256k1_ecdsa_verify(ctx, &signature,sha256Out2, &pubkey2);
  printf("Verifty signature: %d\n", fb);
  
  secp256k1_context_destroy(ctx);

  return 0;
}
