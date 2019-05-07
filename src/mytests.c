#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "secp256k1.c"
#include "include/secp256k1.h"
#include "testrand_impl.h"
#include "include/secp256k1_recovery.h"

/* printf switch flag */
#define DEBUG_PRINTF
#undef  DEBUG_PRINTF

#define SUBCMD_SIGN         "sign"
#define ARGS_LEN_SIGN       3
#define SUBCMD_SHA256      "sha256"
#define ARGS_LEN_SHA256    2
#define SUBCMD_VERIFY       "verify"
#define ARGS_LEN_VERIFY     3
#define SUBCMD_TEST         "test"
#define ARGS_LEN_TEST       2




void fb_wrong_args(void){
  char str[] = "{\"status\":-1,\"data\":\"Wrong cmd args\"}";
  printf("%s",str);
}

void fb_wrong_cmd(void){
  char str[] = "{\"status\":-1,\"data\":\"Wrong cmd\"}";
  printf("%s",str);
}
void fb_wrong(int status, char *data){
  char str[256];
  sprintf(str, "{\"status\":%d,\"data\":\"%s\"}", status, data);
  printf("%s", str);
}

int ascii_to_int(char c){
 
  if(c >= 0x61 && c <= 0x66){
    return c - 0x61 + 10;
  }else if( c >= 0x30 && c <= 0x39 ){
    return c - 0x30;
  }else{
    return 0;
  }
}
char hex_to_asicc(unsigned char ch){
  if(ch <=9){
    return ch + 0x30;
  }
  else if( ch >= 10 && ch <=15){
    return ch -10 + 0x61;
  }else{
    return 0;
  }
}

int ascii_to_hex(char c, char d){
  int high = ascii_to_int(c) * 16;
  int low = ascii_to_int(d);
  return high+low;
}
int arr_ascii_to_hex(unsigned char* input, int leninput,unsigned char*output, int lenoutput){
  int lenInput = leninput;
  int lenOutput = lenoutput;
  int i;
  int iLen;
  
  if(lenInput!= lenOutput*2
     || lenInput%2 != 0
     || lenOutput%2 != 0){
#ifdef DEBUG_PRINTF
    printf("input len:%d\n", lenInput);
    printf("output len:%d\n", lenOutput);
#endif
    return -1;
  }
  
  iLen = (int) lenInput/2;
  for(i = 0; i< iLen; i++){

#ifdef DEBUG_PRINTF
    printf("input %02x %02x\n",input[i*2], input[i*2 +1]);
#endif
    output[i] = ascii_to_hex(input[i*2], input[i*2 + 1]);
  }
  return 0;
}
int arr_hex_to_ascii(unsigned char * input, int leninput, unsigned char *output, int lenoutput){
  int lenInput = leninput;
  int lenOutput = lenoutput;
  int i;
  int iLen = leninput;
  char chH;
  char chL;
  
  if(lenInput!= lenOutput/2
     || lenInput%2 != 0
     || lenOutput%2 != 0){
#ifdef DEBUG_PRINTF
    printf("hex_to_ascii input len:%d\n", lenInput);
    printf("hex_to_ascii output len:%d\n", lenOutput);
#endif
    return -1;
  }

  for(i=0; i< iLen; i++){
#ifdef DEBUG_PRINTF
    printf("input %02x\n", input[i]);
#endif
    chH = input[i]/16;
    chL = input[i] - 16*(input[i]/16);
    output[i*2] = hex_to_asicc(chH);
    output[i*2 + 1] = hex_to_asicc(chL);
  }

  
  return 0;
}

void printArrHex(unsigned char *input, unsigned int len)
{
  unsigned int i;
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

int double_sha256(unsigned char *input, unsigned char*output){
  unsigned char sha256Out[32];
  
  if(quick_sha256(input,strlen((const char *)input), sha256Out) == 0){
#ifdef DEBUG_PRINTF
    printf("sha256 1st finished:\n");
    printArrHex(sha256Out, 32);

#endif
  }else{
    return -1;
  }
  if(quick_sha256(sha256Out,32, output) == 0){
#ifdef DEBUG_PRINTF
    printf("sha256 2nd finished:\n");
    printArrHex(output, 32);

#endif
  }else{
    return -1;
  }
  return 0;
}


int sign(unsigned char *msg32, unsigned char *private_key, unsigned char *signature, int* recid){
  secp256k1_context* secp256k1ctx;
  secp256k1_ecdsa_recoverable_signature sig;
  int fb;

  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;
  
  secp256k1ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN
					  | SECP256K1_CONTEXT_VERIFY);  
  fb = secp256k1_ecdsa_sign_recoverable(secp256k1ctx, &sig, msg32, private_key, noncefn, NULL);
  if(fb == 0){
    secp256k1_context_destroy(secp256k1ctx);
    return -1;
  }
  secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1ctx, signature, recid, &sig);
  
  secp256k1_context_destroy(secp256k1ctx);
  return 0;
}
void subcmd_sign(int argc, char** argv){

  char *ptrMsg= argv[2];
  char *ptrKey = argv[3];
  unsigned char msgHash[32];
  unsigned char keyHash[32];
  unsigned char signature[64];
  unsigned char sigOut[129];
  int rcid;
  char jsonBuf[256];
  
  ptrMsg= argv[2];
  ptrKey = argv[3];

  if(argc != ARGS_LEN_SIGN +1){
    fb_wrong_args();
    return;
  }  
#ifdef DEBUG_PRINTF
  printf("sign:\n");
  printf("msg: %s\n", ptrMsg);
  printf("key: %s\n", ptrKey);
#endif

  if(strlen(ptrKey) != 64){
    fb_wrong(-1, "sign wrong key");
    return;
  }

  if(double_sha256((unsigned char*)ptrMsg, msgHash) != 0){
    fb_wrong(-1,"sign,double_sha256 fail");
    return;
  }

  if(arr_ascii_to_hex((unsigned char*)ptrKey,64, keyHash, 32) != 0){
    fb_wrong(-1,"sign, arr ascii to hex fail");
    return;
  }
#ifdef DEBUG_PRINTF
  printf("\nsign, msg and key\n");
  printArrHex(msgHash, 32);
  printArrHex(keyHash, 32);
#endif

  if(sign(msgHash, keyHash, signature, &rcid) != 0){
    fb_wrong(-1, "sign fail");
    return;
  }
#ifdef DEBUG_PRINTF
  printf("signature and recid\n");
  printArrHex(signature, 64);
  printf("recid:%d\n", rcid);

#endif
  if(arr_hex_to_ascii(signature,64, sigOut, 128) != 0){
    fb_wrong(-1, "sign, hex to ascii fail");
    return;
  }

  sigOut[128] = 0x0;

  sprintf(jsonBuf,"{\"status\":0,\"data\":{\"signature\":\"%s\",\"recid\":%d}}",sigOut,rcid);
#ifdef DEBUG_PRINTF
  printf("jsonBuf length:%lu\n", strlen((const char*)jsonBuf));
  printf("sigOut:\n");
  printf("%s\n", sigOut);
  printf("sigOut len:%lu\n", strlen((const char*)sigOut));
#endif
  printf("%s", jsonBuf);
}
void subcmd_hash256(int argc, char **argv){
  char *ptrMsg;
  unsigned char sha256Out[32];
  unsigned char temp[65];
  char output[128];
 
  if(argc != ARGS_LEN_SHA256 + 1){
    fb_wrong_args();
    return;
  }
  ptrMsg = argv[2];

#ifdef DEBUG_PRINTF
  printf("hash256:\n");
  printf("msg: %s\n", ptrMsg);
#endif  

  if(quick_sha256((unsigned char*)ptrMsg,strlen((const char *)ptrMsg), sha256Out) == 0){
#ifdef DEBUG_PRINTF
    printf("sha256 1st finished:\n");
    printArrHex(sha256Out, 32);
#endif
    
    arr_hex_to_ascii(sha256Out, 32, temp, 64);
    temp[64] = 0;
    sprintf(output,"{\"status\":0,\"data\":\"%s\"}",(char *)temp);
    printf("%s", output);
  }else{
    fb_wrong(-1, "hash256, fail");
  }  
}

void subcmd_test(int argc, char **argv){
  char *ptrMsg;
  unsigned char hexKey[32];
  int a;
  
  if(argc != ARGS_LEN_TEST + 1){
    fb_wrong_args();
    return;
  }
  
  ptrMsg = argv[2];
  if( strlen((const char*)ptrMsg)%2 != 0){
    fb_wrong_args();
    return;
  }
  

  a = arr_ascii_to_hex((unsigned char*)ptrMsg,strlen((const char*)ptrMsg), hexKey, 32);
  
#ifdef DEBUG_PRINTF
  printf("%d\n", a);
  printArrHex(hexKey, 32);
#endif

}

int main(int argc, char **argv){
#ifdef DEBUG_PRINTF
  printf("argc:%d\n", argc);
#endif

  if(argc <2 ){
    fb_wrong_args();
    return -1;
  }
  
#ifdef DEBUG_PRINTF
  printf("%s %s\n", argv[0], argv[1]);
#endif
 
  if(strcmp(argv[1], SUBCMD_SIGN) == 0){
    subcmd_sign(argc, argv);
  }
  else if(strcmp(argv[1], SUBCMD_SHA256) == 0){
    subcmd_hash256(argc, argv);
  }
  else if(strcmp(argv[1], SUBCMD_TEST) == 0){
    subcmd_test(argc,argv);
  }
  else{
    fb_wrong_cmd();
  }

  return 0;

}

int main_bk(int argc, char **argv)

{

  secp256k1_pubkey zero_pubkey;
  secp256k1_pubkey pubkey2;
  secp256k1_pubkey pubkey;
  /* secp256k1_ge pub; */
  secp256k1_scalar msg, key;
  /* secp256k1_scalar sigr, sigs; */
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
  size_t pubkeyclen;
  secp256k1_context *ctx;
  
  pubkeyclen = 65;
  printf("It is my tests now\n");
  
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
  
  ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

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
