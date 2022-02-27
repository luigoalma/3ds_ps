#pragma once
#include <3ds/ps.h>
#include <3ds/types.h>

Result pxiPs9Init(void);

void pxiPs9Exit(void);

Result PXIPS9_CryptRsa(const PS_RSA_Context* rsa, const void* inbuf, void* outbuf, size_t buf_size);

Result PXIPS9_SignRsaSha256(const PS_RSA_Context* rsa, const void* sha256, void* sigbuf, size_t sigbuf_size);

Result PXIPS9_VerifyRsaSha256(const PS_RSA_Context* rsa, const void* sha256, const void* sigbuf, size_t sigbuf_size);

Result PXIPS9_SetAesKey(const u8 (*key)[16], u8 keyslot);

Result PXIPS9_EncryptDecryptAES(const u8 (*iv_ctr_inbuf)[16], u8 (*iv_ctr_outbuf)[16],
  const void* inbuf, void* outbuf, size_t bufsize,
  PS_AES_AlgoTypes algo, u8 keyslot);

Result PXIPS9_EncryptSignDecryptVerifyAesCcm(const u8 (*nonce)[12],
  const void* inbuf, size_t inbufsize, void* outbuf, size_t outbufsize,
  size_t aescbcmacdatasize, size_t totaldatasize, size_t aescbcmacsize,
  PS_AES_AlgoTypes algo, u8 keyslot);

Result PXIPS9_GetRomID(u8 (*out)[16]);

Result PXIPS9_GetRomID2(u8 (*out)[17]);

Result PXIPS9_GetCTRCardAutoStartupBit(u8* autobit);

Result PXIPS9_GetRomMakerCode(u8* makercode);

Result PXIPS9_GetLocalFriendCodeSeed(u64* friendcodeseed);

Result PXIPS9_GetDeviceId(u32* deviceid);

Result PXIPS9_SeedRNG(const void* seedbuf, size_t bufsize);

Result PXIPS9_GenerateRandomBytes(void* randbuf, size_t bufsize);

Result PXIPS9_GenerateAmiiboHMAC(void* hmac, size_t hmacsize,
  const void* data, size_t datasize);

Result PXIPS9_GenerateAmiiboKeyDataInternal(const void* data, size_t size, u8 flag);

Result PXIPS9_AmiiboEncryptDecrypt(const void* inbuf, void* outbuf, size_t size);

Result PXIPS9_AmiiboEncryptDecryptDev(const void* inbuf, void* outbuf, size_t size);
