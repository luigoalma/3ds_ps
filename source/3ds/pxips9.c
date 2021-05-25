#include <3ds/types.h>
#include <3ds/svc.h>
#include <3ds/ipc.h>
#include <3ds/result.h>
#include <3ds/srv.h>
#include <3ds/os.h>
#include <3ds/pxips9.h>
#include <ps.h>
#include <memops.h>

static Handle pxiPs9Handle;
static int pxiPs9RefCount;

#define SET_READONLY (PSActiveVersion >= 3072)
#define IS_PRE_2_0_0 (PSActiveVersion == 0)

Result pxiPs9Init(void)
{
	if (pxiPs9RefCount++) return 0;
	Result res = srvGetServiceHandle(&pxiPs9Handle, "pxi:ps9");
	if (R_FAILED(res)) --pxiPs9RefCount;
	return res;
}

void pxiPs9Exit(void)
{
	if (--pxiPs9RefCount) return;
	svcCloseHandle(pxiPs9Handle);
}

// does it really take a PS_RSA_Context?
// or maybe takes an object similar to PS_RSA_Context?
// cause how are you gonna sign with a mod and public exponent?
// it should just not work!
// unless its an object sized like a PS_RSA_Context, but its not the same
// wouldn't know by just writing code and reversing PS alone, need to run in a real world test example
Result PXIPS9_SignRsaSha256(const PS_RSA_Context* rsa, const void* sha256, void* sigbuf, size_t sigbuf_size) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0]  = IPC_MakeHeader(0x2,10,4); // 0x20284
	_memcpy(&cmdbuf[1], sha256, 32);
	cmdbuf[9]  = (sigbuf_size < (u32)(rsa->rsa_bit_size >> 3)) ? sigbuf_size : (u32)(rsa->rsa_bit_size >> 3);
	cmdbuf[10] = sizeof(PS_RSA_Context);
	cmdbuf[11] = IPC_Desc_PXIBuffer(sizeof(PS_RSA_Context), 0, SET_READONLY); // v2049 -> v3072, became read-only!! before it was false
	cmdbuf[12] = (u32)rsa;
	cmdbuf[13] = IPC_Desc_PXIBuffer(cmdbuf[9], 1, false);
	cmdbuf[14] = (u32)sigbuf;

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	return (Result)cmdbuf[1];
}

Result PXIPS9_VerifyRsaSha256(const PS_RSA_Context* rsa, const void* sha256, const void* sigbuf, size_t sigbuf_size) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0]  = IPC_MakeHeader(0x3,10,4); // 0x30284
	_memcpy(&cmdbuf[1], sha256, 32);
	cmdbuf[9]  = (sigbuf_size < (u32)(rsa->rsa_bit_size >> 3)) ? sigbuf_size : (u32)(rsa->rsa_bit_size >> 3);
	cmdbuf[10] = sizeof(PS_RSA_Context);
	cmdbuf[11] = IPC_Desc_PXIBuffer(cmdbuf[9], 0, SET_READONLY); // v2049 -> v3072, became read-only!! before it was false
	cmdbuf[12] = (u32)sigbuf;
	cmdbuf[13] = IPC_Desc_PXIBuffer(sizeof(PS_RSA_Context), 1, SET_READONLY); // v2049 -> v3072, became read-only!! before it was false
	cmdbuf[14] = (u32)rsa;

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	return (Result)cmdbuf[1];
}

Result PXIPS9_SetAesKey(const u8 (*key)[16], u8 keyslot) {

	if (!IS_PRE_2_0_0) {
		return PS_NOT_IMPLEMENTED;
	}

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x4,5,0); // 0x40140
	_memcpy(&cmdbuf[1], key, sizeof(*key));
	cmdbuf[5] = keyslot; // maybe, sounds likely

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	return (Result)cmdbuf[1];
}

// I know PXI services are reserved for modules to use, but good lord, why a cmd id change

Result PXIPS9_EncryptDecryptAES(const u8 (*iv_ctr_inbuf)[16], u8 (*iv_ctr_outbuf)[16],
  const void* inbuf, void* outbuf, size_t bufsize,
  PS_AES_AlgoTypes algo, u8 keyslot) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0]  = IPC_MakeHeader(IS_PRE_2_0_0 ? 0x5 : 0x4,7,4); // sys < 2.0.0 0x501C4 else 0x401C4
	cmdbuf[1]  = bufsize;
	_memcpy(&cmdbuf[2], iv_ctr_inbuf, sizeof(*iv_ctr_inbuf));
	cmdbuf[6]  = (u32)algo;
	cmdbuf[7]  = keyslot;
	cmdbuf[8]  = IPC_Desc_PXIBuffer(bufsize, 0, SET_READONLY); // v2049 -> v3072, became read-only!! before it was false
	cmdbuf[9]  = (u32)inbuf;
	cmdbuf[10] = IPC_Desc_PXIBuffer(bufsize, 1, false);
	cmdbuf[11] = (u32)outbuf;

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	if (iv_ctr_outbuf) {
		_memcpy(iv_ctr_outbuf, &cmdbuf[2], sizeof(*iv_ctr_outbuf));
	}

	return (Result)cmdbuf[1];
}

// 3dbrew, what are these long ass names?? I mean I see *why*, but hot damn
Result PXIPS9_EncryptSignDecryptVerifyAesCcm(const u8 (*nonce)[12],
  const void* inbuf, size_t inbufsize, void* outbuf, size_t outbufsize,
  size_t aescbcmacdatasize, size_t totaldatasize, size_t aescbcmacsize,
  PS_AES_AlgoTypes algo, u8 keyslot) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0]  = IPC_MakeHeader(IS_PRE_2_0_0 ? 0x6 : 0x5,10,4); // sys < 2.0.0 0x60284 else 0x50284
	cmdbuf[1]  = inbufsize;
	cmdbuf[2]  = outbufsize;
	cmdbuf[3]  = aescbcmacdatasize;
	cmdbuf[4]  = totaldatasize;
	cmdbuf[5]  = aescbcmacsize;
	_memcpy(&cmdbuf[6], nonce, sizeof(*nonce));
	cmdbuf[9]  = (u32)algo;
	cmdbuf[10] = keyslot;
	cmdbuf[11] = IPC_Desc_PXIBuffer(inbufsize, 0, SET_READONLY); // v2049 -> v3072, became read-only!! before it was false
	cmdbuf[12] = (u32)inbuf;
	cmdbuf[13] = IPC_Desc_PXIBuffer(outbufsize, 1, false);
	cmdbuf[14] = (u32)outbuf;

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	return (Result)cmdbuf[1];
}

Result PXIPS9_GetRomID(u8 (*out)[16]) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(IS_PRE_2_0_0 ? 0x7 : 0x6,0,0); // sys < 2.0.0 0x70000 else 0x60000

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	if (out) {
		_memcpy(out, &cmdbuf[2], sizeof(*out));
	}

	return (Result)cmdbuf[1];
}

Result PXIPS9_GetRomID2(u8 (*out)[17]) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(IS_PRE_2_0_0 ? 0x8 : 0x7,0,0); // sys < 2.0.0 0x80000 else 0x70000

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	if (out) {
		_memcpy(out, &cmdbuf[2], sizeof(*out));
	}

	return (Result)cmdbuf[1];
}

Result PXIPS9_GetCTRCardAutoStartupBit(u8* autobit) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(IS_PRE_2_0_0 ? 0x9 : 0x8,0,0); // sys < 2.0.0 0x90000 else 0x80000

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	if (autobit) *autobit = (u8)cmdbuf[2];

	return (Result)cmdbuf[1];
}

Result PXIPS9_GetRomMakerCode(u8* makercode) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(IS_PRE_2_0_0 ? 0xA : 0x9,0,0); // sys < 2.0.0 0xA0000 else 0x90000

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	if (makercode) *makercode = (u8)cmdbuf[2];

	return (Result)cmdbuf[1];
}

Result PXIPS9_GetLocalFriendCodeSeed(u64* friendcodeseed) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(IS_PRE_2_0_0 ? 0xB : 0xA,0,0); // sys < 2.0.0 0xB0000 else 0xA0000

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	if (friendcodeseed) *friendcodeseed = (((u64)cmdbuf[3]) << 32) | cmdbuf[2];

	return (Result)cmdbuf[1];
}

Result PXIPS9_GetDeviceId(u32* deviceid) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(IS_PRE_2_0_0 ? 0xC : 0xB,0,0); // sys < 2.0.0 0xC0000 else 0xB0000

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	if (deviceid) *deviceid = cmdbuf[2];

	return (Result)cmdbuf[1];
}

Result PXIPS9_SeedRNG(const void* seedbuf, size_t bufsize) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(IS_PRE_2_0_0 ? 0xD : 0xC,1,2); // sys < 2.0.0 0xD0042 else 0xC0042
	cmdbuf[1] = bufsize;
	cmdbuf[2] = IPC_Desc_PXIBuffer(bufsize, 0, SET_READONLY); // v2049 -> v3072, became read-only!! before it was false
	cmdbuf[3] = (u32)seedbuf;

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	return (Result)cmdbuf[1];
}

Result PXIPS9_GenerateRandomBytes(void* randbuf, size_t bufsize) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(IS_PRE_2_0_0 ? 0xE : 0xD,1,2); // sys < 2.0.0 0xE0042 else 0xD0042
	cmdbuf[1] = bufsize;
	cmdbuf[2] = IPC_Desc_PXIBuffer(bufsize, 0, false);
	cmdbuf[3] = (u32)randbuf;

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	return (Result)cmdbuf[1];
}

Result PXIPS9_GenerateAmiiboHMAC(void* hmac, size_t hmacsize,
  const void* data, size_t datasize) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x401,2,4); // 0x4010084
	cmdbuf[1] = datasize;
	cmdbuf[2] = hmacsize;
	cmdbuf[3] = IPC_Desc_PXIBuffer(datasize, 0, true);
	cmdbuf[4] = (u32)data;
	cmdbuf[5] = IPC_Desc_PXIBuffer(hmacsize, 1, false);
	cmdbuf[6] = (u32)hmac;

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	return (Result)cmdbuf[1];
}

Result PXIPS9_GenerateAmiiboKeyDataInternal(const void* data, size_t size, u8 flag) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x402,2,2); // 0x4020082
	cmdbuf[1] = size;
	cmdbuf[2] = flag;
	cmdbuf[3] = IPC_Desc_PXIBuffer(size, 0, true);
	cmdbuf[4] = (u32)data;

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	return (Result)cmdbuf[1];
}

Result PXIPS9_AmiiboEncryptDecrypt(const void* inbuf, void* outbuf, size_t size) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x403,1,4); // 0x4030044
	cmdbuf[1] = size;
	cmdbuf[2] = IPC_Desc_PXIBuffer(size, 0, true);
	cmdbuf[3] = (u32)inbuf;
	cmdbuf[4] = IPC_Desc_PXIBuffer(size, 1, false);
	cmdbuf[5] = (u32)outbuf;

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	return (Result)cmdbuf[1];
}

Result PXIPS9_AmiiboEncryptDecryptDev(const void* inbuf, void* outbuf, size_t size) {

	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x404,1,4); // 0x4040044
	cmdbuf[1] = size;
	cmdbuf[2] = IPC_Desc_PXIBuffer(size, 0, true);
	cmdbuf[3] = (u32)inbuf;
	cmdbuf[4] = IPC_Desc_PXIBuffer(size, 1, false);
	cmdbuf[5] = (u32)outbuf;

	if(R_FAILED(res = svcSendSyncRequest(pxiPs9Handle)))
		return res;

	return (Result)cmdbuf[1];
}
