#include <3ds/ipc.h>
#include <3ds/os.h>
#include <3ds/result.h>
#include <3ds/types.h>
#include <3ds/svc.h>
#include <3ds/srv.h>
#include <3ds/fs.h>
#include <3ds/mcupls.h>
#include <3ds/pxips9.h>
#include <ps.h>
#include <err.h>
#include <memops.h>

// v1025 -> v2049, rebuild, no significant service related changes

#define OS_REMOTE_SESSION_CLOSED MAKERESULT(RL_STATUS,    RS_CANCELED, RM_OS, 26)
#define OS_INVALID_HEADER        MAKERESULT(RL_PERMANENT, RS_WRONGARG, RM_OS, 47)
#define OS_INVALID_IPC_PARAMATER MAKERESULT(RL_PERMANENT, RS_WRONGARG, RM_OS, 48)

static __attribute__((section(".data.TerminationFlag"))) bool TerminationFlag = false;

// global control like this lets me have less code space used over constantly using osGetFirmVersion
u32 PSActiveVersion;

typedef struct {
	u8 static_buf1[0x300];
	// v3072 -> v4096, amiibo related bufs added
	u8 static_buf2[0x400]; // v4096 -> v5120, buffer size changed from 0x1C8 to 0x400
	u8 amiibo_hmac[0x20];
} ALIGN(8) IPC_WorkData;

inline static void HandleSRVNotification() {
	u32 id;
	Err_FailedThrow(srvReceiveNotification(&id));
	if (id == 0x100)
		TerminationFlag = true;
}

static Result PSIPC_SetAesKey(const u8 (*key)[16], u8 keyslot) {
	if (keyslot != 8) // only 8 was allowed, but returned false positive otherwise
		return 0;
	return PXIPS9_SetAesKey(key, keyslot);
}

static Result PSIPC_EncryptDecryptAES(const u8 (*iv_ctr_inbuf)[16], u8 (*iv_ctr_outbuf)[16],
  const void* inbuf, void* outbuf, size_t bufsize,
  PS_AES_AlgoTypes algo, u8 keyslot) {

	if (algo == CCM_Encrypt || algo == CCM_Decrypt)
		return PS_INVALID_SELECTION;
	if (algo == CBC_Encrypt || algo == CBC_Decrypt)
		bufsize &= ~0xF;

	return PXIPS9_EncryptDecryptAES(iv_ctr_inbuf, iv_ctr_outbuf, inbuf, outbuf, bufsize, algo, keyslot);
}

static Result PSIPC_EncryptSignDecryptVerifyAesCcm(const u8 (*nonce)[12],
  const void* inbuf, size_t inbufsize, void* outbuf, size_t outbufsize,
  size_t aescbcmacdatasize, size_t totaldatasize, size_t aescbcmacsize,
  PS_AES_AlgoTypes algo, u8 keyslot) {

	if (algo != CCM_Encrypt && algo != CCM_Decrypt)
		return PS_INVALID_SELECTION;
	if (aescbcmacdatasize & 0xF || aescbcmacsize & 0x1 || aescbcmacsize > 10)
		return PS_INVALID_SIZE;

	size_t _inbufsize = aescbcmacdatasize + totaldatasize;
	size_t _outbufsize = totaldatasize;

	if (algo == CCM_Encrypt) {
		_outbufsize += aescbcmacsize;
	} else {
		_inbufsize += aescbcmacsize;
	}

	// extra checks away from original PS binary, it didn't check against original buffer boundaries
	if (_inbufsize > inbufsize || _outbufsize > outbufsize) {
		return PS_INVALID_SIZE;
	}

	return PXIPS9_EncryptSignDecryptVerifyAesCcm(nonce, inbuf, _inbufsize, outbuf, _outbufsize, aescbcmacdatasize, totaldatasize, aescbcmacsize, algo, keyslot);
}

static Result PSIPC_GetRomID(u8 (*out)[16], u32 process_id) {
	FS_ProgramInfo info;

	if (R_FAILED(FSUSER_GetProgramLaunchInfo(&info, process_id)))
		return PS_NOT_FOUND;

	if ((u8)info.mediaType < (u8)MEDIATYPE_GAME_CARD)
		_memset(out, 0, sizeof(out));
	else
		Err_Panic(PXIPS9_GetRomID(out));
	return 0;
}

static Result PSIPC_GetRomID2(u8 (*out)[17], u32 process_id) {
	FS_ProgramInfo info;

	if (R_FAILED(FSUSER_GetProgramLaunchInfo(&info, process_id)))
		return PS_NOT_FOUND;

	if ((u8)info.mediaType < (u8)MEDIATYPE_GAME_CARD)
		_memset(out, 0, sizeof(out));
	else
		Err_Panic(PXIPS9_GetRomID2(out));
	return 0;
}

static Result PSIPC_GetRomMakerCode(u8* makercode, u32 process_id) {
	FS_ProgramInfo info;

	if (R_FAILED(FSUSER_GetProgramLaunchInfo(&info, process_id)))
		return PS_NOT_FOUND;

	if ((u8)info.mediaType < (u8)MEDIATYPE_GAME_CARD)
		*makercode = 0;
	else
		Err_Panic(PXIPS9_GetRomMakerCode(makercode));
	return 0;
}

static void PSIPC_SeedRNG() {
	ALIGN(8) u8 seedbuf[20];

	*(u64*)seedbuf = svcGetSystemTick();

	Err_Panic(MCUPLS_GetDatetime((u8(*)[7])&seedbuf[8]));

	u16 tick;
	Err_Panic(MCUPLS_GetTickCounter(&tick));

	seedbuf[15] = (u8)(tick & 0xFF);
	seedbuf[16] = (u8)(tick >> 8);

	// [17..19] left uninitialized, cause who knows, stack garbage is an RNG seeding source I suppose

	Err_Panic(PXIPS9_SeedRNG(seedbuf, sizeof(seedbuf)));
}

static void PSIPC_GenerateRandomBytes(void* rand, size_t size) {
	PSIPC_SeedRNG();
	Err_Panic(PXIPS9_GenerateRandomBytes(rand, size));
}

static void PS_IPCSession(IPC_WorkData* ipc_data) {
	u32* cmdbuf = getThreadCommandBuffer();

	u16 cmdid = cmdbuf[0] >> 16;

	if (PSActiveVersion < 4096 && cmdid >= 0xE) { // disable amiibo cmds before 8.0.0
		cmdbuf[0] = IPC_MakeHeader(0x0, 1, 0);
		cmdbuf[1] = OS_INVALID_HEADER;
		return;
	}

	switch (cmdid) {
	case 0x1:
		if (!IPC_CompareHeader(cmdbuf[0], 0x1, 9, 4) || !IPC_Is_Desc_StaticBufferId(cmdbuf[10], 0) || !IPC_Is_Desc_Buffer(cmdbuf[12], IPC_BUFFER_W)) {
			cmdbuf[0] = IPC_MakeHeader(0x0, 1, 0);
			cmdbuf[1] = OS_INVALID_IPC_PARAMATER;
		} else {
			const PS_RSA_Context *rsa = (PS_RSA_Context*)cmdbuf[11];
			void *outbuf = (void*)cmdbuf[13];

			size_t rsa_insize = IPC_Get_Desc_StaticBuffer_Size(cmdbuf[10]);

			if (rsa_insize < sizeof(PS_RSA_Context)) {
				// feature add compared to original binary
				// wipe whats not provided to disallow reuse of data leftover in static buf index 0
				_memset(&((u8*)rsa)[rsa_insize], 0, sizeof(PS_RSA_Context) - rsa_insize);
			}

			size_t outsize = IPC_Get_Desc_Buffer_Size(cmdbuf[12]);

			ALIGN(4) u8 sha256[32];
			_memcpy32_aligned(sha256, &cmdbuf[1], 32);

			cmdbuf[1] = PXIPS9_SignRsaSha256(rsa, sha256, outbuf, outsize);
			cmdbuf[0] = IPC_MakeHeader(0x1, 1, 2);
			cmdbuf[2] = IPC_Desc_Buffer(outsize, IPC_BUFFER_W);
			cmdbuf[3] = (u32)outbuf;
		}
		break;
	case 0x2:
		if (!IPC_CompareHeader(cmdbuf[0], 0x2, 9, 4) || !IPC_Is_Desc_StaticBufferId(cmdbuf[10], 0) || !IPC_Is_Desc_Buffer(cmdbuf[12], IPC_BUFFER_R)) {
			cmdbuf[0] = IPC_MakeHeader(0x0, 1, 0);
			cmdbuf[1] = OS_INVALID_IPC_PARAMATER;
		} else {
			const PS_RSA_Context *rsa = (PS_RSA_Context*)cmdbuf[11];
			void *inbuf = (void*)cmdbuf[13];

			size_t rsa_insize = IPC_Get_Desc_StaticBuffer_Size(cmdbuf[10]);

			if (rsa_insize < sizeof(PS_RSA_Context)) {
				// feature add compared to original binary
				// wipe whats not provided to disallow reuse of data leftover in static buf index 0
				_memset(&((u8*)rsa)[rsa_insize], 0, sizeof(PS_RSA_Context) - rsa_insize);
			}

			size_t insize = IPC_Get_Desc_Buffer_Size(cmdbuf[12]);

			ALIGN(4) u8 sha256[32];
			_memcpy32_aligned(sha256, &cmdbuf[1], 32);

			cmdbuf[1] = PXIPS9_VerifyRsaSha256(rsa, sha256, inbuf, insize);
			cmdbuf[0] = IPC_MakeHeader(0x2, 1, 2);
			cmdbuf[2] = IPC_Desc_Buffer(insize, IPC_BUFFER_R);
			cmdbuf[3] = (u32)inbuf;
		}
		break;
	case 0x3: // v0 -> v1025, no longer implemented
		if (PSActiveVersion != 0) {
			cmdbuf[1] = PS_NOT_IMPLEMENTED;
		} else {
			ALIGN(4) u8 key[16];
			_memcpy32_aligned(key, &cmdbuf[1], 16);

			cmdbuf[1] = PSIPC_SetAesKey(&key, (u8)cmdbuf[5]);
		}
		cmdbuf[0] = IPC_MakeHeader(0x3, 1, 0);
		break;
	case 0x4:
		if (!IPC_CompareHeader(cmdbuf[0], 0x4, 8, 4) || !IPC_Is_Desc_Buffer(cmdbuf[9], IPC_BUFFER_R) || !IPC_Is_Desc_Buffer(cmdbuf[11], IPC_BUFFER_W)) {
			cmdbuf[0] = IPC_MakeHeader(0x0, 1, 0);
			cmdbuf[1] = OS_INVALID_IPC_PARAMATER;
		} else {
			const void *inbuf = (void*)cmdbuf[10];
			void *outbuf = (void*)cmdbuf[12];

			size_t insize = IPC_Get_Desc_Buffer_Size(cmdbuf[9]);
			size_t outsize = IPC_Get_Desc_Buffer_Size(cmdbuf[11]);
			size_t size = (outsize < insize) ? outsize : insize; // original ps binary doesn't check this

			PS_AES_AlgoTypes algo = (PS_AES_AlgoTypes)(u8)cmdbuf[7];
			u8 keyslot = (u8)cmdbuf[8];

			ALIGN(4) u8 iv_ctr_inbuf[16];
			ALIGN(4) u8 iv_ctr_outbuf[16];
			_memcpy32_aligned(iv_ctr_inbuf, &cmdbuf[3], 16);

			cmdbuf[1] = PSIPC_EncryptDecryptAES(&iv_ctr_inbuf, &iv_ctr_outbuf, inbuf, outbuf, size, algo, keyslot);
			cmdbuf[0] = IPC_MakeHeader(0x4, 5, 4);
			_memcpy32_aligned(&cmdbuf[2], iv_ctr_outbuf, 16);
			cmdbuf[6] = IPC_Desc_Buffer(insize, IPC_BUFFER_R);
			cmdbuf[7] = (u32)inbuf;
			cmdbuf[8] = IPC_Desc_Buffer(outsize, IPC_BUFFER_W);
			cmdbuf[9] = (u32)outbuf;
		}
		break;
	case 0x5:
		if (!IPC_CompareHeader(cmdbuf[0], 0x5, 10, 4) || !IPC_Is_Desc_Buffer(cmdbuf[11], IPC_BUFFER_R) || !IPC_Is_Desc_Buffer(cmdbuf[13], IPC_BUFFER_W)) {
			cmdbuf[0] = IPC_MakeHeader(0x0, 1, 0);
			cmdbuf[1] = OS_INVALID_IPC_PARAMATER;
		} else {
			const void *inbuf = (void*)cmdbuf[12];
			void *outbuf = (void*)cmdbuf[14];

			size_t insize = IPC_Get_Desc_Buffer_Size(cmdbuf[11]);
			size_t outsize = IPC_Get_Desc_Buffer_Size(cmdbuf[13]);

			PS_AES_AlgoTypes algo = (PS_AES_AlgoTypes)(u8)cmdbuf[9];
			u8 keyslot = (u8)cmdbuf[10];

			size_t aescbcmacdatasize = cmdbuf[2];
			size_t totaldatasize = cmdbuf[3];
			size_t aescbcmacsize = cmdbuf[5];

			ALIGN(4) u8 nonce[12];
			_memcpy32_aligned(nonce, &cmdbuf[6], 12);

			cmdbuf[1] = PSIPC_EncryptSignDecryptVerifyAesCcm(&nonce, inbuf, insize, outbuf, outsize, aescbcmacdatasize, totaldatasize, aescbcmacsize, algo, keyslot);
			cmdbuf[0] = IPC_MakeHeader(0x5, 1, 4);
			cmdbuf[2] = IPC_Desc_Buffer(insize, IPC_BUFFER_R);
			cmdbuf[3] = (u32)inbuf;
			cmdbuf[4] = IPC_Desc_Buffer(outsize, IPC_BUFFER_W);
			cmdbuf[5] = (u32)outbuf;
		}
		break;
	case 0x6:
		{
			u8 id[16];
			cmdbuf[1] = PSIPC_GetRomID(&id, cmdbuf[1]);
			cmdbuf[0] = IPC_MakeHeader(0x6, 5, 0);
			_memcpy(&cmdbuf[2], id, sizeof(id));
		}
		break;
	case 0x7:
		{
			u8 id[17];
			cmdbuf[1] = PSIPC_GetRomID2(&id, cmdbuf[1]);
			cmdbuf[0] = IPC_MakeHeader(0x7, 6, 0);
			_memcpy(&cmdbuf[2], id, sizeof(id));
		}
		break;
	case 0x8:
		{
			u8 makercode;
			cmdbuf[1] = PSIPC_GetRomMakerCode(&makercode, cmdbuf[1]);
			cmdbuf[0] = IPC_MakeHeader(0x8, 2, 0);
			cmdbuf[2] = makercode;
		}
		break;
	case 0x9:
		{
			u8 autobit;
			Err_Panic(PXIPS9_GetCTRCardAutoStartupBit(&autobit));
			cmdbuf[0] = IPC_MakeHeader(0x9, 2, 0);
			cmdbuf[1] = 0;
			cmdbuf[2] = autobit;
		}
		break;
	case 0xA:
		{
			u64 lfcs;
			Err_Panic(PXIPS9_GetLocalFriendCodeSeed(&lfcs));
			cmdbuf[0] = IPC_MakeHeader(0xA, 3, 0);
			cmdbuf[1] = 0;
			cmdbuf[2] = (u32)(lfcs & 0xFFFFFFFF);
			cmdbuf[3] = (u32)(lfcs >> 32);
		}
		break;
	case 0xB:
		{
			u32 deviceid;
			Err_Panic(PXIPS9_GetDeviceId(&deviceid));
			cmdbuf[0] = IPC_MakeHeader(0xB, 2, 0);
			cmdbuf[1] = 0;
			cmdbuf[2] = deviceid;
		}
		break;
	case 0xC:
		PSIPC_SeedRNG();
		cmdbuf[0] = IPC_MakeHeader(0xC, 1, 0);
		cmdbuf[1] = 0;
		break;
	case 0xD:
		if (!IPC_CompareHeader(cmdbuf[0], 0xD, 1, 2) || !IPC_Is_Desc_Buffer(cmdbuf[2], IPC_BUFFER_W)) {
			cmdbuf[0] = IPC_MakeHeader(0x0, 1, 0);
			cmdbuf[1] = OS_INVALID_IPC_PARAMATER;
		} else {
			void *buf = (void*)cmdbuf[3];
			size_t size = IPC_Get_Desc_Buffer_Size(cmdbuf[2]);
			PSIPC_GenerateRandomBytes(buf, size);
			cmdbuf[0] = IPC_MakeHeader(0xD, 1, 2);
			cmdbuf[1] = 0;
			cmdbuf[2] = IPC_Desc_Buffer(size, IPC_BUFFER_W);
			cmdbuf[3] = (u32)buf;
		}
		break;
		// v3072 -> v4096, n3ds amiibo related commands added
	case 0xE:
		if (!IPC_CompareHeader(cmdbuf[0], 0xE, 2, 2) || !IPC_Is_Desc_StaticBufferId(cmdbuf[3], 1)) {
			cmdbuf[0] = IPC_MakeHeader(0x0, 1, 0);
			cmdbuf[1] = OS_INVALID_IPC_PARAMATER;
		} else {
			void *buf = (void*)cmdbuf[4];
			size_t bufsize = IPC_Get_Desc_StaticBuffer_Size(cmdbuf[3]);
			size_t hmacsize = sizeof(ipc_data->amiibo_hmac);
			hmacsize = (cmdbuf[2] > hmacsize) ? hmacsize : cmdbuf[2];
			cmdbuf[1] = PXIPS9_GenerateAmiiboHMAC(ipc_data->amiibo_hmac, hmacsize, buf, bufsize);
			cmdbuf[0] = IPC_MakeHeader(0xE, 1, 2);
			cmdbuf[2] = IPC_Desc_StaticBuffer(hmacsize, 0);
			cmdbuf[3] = (u32)buf;
		}
		break;
	case 0xF:
		if (!IPC_CompareHeader(cmdbuf[0], 0xF, 2, 2) || !IPC_Is_Desc_StaticBufferId(cmdbuf[3], 1)) {
			cmdbuf[0] = IPC_MakeHeader(0x0, 1, 0);
			cmdbuf[1] = OS_INVALID_IPC_PARAMATER;
		} else {
			void *buf = (void*)cmdbuf[4];
			size_t bufsize = IPC_Get_Desc_StaticBuffer_Size(cmdbuf[3]);
			cmdbuf[1] = PXIPS9_GenerateAmiiboKeyDataInternal(buf, bufsize, cmdbuf[2]);
			cmdbuf[0] = IPC_MakeHeader(0xF, 1, 0);
		}
		break;
	case 0x10:
		if (!IPC_CompareHeader(cmdbuf[0], 0x10, 1, 2) || !IPC_Is_Desc_StaticBufferId(cmdbuf[2], 1)) {
			cmdbuf[0] = IPC_MakeHeader(0x0, 1, 0);
			cmdbuf[1] = OS_INVALID_IPC_PARAMATER;
		} else {
			void *buf = (void*)cmdbuf[3];
			size_t bufsize = IPC_Get_Desc_StaticBuffer_Size(cmdbuf[2]);
			cmdbuf[1] = PXIPS9_AmiiboEncryptDecrypt(buf, buf, bufsize);
			cmdbuf[0] = IPC_MakeHeader(0x10, 1, 2);
			cmdbuf[2] = IPC_Desc_StaticBuffer(bufsize, 0);
			cmdbuf[3] = (u32)buf;
		}
		break;
	case 0x11:
		if (!IPC_CompareHeader(cmdbuf[0], 0x11, 1, 2) || !IPC_Is_Desc_StaticBufferId(cmdbuf[2], 1)) {
			cmdbuf[0] = IPC_MakeHeader(0x0, 1, 0);
			cmdbuf[1] = OS_INVALID_IPC_PARAMATER;
		} else {
			void *buf = (void*)cmdbuf[3];
			size_t bufsize = IPC_Get_Desc_StaticBuffer_Size(cmdbuf[2]);
			cmdbuf[1] = PXIPS9_AmiiboEncryptDecryptDev(buf, buf, bufsize);
			cmdbuf[0] = IPC_MakeHeader(0x11, 1, 2);
			cmdbuf[2] = IPC_Desc_StaticBuffer(bufsize, 0);
			cmdbuf[3] = (u32)buf;
		}
		break;
	#if defined PS_CUSTOM_COMMAND && PS_CUSTOM_COMMAND == 1
	case 0x401:
		if (!IPC_CompareHeader(cmdbuf[0], 0x401, 0, 6) || !IPC_Is_Desc_StaticBufferId(cmdbuf[1], 0) || !IPC_Is_Desc_Buffer(cmdbuf[3], IPC_BUFFER_R) || !IPC_Is_Desc_Buffer(cmdbuf[5], IPC_BUFFER_W)) {
			cmdbuf[0] = IPC_MakeHeader(0x0, 1, 0);
			cmdbuf[1] = OS_INVALID_IPC_PARAMATER;
		} else {
			const PS_RSA_Context *rsa = (PS_RSA_Context*)cmdbuf[2];
			void *inbuf = (void*)cmdbuf[4];
			void *outbuf = (void*)cmdbuf[6];

			size_t rsa_insize = IPC_Get_Desc_StaticBuffer_Size(cmdbuf[1]);

			if (rsa_insize < sizeof(PS_RSA_Context)) {
				// wipe whats not provided to disallow reuse of data leftover in static buf index 0
				_memset(&((u8*)rsa)[rsa_insize], 0, sizeof(PS_RSA_Context) - rsa_insize);
			}

			size_t insize = IPC_Get_Desc_Buffer_Size(cmdbuf[3]);
			size_t outsize = IPC_Get_Desc_Buffer_Size(cmdbuf[5]);

			cmdbuf[1] = PXIPS9_CryptRsa(rsa, inbuf, outbuf, insize < outsize ? insize : outsize);
			cmdbuf[0] = IPC_MakeHeader(0x401, 1, 4);
			cmdbuf[2] = IPC_Desc_Buffer(insize, IPC_BUFFER_R);
			cmdbuf[3] = (u32)inbuf;
			cmdbuf[4] = IPC_Desc_Buffer(outsize, IPC_BUFFER_W);
			cmdbuf[5] = (u32)outbuf;
		}
		break;
	#endif
	default:
		cmdbuf[0] = IPC_MakeHeader(0x0, 1, 0);
		cmdbuf[1] = OS_INVALID_HEADER;
	}
}

static inline void initBSS() {
	extern void* __bss_start__;
	extern void* __bss_end__;
	_memset32_aligned(__bss_start__, 0, (size_t)__bss_end__ - (size_t)__bss_start__);
}

static inline void determinePSVersion() {
	u32 osfirmver = osGetFirmVersion();
	if (osfirmver < SYS_2_0_0) {
		PSActiveVersion = 0;
	} else if (osfirmver < SYS_6_0_0) {
		PSActiveVersion = 1025; // v2049 is the same in functionality, so we go lowest here
	} else if (osfirmver < SYS_8_0_0) {
		PSActiveVersion = 3072;
	} else if (osfirmver < SYS_9_0_0) {
		PSActiveVersion = 4096;
	} else {
		PSActiveVersion = 5120;
	}
}

void PSMain() {
	initBSS();
	determinePSVersion();

	const s32 SERVICE_COUNT = 1;
	const s32 INDEX_MAX = 22;
	const s32 REMOTE_SESSION_INDEX = SERVICE_COUNT + 1;

	Handle session_handles[22];

	s32 handle_count = SERVICE_COUNT + 1;

	Err_FailedThrow(srvInit());
	Err_FailedThrow(fsInit());
	Err_Panic(mcuPlsInit());
	Err_Panic(pxiPs9Init());

	Err_FailedThrow(srvRegisterService(&session_handles[1], "ps:ps", 20)); // original service says 9, but has space for 20, so we'll do the amount of space it had for

	Err_FailedThrow(srvEnableNotification(&session_handles[0]));

	IPC_WorkData ipc_data;

	u32* statbuf = getThreadStaticBuffers();
	statbuf[0] = IPC_Desc_StaticBuffer(sizeof(ipc_data.static_buf1), 0);
	statbuf[1] = (u32)&ipc_data.static_buf1[0];
	if (PSActiveVersion >= 4096) {
		statbuf[2] = IPC_Desc_StaticBuffer((PSActiveVersion >= 5120) ? sizeof(ipc_data.static_buf2) : 0x1C8, 0);
		statbuf[3] = (u32)&ipc_data.static_buf2[0];
	}

	Handle target = 0;
	s32 target_index = -1;
	for (;;) {
		s32 index;

		if (!target) {
			if (TerminationFlag && handle_count == REMOTE_SESSION_INDEX)
				break;
			else
				*getThreadCommandBuffer() = 0xFFFF0000;
		}

		Result res = svcReplyAndReceive(&index, session_handles, handle_count, target);
		s32 last_target_index = target_index;
		target = 0;
		target_index = -1;

		if (R_FAILED(res)) {

			if (res != OS_REMOTE_SESSION_CLOSED)
				Err_Throw(res);

			else if (index == -1) {
				if (last_target_index == -1)
					Err_Throw(PS_CANCELED_RANGE);
				else
					index = last_target_index;
			}

			else if (index >= handle_count)
				Err_Throw(PS_CANCELED_RANGE);

			svcCloseHandle(session_handles[index]);

			handle_count--;
			for (s32 i = index - REMOTE_SESSION_INDEX; i < handle_count - REMOTE_SESSION_INDEX; i++) {
				session_handles[REMOTE_SESSION_INDEX + i] = session_handles[REMOTE_SESSION_INDEX + i + 1];
			}

			continue;
		}

		if (index == 0)
			HandleSRVNotification();

		else if (index == 1) {
			Handle newsession = 0;
			Err_FailedThrow(svcAcceptSession(&newsession, session_handles[index]));

			if (handle_count >= INDEX_MAX) {
				svcCloseHandle(newsession);
				continue;
			}

			session_handles[handle_count] = newsession;
			handle_count++;

		} else if (index >= REMOTE_SESSION_INDEX && index < INDEX_MAX) {
			PS_IPCSession(&ipc_data);
			target = session_handles[index];
			target_index = index;
		} else {
			Err_Throw(PS_INTERNAL_RANGE);
		}
	}

	Err_FailedThrow(srvUnregisterService("ps:ps"));
	svcCloseHandle(session_handles[1]);

	svcCloseHandle(session_handles[0]);

	pxiPs9Exit();
	mcuPlsExit();
	fsExit();
	srvExit();
}
