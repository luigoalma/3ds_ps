#include <3ds/types.h>
#include <3ds/svc.h>
#include <3ds/ipc.h>
#include <3ds/result.h>
#include <3ds/srv.h>
#include <3ds/mcupls.h>
#include <memops.h>

static Handle mcuPlsHandle;
static int mcuPlsRefCount;

Result mcuPlsInit(void)
{
	if (mcuPlsRefCount++) return 0;
	Result res = srvGetServiceHandle(&mcuPlsHandle, "mcu::PLS");
	if (R_FAILED(res)) --mcuPlsRefCount;
	return res;
}

void mcuPlsExit(void)
{
	if (--mcuPlsRefCount) return;
	svcCloseHandle(mcuPlsHandle);
}

Result MCUPLS_GetDatetime(u8 (*out)[7]) {
	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x1,0,0); // 0x10000

	if(R_FAILED(res = svcSendSyncRequest(mcuPlsHandle)))
		return res;

	if (out) {
		_memcpy(out, &cmdbuf[2], sizeof(*out));
	}

	return (Result)cmdbuf[1];
}

Result MCUPLS_GetTickCounter(u16* out) {
	Result res = 0;
	u32* cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x9,0,0); // 0x90000

	if(R_FAILED(res = svcSendSyncRequest(mcuPlsHandle)))
		return res;

	if (out) *out = (u16)cmdbuf[2];

	return (Result)cmdbuf[1];
}
