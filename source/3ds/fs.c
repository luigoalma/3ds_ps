#include <3ds/types.h>
#include <3ds/result.h>
#include <3ds/svc.h>
#include <3ds/srv.h>
#include <3ds/fs.h>
#include <3ds/ipc.h>
#include <memops.h>

static Handle fsuHandle;
static int fsuRefCount;

Result fsInit(void)
{
	Result ret = 0;

	if (fsuRefCount++) return 0;

	ret = srvGetServiceHandle(&fsuHandle, "fs:USER");
	if (R_SUCCEEDED(ret))
	{
		ret = FSUSER_Initialize(fsuHandle);
		if (R_FAILED(ret)) svcCloseHandle(fsuHandle);
	}

	if (R_FAILED(ret)) --fsuRefCount;
	return ret;
}

void fsExit(void)
{
	if (--fsuRefCount) return;
	svcCloseHandle(fsuHandle);
}

Result FSUSER_Initialize(Handle session)
{
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x801,0,2); // 0x8010002
	cmdbuf[1] = IPC_Desc_CurProcessId();

	Result ret = 0;
	if(R_FAILED(ret = svcSendSyncRequest(session))) return ret;

	return cmdbuf[1];
}

Result FSUSER_GetProgramLaunchInfo(FS_ProgramInfo* info, u32 processId)
{
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x82F,1,0); // 0x82F0040
	cmdbuf[1] = processId;

	Result ret = 0;
	if(R_FAILED(ret = svcSendSyncRequest(fsuHandle))) return ret;

	if(info) _memcpy(info, &cmdbuf[2], sizeof(FS_ProgramInfo));

	return cmdbuf[1];
}
