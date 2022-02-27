#include <3ds.h>

// custom command info

Result PS_CustomCryptRsa(const PS_RSA_Context *ctx, const u8 *inbuf, u8 *outbuf)
{
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();
	u32 size;

	size = ctx->rsa_bit_size>>3;

	cmdbuf[0] = IPC_MakeHeader(0x401,0,6); // 0x4010006
	cmdbuf[1] = IPC_Desc_StaticBuffer(sizeof(*ctx), 0);
	cmdbuf[2] = (u32)ctx;
	cmdbuf[3] = IPC_Desc_Buffer(size, IPC_BUFFER_R);
	cmdbuf[4] = (u32)inbuf;
	cmdbuf[5] = IPC_Desc_Buffer(size, IPC_BUFFER_W);
	cmdbuf[6] = (u32)outbuf;

	if(R_FAILED(ret = svcSendSyncRequest(psGetSessionHandle()))) return ret;

	return (Result)cmdbuf[1];
}
