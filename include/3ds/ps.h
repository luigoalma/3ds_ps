#pragma once

#include <3ds/types.h>

typedef struct {
	u8 mod[0x100];
	u8 exp[0x100];
	s32 rsa_bit_size;
	u8 is_priv_exp; // 1 if private exp, 0 otherwise
	u8 padding[3];
} PS_RSA_Context;

typedef enum {
	CBC_Encrypt = 0,
	CBC_Decrypt = 1,
	CTR_Encrypt = 2,
	CTR_Decrypt = 3,
	CCM_Encrypt = 4,
	CCM_Decrypt = 5
} PS_AES_AlgoTypes;
