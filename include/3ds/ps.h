#pragma once

#include <3ds/types.h>

typedef struct {
	u8 mod[0x100];
	union {
		u32 small_exp; // = this member if is_full_exponent is 0, e.g. = 0x10001
		u8 exp[0x100]; // memcpy big endian number to this member if is_full_exponent is 1
	};
	s32 rsa_bit_size;
	u8 is_full_exponent; // 1 if big endian full exponent, 0 if small 4 byte little endian exponent
	u8 padding[3];
} PS_RSA_Context;

_Static_assert(sizeof(PS_RSA_Context) == 0x208, "Invalid PS_RSA_Context size compiled");

typedef enum {
	CBC_Encrypt = 0,
	CBC_Decrypt = 1,
	CTR_Encrypt = 2,
	CTR_Decrypt = 3,
	CCM_Encrypt = 4,
	CCM_Decrypt = 5
} PS_AES_AlgoTypes;
