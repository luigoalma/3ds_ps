#pragma once
#include <3ds/types.h>
#include <3ds/os.h>
#include <3ds/result.h>

// Result values
#define PS_NOT_FOUND         MAKERESULT(RL_STATUS, RS_WRONGARG, RM_PS, RD_NOT_FOUND)
#define PS_NOT_IMPLEMENTED   MAKERESULT(RL_PERMANENT, RS_NOTSUPPORTED, RM_PS, RD_NOT_IMPLEMENTED)
#define PS_INVALID_SELECTION MAKERESULT(RL_STATUS, RS_WRONGARG, RM_PS, RD_INVALID_SELECTION)
#define PS_INVALID_SIZE      MAKERESULT(RL_STATUS, RS_WRONGARG, RM_PS, RD_INVALID_SIZE)

// Result values, my additions edition:tm:
#define PS_INTERNAL_RANGE    MAKERESULT(RL_FATAL, RS_INTERNAL, RM_PS, RD_OUT_OF_RANGE)
#define PS_CANCELED_RANGE    MAKERESULT(RL_FATAL, RS_CANCELED, RM_PS, RD_OUT_OF_RANGE)

// version checks
#define SYS_2_0_0            SYSTEM_VERSION(2, 29, 7)
#define SYS_6_0_0            SYSTEM_VERSION(2, 37, 0)
#define SYS_8_0_0            SYSTEM_VERSION(2, 44, 6)
#define SYS_9_0_0            SYSTEM_VERSION(2, 46, 0)

// what version are we actively acting as, depending on firmware version we supposedly in
extern u32 PSActiveVersion;
