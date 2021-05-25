#pragma once

Result mcuPlsInit(void);

void mcuPlsExit(void);

Result MCUPLS_GetDatetime(u8 (*out)[7]);

Result MCUPLS_GetTickCounter(u16* out);
