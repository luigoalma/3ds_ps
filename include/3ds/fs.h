/**
 * @file fs.h
 * @brief Filesystem Services
 */
#pragma once

#include <3ds/types.h>

/// Media types.
typedef enum
{
	MEDIATYPE_NAND      = 0, ///< NAND.
	MEDIATYPE_SD        = 1, ///< SD card.
	MEDIATYPE_GAME_CARD = 2, ///< Game card.
} FS_MediaType;

/// Program information.
typedef struct
{
	u64 programId;              ///< Program ID.
	FS_MediaType mediaType : 8; ///< Media type.
	u8 padding[7];              ///< Padding.
} FS_ProgramInfo;

/// Initializes FS.
Result fsInit(void);

/// Exits FS.
void fsExit(void);

/**
 * @brief Initializes a FSUSER session.
 * @param session The handle of the FSUSER session to initialize.
 */
Result FSUSER_Initialize(Handle session);

/**
 * @brief Gets a process's program launch info.
 * @param info Pointer to output the program launch info to.
 * @param processId ID of the process.
 */
Result FSUSER_GetProgramLaunchInfo(FS_ProgramInfo* info, u32 processId);
