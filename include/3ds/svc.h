/**
 * @file svc.h
 * @brief Syscall wrappers.
 */
#pragma once

#include "types.h"

/// Reasons for a user break.
typedef enum {
	USERBREAK_PANIC         = 0, ///< Panic.
	USERBREAK_ASSERT        = 1, ///< Assertion failed.
	USERBREAK_USER          = 2, ///< User related.
	USERBREAK_LOAD_RO       = 3, ///< Load RO.
	USERBREAK_UNLOAD_RO     = 4, ///< Unload RO.
} UserBreakType;

/**
 * @brief Gets the thread local storage buffer.
 * @return The thread local storage bufger.
 */
static inline void* getThreadLocalStorage(void)
{
	void* ret;
	__asm__ ("mrc p15, 0, %[data], c13, c0, 3" : [data] "=r" (ret));
	return ret;
}

/**
 * @brief Gets the thread command buffer.
 * @return The thread command bufger.
 */
static inline u32* getThreadCommandBuffer(void)
{
	return (u32*)((u8*)getThreadLocalStorage() + 0x80);
}

/**
 * @brief Gets the thread static buffer.
 * @return The thread static bufger.
 */
static inline u32* getThreadStaticBuffers(void)
{
	return (u32*)((u8*)getThreadLocalStorage() + 0x180);
}

/**
 * @brief Gets the ID of a process.
 * @param[out] out Pointer to output the process ID to.
 * @param handle Handle of the process to get the ID of.
 */
static inline Result svcGetProcessId(u32 *out, Handle handle) {
	register const Handle _handle __asm__("r1") = handle;

	register Result res __asm__("r0");
	register Handle out_handle __asm__("r1");

	__asm__ volatile ("svc\t0x35" : "=r"(res), "=r"(out_handle) : "r"(_handle) : "r2", "r3", "r12");

	*out = out_handle;

	return res;
}

/**
 * @brief Connects to a port.
 * @param[out] out Pointer to output the port handle to.
 * @param portName Name of the port.
 */
static inline Result svcConnectToPort(volatile Handle* out, const char* portName) {
	register const char* _portName __asm__("r1") = portName;

	register Result res __asm__("r0");
	register Handle out_handle __asm__("r1");

	__asm__ volatile ("svc\t0x2D" : "=r"(res), "=r"(out_handle) : "r"(_portName) : "r2", "r3", "r12", "memory");

	*out = out_handle;

	return res;
}

/**
 * @brief Puts the current thread to sleep.
 * @param ns The minimum number of nanoseconds to sleep for.
 */
static inline void svcSleepThread(s64 ns) {
	register u32 lo_ns __asm__("r0") = (u32)(((u64)ns) & ((u32)~0));
	register u32 hi_ns __asm__("r1") = (u32)(((u64)ns) >> 32);

	__asm__ volatile ("svc\t0x0A" : "+r"(lo_ns), "+r"(hi_ns) : : "r2", "r3", "r12");
}

/**
 * @brief Sends a synchronized request to a session handle.
 * @param session Handle of the session.
 */
static inline Result svcSendSyncRequest(Handle session) {
	register const Handle _handle __asm__("r0") = session;

	register Result res __asm__("r0");

	__asm__ volatile ("svc\t0x32" : "=r"(res) : "r"(_handle) : "r1", "r2", "r3", "r12", "memory");

	return res;
}

/**
 * @brief Accepts a session.
 * @param[out] session Pointer to output the created session handle to.
 * @param port Handle of the port to accept a session from.
 */
static inline Result svcAcceptSession(Handle* session, Handle port) {
	register const Handle _port __asm__("r1") = port;

	register Result res __asm__("r0");
	register Handle out_handle __asm__("r1");

	__asm__ volatile ("svc\t0x4A" : "=r"(res), "=r"(out_handle) : "r"(_port) : "r2", "r3", "r12");

	*session = out_handle;

	return res;
}

/**
 * @brief Replies to and receives a new request.
 * @param index Pointer to the index of the request.
 * @param handles Session handles to receive requests from.
 * @param handleCount Number of handles.
 * @param replyTarget Handle of the session to reply to.
 */
static inline Result svcReplyAndReceive(s32* index, const Handle* handles, s32 handleCount, Handle replyTarget) {
	register const Handle* _handles __asm__("r1") = handles;
	register s32 _handleCount __asm__("r2") = handleCount;
	register Handle _replyTarget __asm__("r3") = replyTarget;

	register s32 _out_index __asm__("r1");
	register Result res __asm__("r0");

	__asm__ volatile ("svc\t0x4F" : "=r"(res), "=r"(_out_index), "+r"(_handleCount), "+r"(_replyTarget) : "r"(_handles) : "r12", "memory");

	*index = _out_index;

	return res;
}

/**
 * @brief Gets the current system tick.
 * @return The current system tick.
 */
static inline u64    svcGetSystemTick(void) {
	register u32 lo_tick __asm__("r0");
	register u32 hi_tick __asm__("r1");

	__asm__ volatile ("svc\t0x28" : "=r"(lo_tick), "=r"(hi_tick) : : "r2", "r3", "r12");

    return (((u64)hi_tick) << 32) | lo_tick;
}

/**
 * @brief Closes a handle.
 * @param handle Handle to close.
 */
static inline Result svcCloseHandle(Handle handle) {
	register const Handle _handle __asm__("r0") = handle;

	register Result res __asm__("r0");

	__asm__ volatile ("svc\t0x23" : "=r"(res) : "r"(_handle) : "r1", "r2", "r3", "r12");

	return res;
}

/**
 * @brief Breaks execution.
 * @param breakReason Reason for breaking.
 */
static inline void svcBreak(UserBreakType breakReason) {
	register UserBreakType _breakReason __asm__("r0") = breakReason;

	__asm__ volatile ("svc\t0x3C" : "+r"(_breakReason) : : "r1", "r2", "r3", "r12");
}

/// Stop point, does nothing if the process is not attached (as opposed to 'bkpt' instructions)
#define SVC_STOP_POINT __asm__ volatile("svc 0xFF");
