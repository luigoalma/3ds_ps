/**
 * @file srv.h
 * @brief Service API.
 */
#pragma once

/// Initializes the service API.
Result srvInit(void);

/// Exits the service API.
void srvExit(void);

/**
 * @brief Retrieves a service handle, retrieving from the environment handle list if possible.
 * @param out Pointer to write the handle to.
 * @param name Name of the service.
 * @return 0 if no error occured,
 *         0xD8E06406 if the caller has no right to access the service,
 *         0xD0401834 if the requested service port is full and srvGetServiceHandle is non-blocking (see @ref srvSetBlockingPolicy).
 */
Result srvGetServiceHandle(Handle* out, const char* name);

/// Registers the current process as a client to the service API.
Result srvRegisterClient(void);

/**
 * @brief Enables service notificatios, returning a notification semaphore.
 * @param semaphoreOut Pointer to output the notification semaphore to.
 */
Result srvEnableNotification(Handle* semaphoreOut);

/**
 * @brief Registers the current process as a service.
 * @param out Pointer to write the service handle to.
 * @param name Name of the service.
 * @param maxSessions Maximum number of sessions the service can handle.
 */
Result srvRegisterService(Handle* out, const char* name, int maxSessions);

/**
 * @brief Unregisters the current process as a service.
 * @param name Name of the service.
 */
Result srvUnregisterService(const char* name);

/**
 * @brief Retrieves a service handle.
 * @param out Pointer to output the handle to.
 * @param name Name of the service.
 * * @return 0 if no error occured,
 *           0xD8E06406 if the caller has no right to access the service,
 *           0xD0401834 if the requested service port is full and srvGetServiceHandle is non-blocking (see @ref srvSetBlockingPolicy).
 */
Result srvGetServiceHandleDirect(Handle* out, const char* name);

/**
 * @brief Receives a notification.
 * @param notificationIdOut Pointer to output the ID of the received notification to.
 */
Result srvReceiveNotification(u32* notificationIdOut);
