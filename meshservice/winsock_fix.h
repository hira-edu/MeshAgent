// winsock_fix.h - ensure winsock2 is included first in all translation units
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>

// Prevent legacy winsock.h from being included later
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
