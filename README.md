# RelaBP
A x64dbg plugin which can restore relative breakpoints

This plugin is usefull in such situation:
You debug a program which will allocate a regon of RWX memory, fill in shellcode, and execute the shellcode in this regon.
Since the shellcode address changes every time you restart the program, and the address is not relative to the debuggee process,
x64dbg can't record the breakpoint address which you set in that shellcode.

This plugin will record the the breakpoints' relative addresses in a file, and load them on next start, thus restore breakpoints you previously set.

This plugin is not finished yet, and currenty only fit my dev needs.
