# Nim-HalosGate-Injector

My Nim implementation of the most common shellcode injector, using HalosGate to retrieve system call opcodes dynamically from NTDLL even when there are EDR API Hooks in place. 

It relies heavily in other implementations, so huge thanks to SEKTOR7 [1] for implementing this technique and @am0nsec and @RtlMateusz for creating the Hell's Gate paper in first place [2]. 


[1]:https://blog.sektor7.net/#!res/2021/halosgate.md
[2]:https://github.com/am0nsec/HellsGate
