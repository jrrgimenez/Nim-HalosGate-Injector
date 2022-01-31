# Nim-HalosGate-Injector

My Nim implementation of the most common shellcode injector, using HalosGate to retrieve system call opcodes dynamically from NTDLL even when there are EDR API Hooks in place. 

It relies heavily in other implementations, so huge thanks to SEKTOR7 [1] for implementing this technique and @am0nsec and @RtlMateusz for creating the Hell's Gate paper in first place [2]. Thanks also to @zimawhit3 for its Nim Hell's gate implementation [3] :)

# Usage

Its usage is pretty simple, just compile the binary with nim:
```bash
nim c -d=mingw --app=console --cpu=amd64 HalosGate.nim
```

And run it in the target machine specifying the PID of the process in which you want to inject the shellcode:
```powershell
./HalosGate.exe <PID>
```

[1]:https://blog.sektor7.net/#!res/2021/halosgate.md
[2]:https://github.com/am0nsec/HellsGate
[3]:https://github.com/zimawhit3/HellsGateNim
