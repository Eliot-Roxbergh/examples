# Building secure C Binary
Here is my quick summary on hardening C binaries using GCC on Linux. As well as other GCC / linker settings.

Sources and links at the end.


## Summary of Defensive Techniques

**ASLR** - PIE (for ASLR we very much prefer 64-bit) -> (e.g. harder to performs ROP attacks)

**Stack smashing protector** - stack canary... (but there are still attacks which doesn't use stack: heap, arbitrary memory writes, overwrite function pointer, overwrite GOT ...)

**Buffer overflow / bounds checking** - we can try to check during compile time and runtime if destination is large enough (not 100% / can be edge cases) [object-size-checking].

**Control flow integrity protection** - check where we are jumping/returning/... some CPU magic, see your hardware support (I can imagine this is easy in theory, but difficult for performance reasons (?)) (From GCC manpage -> "implementation based on Intel Control-flow Enforcement Technology (CET)")

**GOT read-only** - By disabling lazy binding (or only use static libraries and skip GOT) we can write GOT as the process is loaded into memory, and then make GOT read-only [GOT-RELRO-hardening]. (preventing exploits introduced with the use of dynamically linked libraries)

**No execute** - Ideally, memory (stack, heap, ..) should either be executable OR writable. So that if a overflow is possible, it's not directly possible to write and execute exploit code (not perfect as still it doesn't help against ROP and GOT attacks)


## GCC Flags

Note, nothing is free and some of these settings may have large overhead (for instance).


__SECURITY STUFF__
```
-D_FORTIFY_SOURCE=2                             Run-time buffer overflow detection
-D_GLIBCXX_ASSERTIONS                           Run-time bounds checking for C++ strings and containers ("Enable C++ standard library hardening with -D_GLIBCXX_ASSERTIONS.
                                                                                                          This turns on cheap range checks for C++ arrays, vectors, and strings." - https://fedoraproject.org/wiki/Changes/HardeningFlags28)
-fpie -Wl,-pie                                  Full ASLR for executables                               ("executables ONLY", we want 64-bit for entropy)
-fpic -shared                                   No text relocations for shared libraries                ("libraries ONLY")
-fstack-clash-protection                        Increased reliability of stack overflow detection       (>GCC 7.5??)
-fstack-protector or -fstack-protector-all      Stack smashing protector                                (Stack canary. -all is mostly overkill and -strong was added to give a good middle ground -> [fstack-protector])
                  or -fstack-protector-strong   -
-mcet -fcf-protection=full                      Control flow integrity protection                       (Intel only)

-Wl,-z,now                                      Disable lazy binding                                    Not a security feature directly but it allows for relro (see below).
                                                                                                        (Disable lazy binding... also https://stackoverflow.com/questions/23485489/does-clang-gcc-really-support-a-delay-loading-feature)
-Wl,-z,relro                                    Read-only segments after relocation                     Set GOT read-only, possible if all symbols are resolved at application start (ELF is loaded into process memory) [GOT-RELRO-hardening].

-Wl,-z,noexecstack                              -                                                       Non-executable stack .. usually default on, see https://linux.die.net/man/8/execstack
                                                                                                        (Set NX-bit..? Why would stack, heap, .., be writable AND executable?)
```

(-Wl to pass comma-separated list to the linker)

__DIV__
```
-Wl,-z,defs                                     Detect and reject underlinking                          "Report unresolved symbol references from regular object files.  This is done even if the linker is creating a non-symbolic shared library."
                                                                                                        (like if one library requires a symbol from another lib, which could be missing?
                                                                                                         -> https://stackoverflow.com/questions/2356168/force-gcc-to-notify-about-undefined-references-in-shared-libraries)
-fno-common                                     -                                                       Detects multiple definitions.. "places uninitialized global variables in the BSS section" (should be default in newer GCC >=10?)
```
__DEBUG__
```
-g                                              Generate debugging information
-fasynchronous-unwind-tables                    Increased reliability of backtraces
-fexceptions                                    Enable table-based thread cancellation
-grecord-gcc-switches                           Store compiler flags in debugging information
-pipe                                           Avoid temporary files, speeding up builds
-fplugin=annobin                                Generate data for hardening quality control             (some fancy new metadata feature IDK)
-Og                                             -                                                       (build optimized for debugging, seems like this can also detect some errors)
```

__WARNINGS__
```
-Werror=format-security                         Reject potentially unsafe format string arguments       (warning is already included in -Wformat=2)
-Werror=implicit-function-declaration           Reject missing function prototypes                      (warning is already included in -Wall) ("C only")
-Werror                                                                                                  Make all warnings into errors

-Wextra -Wall -pedantic                         -                                                        These flags enable numerous extra warnings (but not "all") (for pedantic remember to set --std= to your standard version)
                                                                                                         (includes e.g. -Wunused, Wformat-truncation, -Wformat=1)

-Wconversion                                    -                                                        Warn on implicit conversions that may alter the value (such as converting to a smaller variable or from signed to unsigned)
                                                                                                         I strongly recommend to enable this, otherwise gcc doesn't say anything on e.g.: unsigned char a = -1;
                                                                                                         (It doesn't warn on explicit casts.)
-Wformat=2                                      -                                                        Mostly enables security warnings regarding printf and scanf functions
```

__OPTIMIZE__
```
-O2                                             Recommended optimizations                                (for test/debugging lower optimization could give simpler assembly code and e.g. not optimize away unused code..)


-Og - (most debug info, while quick to run and some optimizations in code)
-O0 - (fewest, but some, optimizations)

-S  - (get assembly code as output, note that your optimization level changes the result)
```

Table taken from [gcc_recommended_flags] with my modifications and I added the last column with my own comments (the middle column is direct citation from their site).

### Suggested Flags from Above (WIP)

```
gcc_flags_debug="-g -fasynchronous-unwind-tables -fexceptions"
gcc_flags_warnings="-Wall -Wextra -pedantic -Werror -Wformat=2  -Wconversion"

gcc_flags_security="-D_FORTIFY_SOURCE=2  -D_GLIBCXX_ASSERTIONS -fstack-protector-strong -Wl,-z,noexecstack -Wl,-z,now -Wl,-z,relro -Wl,-z,defs "
gcc_flags_security_exec="-fpie -Wl,-pie"
gcc_flags_security_lib="-fpic"
//more="-fstack-clash-protection -mcet -fcf-protection" # (not in my GCC)
// Just took recommended flags from https://developers.redhat.com/blog/2018/03/21/compiler-and-linker-flags-gcc/, could require some more thought...
```


### Sources

[gcc_recommended_flags] - https://developers.redhat.com/blog/2018/03/21/compiler-and-linker-flags-gcc/

[fstack-protector] - https://lists.llvm.org/pipermail/cfe-dev/2017-April/053662.html, https://outflux.net/blog/archives/2014/01/27/fstack-protector-strong/

[GOT-RELRO-hardening] - https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro

[object-size-checking] - https://gcc.gnu.org/legacy-ml/gcc-patches/2004-09/msg02055.html

More reading on recommended GCC flags: https://security.stackexchange.com/questions/24444/what-is-the-most-hardened-set-of-options-for-gcc-compiling-c-c, https://wiki.debian.org/Hardening

