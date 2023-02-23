# Tools for C

## Compiler, linker, ..

Remember to enable relevant warnings in the compiler, as well as setting secure build flags.

See my comments in _gcc_flags.md_

## Dynamic Program Analysis
### Memory Check and More

valgrind --leak-check=yes ./binary.so args

Valgrind test suite has many more tests than just the default memcheck ("Valgrind"), see https://valgrind.org/info/tools.html

### Fuzzy Testing

AFL++


## Static Code Analysis

~_See seperate discussion and testing in ../examples/README.md_~

See my static analysis comparison for more info: https://github.com/Eliot-Roxbergh/static_analysis \
For an example of C project with static analysis setup see https://github.com/Eliot-Roxbergh/task_portknocker


### Supported in CMake (C / C++)

clang-tidy cppcheck iwyu lwyu cpplint

An alternative is CodeChecker (front-end to clang static analysis tools)

>CodeChecker check --build "make clean; cmake . && cmake --build ."  --output ./reports --clean --enable sensitive

### More checkers

Semgrep (only for open-source projects)

codeQL (proprietary)

Infer

### Linux Kernel SAST /w Sparse

The Linux kernel is compiled with GCC, making clang-tidy of little use.
Due to a lot of low level functions and special defines etc. I'm not sure how well other analyze tools would perform.
-> Use Sparse which is made for the Kernel.

#### Prereqs. 

```
sudo apt update
sudo apt install -y git fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison
sudo apt install -y dwarves sparse
# (get kernel to ./linux)
cd linux
```

#### Analyze patch diff

Run static analysis on the patches for the linux kernel.
That is, build kernel, apply patches, run sparse only on the files which needs to be recompiled.
This is not a perfect "diff" but it generates less warnings than running Sparse on the whole thing.


```
make -j8 #(=8 cores, for instance)

# It's possible to patch with the `patch` command
#   but by using `git am` each patch gets their own Git commit
git am my_patches/*.patch

# Analyze only files which need to be recompiled (C=1)
make -j8 C=1 2> sparse_on_patches.txt
```

#### Analyze specific file

It is also possible to run sparse only on some files:

```
# Analyze all C=2
make C=2 some/interesting/path
```


## Unit Tests

Google Test

Criterion

Check


For CMake see also CTest, and CDash (e.g. to be used in conjunction with Google Test)

## Code Coverage

gcov & lcov (included in GCC)

(there are many commercial products..)

## Mocking

gmock (Google Test)

cmocka

(could ofc also naively mock a function manually by using #defines or look at the dynamic linking)

# Comments
There are of course many more tools to choose from, see for instance,

https://en.wikipedia.org/wiki/List_of_tools_for_static_code_analysis

https://en.wikipedia.org/wiki/List_of_unit_testing_frameworks#C
