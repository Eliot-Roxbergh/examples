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

_See seperate discussion and testing in ../examples/README.md_

Semgrep (only for open-source projects)

codeQL (proprietary)

Infer

### Supported in CMake (C / C++)

clang-tidy cppcheck iwyu lwyu cpplint

An alternative is CodeChecker (front-end to clang static analysis tools)

>CodeChecker check --build "make clean; cmake . && cmake --build ."  --output ./reports --clean --enable sensitive

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
