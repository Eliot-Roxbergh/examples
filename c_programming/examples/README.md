# C Programming

## CI

For this C programming part we have a small Github CI pipeline.
For every commit, as well as once per week, a few analysis tools are ran:

**cmake** (see _code-analysis_ output in https://github.com/Eliot-Roxbergh/examples/actions/workflows/cmake.yml. This includes different tools as specified in CMakeLists.txt)

**semgrep** (see https://github.com/Eliot-Roxbergh/examples/security/code-scanning)

**codeql** (see https://semgrep.dev/orgs/eliot-roxbergh/findings)

TODO yes these code warnings get lost and the tests does not necessarily fail, need to manually check as is now.

## Static Code Analysis

### Finding Bugs

#### Recommendation

Run Semgrep (CI) and clang-tidy + cppcheck (via cmake). Semgrep uses Google Analytics but can be disabled.

CodeQL gave little input, also it cannot be used on proprietary projects ... but no false positives so all good.

Did not test Splint further, seems hard to setup properly and finds many false positives (or very specific requirements avoid these).

##### Results from Scanning

Semgrep and clang-tidy found multiple potential issues. CodeQL found only two issues which clang-tidy had already reported on.

cppcheck found two minor issues, one of which already reported by CodeQL.

#### TODO

Would be interesting to also try Infer (https://github.com/facebook/infer).

Manually specify rules in Semgrep, looks useful.

CodeChecker is a front-end that support most of these tools (e.g. clang-tidy cppchecker infer cpplint), much easier to read the output.

Integrate all into CI

### Style Feedback

#### Recommendation

Seems like clang-format and cpplint work well in combination, run with

>make clang-format && make cpplint

##### Results from Scanning

clang-format automatically changes all source files to match the desired format (see .clang-format)

cpplint gives some comments on code style which clang-format didn't fix.

Overall I'm impressed. But remember to enable this, or similar, in your IDE.

