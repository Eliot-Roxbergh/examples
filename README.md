# Guides and Examples

Some of my informal guides and examples.
Includes, programming (e.g. C, Bash) and Linux stuff (simple automation, usage, ..), and related topics.

Playing around, feel free to give pointers. 🕵️


## CI

For c-programming/examples we have a small Github CI pipeline.
For every commit, as well as once per week, a few analysis tools are ran:

**cmake** (see _code-analysis_ output in https://github.com/Eliot-Roxbergh/examples/actions/workflows/cmake.yml. This includes different open-source tools)

**semgrep** (see https://github.com/Eliot-Roxbergh/examples/security/code-scanning)

**codeql** (see https://semgrep.dev/orgs/eliot-roxbergh/findings)

TODO yes these code warnings get lost and the tests does not necessarily fail, need to manually check as is now.
