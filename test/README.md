# Node tests

This source distribution retains C++ unit tests, functional node tests,
utility tests and fuzz test code. They are node verification tools; they do
not contain project operator wallets or production credentials. Keys used by
test fixtures are public test data.

The Linux integration build script runs the C++ unit-test executable.
Functional tests are separate and must only be run on an isolated test host.
No daemon or test network is started by the source-verification script.

Developer lint automation, historical-release downloads and the external
merged-mining coordinator are outside the scope of this node distribution.
