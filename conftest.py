# Intentionally empty.
#
# Its presence at the project root is what matters: pytest uses the
# directory containing the outermost conftest.py as an anchor for
# sys.path insertion (under the default "prepend" import mode), so
# `from engine...` resolves correctly in tests/ regardless of the
# current working directory, OS, or pytest version. Without this file,
# `tests/` can get treated as its own rootdir on some platform/pytest
# combinations, and `engine/` (a sibling of tests/, not a package
# inside it) never lands on sys.path — surfacing as
# "ModuleNotFoundError: No module named 'engine'".
