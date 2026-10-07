# Security reporting

Report suspected security vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/fakuivanai/labview-to-ghidra/security/advisories/new).
Include the converter version, operating system, Ghidra version, commands and
observed behavior. A small generated input that reproduces the issue is useful.

This converter reads VI files, XML and runtime DLLs as static inputs. Parser,
file-access and generated-script issues are relevant security reports. Ordinary
unsupported-format cases and analysis inaccuracies can be reported as issues.

Version 0.1.0 is experimental. It supports only the profile documented in the
README. Report findings against the current default branch; older versions do
not have a separate maintenance policy.
