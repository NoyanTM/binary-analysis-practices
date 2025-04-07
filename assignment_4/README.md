# Task 4 - Automated analysis with scripting

## Description
Automated analysis with IDAPython, PyGhidra, etc. for searching code patterns, extracting functions and their dependencies, function call analysis, and so on.

## Solution

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install ghidra-stubs==<ghidra_version>
GHIDRA_INSTALL_DIR=<directory_to_installed_ghidra>
echo $GHIDRA_INSTALL_DIR or check with env / printenv
python3 -m src.main
```

# TODO:
- Refactor functions and return types (return empty list instead of None)
- Convert addresses string to hex in order to calculate them
- Some imports like `from ghidra.program.model.symbol import RefType`, cannot be used outside ghidra program context and raise ModuleNotFoundError
- Stubs not wokring properly - https://github.com/microsoft/pylance-release/issues/5073
- Create appropriate high-level API, wrapper library, more pythonic binding (language binding or binding for library software), because:
  - API is not intuitive and raw. PyGhidra is not raising any exception or provide informatio, if error occurs, so debugging and identifying problems is difficult
    - required to use dir, type, print, debugger in IDE, etc.
  - Examples: GDAL -> Rasterio, PySpark, Selenium, etc.
- Automatic Function Annotation: Write a script that labels unknown functions based on code patterns.
- Bypassing Anti-Debugging Techniques: Detect and disable checks like IsDebuggerPresent, NtQueryInformationProcess.
