# Task 1 - Modify ELF/EP file

## Description

1. Add new section
2. Change entrypoint address
3. Delete or change imported libraries

## Solution

1. Adding new section and changing source binary via lief library:
```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m src.main
```

2. Modifying entrypoint address of source binary, which probably will cause segmentation fault because programm will try to access memory not allowed to it or non-existing segment:
```
./script.sh
```
