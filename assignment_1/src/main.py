import stat
from pathlib import Path
import subprocess

import lief


def modify_rodata_section(binary_object: lief.Binary, base_directory: Path):
    rodata = binary_object.get_section(".rodata")
    data = bytearray(rodata.content)
    old_string = b"Hello"
    new_string = b"Goodbye"
    offset = data.find(old_string)
    if offset == -1:
        raise Exception("Cannot find string in the source data")
    for i in range(len(new_string)):
        data[offset + i] = new_string[i]
    rodata.content = list(data)
    modified_file = base_directory / "build/example_modified.o" 
    binary_object.write(str(modified_file))
    modified_file.chmod(modified_file.stat().st_mode | stat.S_IEXEC) # add chmod +x to the file


def main():
    BASE_DIR = Path(__file__).parent.parent
    build_file_directory = BASE_DIR / "build/example.o"
    subprocess.run(["gcc", "-o", f"{build_file_directory}", f"{BASE_DIR}/src/example.c"]) # recompile binary again
    with build_file_directory.open("rb") as f:
        parsed_binary = lief.ELF.parse(f)
    modify_rodata_section(binary_object=parsed_binary, base_directory=BASE_DIR)
    

if __name__ == "__main__":
    main()
