import lief


def main():
    
    with open("some_executable_2", "rb") as f:
        parsed_binary = lief.ELF.parse(f)
        
    # binary_data = {
    #     "elf_type": parsed_binary.header.file_type,
    #     "architecture": parsed_binary.header.machine_type,
    # }

    rodata = parsed_binary.get_section(".rodata")
    data = bytearray(rodata.content)

    old_string = b"Hello"
    new_string = b"Goodbye"


    offset = data.find(old_string)
    if offset == -1:
        raise

    for i in range(len(new_string)):
        data[offset + i] = new_string[i]


    rodata.content = list(data)

    parsed_binary.write("hello_modified")
    
    # chmod +x
    

if __name__ == "__main__":
    main()
