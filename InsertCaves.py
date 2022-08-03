import pefile
import os 
import mmap
import sys


def align(val_to_align, alignment):
    return ((val_to_align+alignment-1)/alignment)*alignment

def insertCaves(malware, target_section, cave_size=0):
    original_size = os.path.getsize(malware)
    print("Original Size", original_size)
    pe = pefile.PE(malware, fast_load=True)
    print(pe.OPTIONAL_HEADER)
    if not pe.is_exe():
        pe.close()
        raise NotPE()
    elif pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0 or pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size != 0:
        pe.close()
        raise NotPE()
    raw_addition = int(align(0x1000, pe.OPTIONAL_HEADER.FileAlignment))
    virtual_addition = int(align(0x1000, pe.OPTIONAL_HEADER.SectionAlignment))
    target_found = False

    for section in pe.sections:
        if section.Name.decode().rstrip('\x00') == target_section:
            #temp_VirtualSize = section.Misc_VirtualSize
            section.Misc_VirtualSize += virtual_addition
            section.SizeOfRawData += raw_addition
            changing_virtual_address = section.VirtualAddress
            target_found = True
        
        if target_found == True and section.VirtualAddress > changing_virtual_address:
            section.VirtualAddress += virtual_addition
            section.PointerToRawData += raw_addition

    #pe.OPTIONAL_HEADER.SizeOfRawData += raw_addition
    pe.OPTIONAL_HEADER.SizeOfImage += virtual_addition 

    for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if entry.Size>0 and entry.VirtualAddress > changing_virtual_address:
            entry.VirtualAddress += virtual_addition


    pe.write("new_malware.exe")

    # print("New malware created")
    # fil = open("new_malware.exe", 'a+b')
    # map = mmap.mmap(fil.fileno(), 0, access = mmap.ACCESS_WRITE)
    # map.resize(original_size + 0x1000)
    # map.close()
    # fil.close()
    # print("Resized malware file")
    # print(os.path.getsize("new_malware.exe"))

direct = "/home/kshitiz/Downloads/research/Data/sample_mal/0B7FEFAF5C8F3A320DC08EC32BD5955F0B3B2E35034C8B2AD879AE6BDC2CC0BC"
#direct = "putty.exe"
inp = int(input("Select one of the sections to input code cave: \n 1 for .text \n 2 for .rdata \n 3 for .data \n 4 for .rsrc \n"))


if inp == 1: 
    target_section = '.text'
elif inp == 2: 
    target_section = '.rdata'
elif inp == 3: 
    target_section = '.data'
elif inp == 4: 
    target_section = '.rsrc'
else:
    print("Invalid section value entered")
    sys.exit()
insertCaves(direct, target_section)