import pefile
import r2pipe



pe = pefile.PE("new_malware.exe", fast_load=True)

#print(pe.print_info())

print("Machine : " + hex(pe.FILE_HEADER.Machine))
# Check if it is a 32-bit or 64-bit binary
if hex(pe.FILE_HEADER.Machine) == '0x14c':
    print("This is a 32-bit binary")
else:
    print("This is a 64-bit binary")
print("TimeDateStamp : " + pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]
)
print("NumberOfSections : " + hex(pe.FILE_HEADER.NumberOfSections))

print("Characteristics flags : " + hex(pe.FILE_HEADER.Characteristics))


print ("Optional Header Content:")
print("Magic : " + hex(pe.OPTIONAL_HEADER.Magic))
print("ImageBase : " + hex(pe.OPTIONAL_HEADER.ImageBase))
print("SectionAlignment : " + hex(pe.OPTIONAL_HEADER.SectionAlignment))
print("FileAlignment : " + hex(pe.OPTIONAL_HEADER.FileAlignment))
print("SizeOfImage : " + hex(pe.OPTIONAL_HEADER.SizeOfImage))
print("DllCharacteristics flags : " + hex(pe.OPTIONAL_HEADER.DllCharacteristics))
print("DataDirectory: ")
print("*" * 50)
# print name, size and virtualaddress of every DATA_ENTRY in DATA_DIRECTORY
for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
    print(entry.name + "\n|\n|---- Size : " + str(entry.Size) + "\n|\n|---- VirutalAddress : " + hex(entry.VirtualAddress) + '\n')    
print("*" * 50)


print("\n Section Header contents \n")
print("Sections Info: \n")
print("*" * 50)
for section in pe.sections:
    print(section.Name.decode().rstrip('\x00') + "\n|\n|---- Vitual Size : " + hex(section.Misc_VirtualSize) +
     "\n|\n|---- VirutalAddress : " + hex(section.VirtualAddress) + "\n|\n|---- SizeOfRawData : " +
      hex(section.SizeOfRawData) + "\n|\n|---- PointerToRawData : " + hex(section.PointerToRawData) +
       "\n|\n|---- Characterisitcs : " + hex(section.Characteristics)+'\n')    
print("*" * 50)

#print(pe.sections[1])
print(pe.sections[1].sizeof())
#r2 = r2pipe.open("/home/kshitiz/Downloads/research/sample_mal/0B7FEFAF5C8F3A320DC08EC32BD5955F0B3B2E35034C8B2AD879AE6BDC2CC0BC", ['-2'])
new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
#print(bytearray(new_section.sizeof()))

#print(pe.sections[-1].get_file_offset())

#print(len(pe.__data__))
