import argparse
import json
import logging
import mmap
import os
import random
import shutil
import signal
import threading
import time
from json import encoder
import pefile
import r2pipe
import binascii

# #binary = "putty.exe"
# binary = "0B7FEFAF5C8F3A320DC08EC32BD5955F0B3B2E35034C8B2AD879AE6BDC2CC0BC"
# pe = pefile.PE(binary, fast_load=True)
# if not pe.is_exe():
#     pe.close()
#     raise NotPE()
# elif pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0 or \
#     pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size != 0:
#     pe.close()
#     raise NotPE()
# with open(binary,'rb') as f:
#     hex_content = f.read().encode('hex')

# print(hex_content)

a = ['1','2', '3', '4', '5', '6', '7', '8']

print(a[0:4])