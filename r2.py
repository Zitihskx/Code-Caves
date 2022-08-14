import pefile
import os 
import mmap
import sys
import pandas as pd
import time

#binary = "0B7FEFAF5C8F3A320DC08EC32BD5955F0B3B2E35034C8B2AD879AE6BDC2CC0BC"
start_time = time.time()
directory = '/home/kshitiz/Desktop/Gradient Attack/data/train'
#directory = '/home/kshitiz/Desktop/Gradient Attack/data/valid'
#directory = '/home/kshitiz/Desktop/Code caves/Tes_malware'

df = pd.DataFrame(columns = ['binary', 'size', 'count', 'per'])
print(df)

for files in os.scandir(directory):
    if files.is_file():
        try:
            pe = pefile.PE(files, fast_load=True)
        except:
            continue
        size = os.path.getsize(files)
        count = 0
        for each in pe.__data__:
            if each == b'\x00':
                count+=1
        empty_per = count*100/size

        data = {'binary': files, 'size' : size,'count' : count, 'per' : empty_per}
        data_df = pd.DataFrame(data, index=[0])
        df = pd.concat([df, data_df], ignore_index=True, sort=False)
df.to_excel("Random1.xlsx")
print(time.time()-start_time)