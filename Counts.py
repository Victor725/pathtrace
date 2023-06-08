import os


addr_count = {}

def add_addr(addr):
    if addr in addr_count:
        addr_count[addr]+=1
    else:
        addr_count[addr]=1

def get_addrs(path):
    with open(path,'r') as file:
        lines = file.readlines()
        for line in lines:
            line = line.split(' ')
            try:
                i = line.index('cur_loc:')
                addr = int(line[i+1], 16)
                add_addr(addr)

                i = line.index('target_loc:')
                addr = int(line[i+1], 16)
                add_addr(addr)
            except Exception as e:
                #print(e)
                continue
                

get_addrs("/home/kali/Desktop/out")
