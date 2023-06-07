import os

input_path='/home/kali/Desktop/program+input/pdfimages/queue/'
bincmd='/home/kali/Desktop/program+input/pdfimages/pdfimages'

addr_count = {}

def add_addr(addr):
    if addr_count.has_key(addr):
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
            except:
                continue


if __name__=='__main__':
    
    out_path = input_path+'trace'

    if not os.path.exists(out_path):
        os.makedirs(out_path)


    for root, dirs, files in os.walk(input_path):
        for file in files:
            if os.path.exists(out_path+'/'+file):
                continue
            cmd = "/home/kali/Desktop/pin-3.26/pin -t obj-intel64/pathtrace.so -- "+bincmd+' '+file+' /dev/null > '+out_path+'/'+file+'.out'
            print(cmd)
            os.system(cmd)

            #读取log
            get_addrs(out_path+'/'+file)

            cmd = 'rm '+out_path+'/'+file+'.out'
            os.system(cmd)

