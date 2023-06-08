import os

input_path='/home/kali/Desktop/program+input/pdfimages/queue/'
bincmd='/home/kali/Desktop/program+input/pdfimages/pdfimages'

if __name__=='__main__':
    
    out_path = input_path+'trace'

    if not os.path.exists(out_path):
        os.makedirs(out_path)


    for root, dirs, files in os.walk(input_path):
        for input_i in files:
            if os.path.exists(out_path+'/'+input_i):
                continue
            cmd = "/home/kali/Desktop/pin-3.26/pin -t obj-intel64/pathtrace.so -- "+bincmd+' '+input_i+' /dev/null > '+out_path+'/'+input_i+'.out'
            print(cmd)
            os.system(cmd)
