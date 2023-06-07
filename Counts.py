import os

out_path=""

if __name__=="__main__":
    for root, dirs, files in os.walk(out_path):
        for file in files:
            file=out_path+file
            with open(file) as f:

                
