import os
import time
import sys
import hashlib
import textwrap
import report

def exe_cmd(cmd):  
    r = os.popen(cmd)  
    text = r.read()  
    r.close()  
    return text  

def get_dumps_list():
    print("----------------------dump file-------------------")
    dump_files = os.listdir("./dumps/")
    for n in dump_files:
        print(n)    
    print("--------------------------------------------------")
    return dump_files

def auto_scan_dump(pid:str):
    os.system(".\\memscan64.exe " + pid)
    
def yara_match_all(dmp_list):
    dmp_result_dic = {}
    
def gen_preview(data:bytes)->str:
    hex_text = ' '.join(['%02x' % b for b in data[:200]])
    hex_text = textwrap.fill(hex_text,99)
    
    ascii_text = data.decode("ascii","ignore")
    ascii_text = textwrap.fill(ascii_text[:200],50) 

    return (hex_text,ascii_text)
    
def gen_dmp_meta(dmp_name):
    dmp_meta = {}
    with open("./dumps/" + dmp_name, 'rb') as fp:
        dmp_buf = fp.read()
    #hash
    dmp_meta["name"] = dmp_name
    dmp_meta["length"] = str(len(dmp_buf))
    dmp_meta["md5"] = hashlib.md5(dmp_buf).hexdigest()
    dmp_meta["sha256"] = hashlib.sha256(dmp_buf).hexdigest()
    dmp_meta["yara_result"] =  exe_cmd(".\\yara64.exe -w -m .\\rules\\index.yar .\\dumps\\" + dmp_name)
    preview = gen_preview(dmp_buf)
    dmp_meta["hex_preview"] = preview[0]
    dmp_meta["string_preview"] = preview[1]
    
    return dmp_meta


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python auto_scan.py [pid] ")
        os._exit(0)

    pid = sys.argv[1]
    print("[*]Target process id: %s " % pid)
    os.system("powershell -c rm .\\dumps\\*")
    task_id = str(int(time.time()))
    print("[+]Task ID: " + task_id)
    auto_scan_dump(pid)
    dmp_file_list = get_dumps_list()
    dmp_meta_list = []

    if len(dmp_file_list) == 0:
        print("No detect!")
        os._exit(0)

    
    print("[*]Scan dump files.......")
    for name in dmp_file_list:
        dmp_meta = gen_dmp_meta(name)
        dmp_meta_list.append(dmp_meta)
    
    print("[*]Scan finished")
    report.gen_report(task_id=task_id,dmp_meta_list=dmp_meta_list)
    