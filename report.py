import datetime
from bottle import SimpleTemplate,template
import time


dmp_info_tpl =  ''' 
    <div class="dump-show">
        <div class="basic-info">
            Name:{{meta["name"]}}
            <br>
            length:{{meta["length"]}}
            <br>
            md5:{{meta["md5"]}}
            <br>
            sha256:{{meta["sha256"]}}
        </div>
        <HR style="FILTER: alpha(opacity=100,finishopacity=0,style=3)" width="99%" color=pink SIZE=1>
        <div class="data-preview">
            <div class="hex-show" style="float: left;width:69%;border-right:1px solid pink;">
                {{meta["hex_preview"]}}
            </div>
            <div class="string-show" style="width: 30%;margin-left: 70%;">
                {{meta["string_preview"]}}
            </div>
        </div>
        <div style="clear:both"></div>
        <HR style="FILTER: alpha(opacity=100,finishopacity=0,style=3)" width="99%" color=pink SIZE=1>
        <div class="yara-show">{{meta["yara_result"]}}</div>
    </div>
'''
report_tpl =  '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report</title>
    <style>
        body{
            font-family:Consolas, monospace;
            background: linear-gradient(rgba(255, 255, 255, 0.7), rgba(255, 255, 255, 0.7)), url('https://z3.ax1x.com/2021/08/13/fDrPTe.jpg') no-repeat 0% 20%/ cover;
        }
        .dump-show{
            
            border-radius: 10px;
            background-color:rgba(245, 245, 245, 0.74);
            box-shadow:2px 2px 2px gray;
            font-size: 15px;
        }
        .basic-info{
            margin-left: 10px;
            margin-top: 10px;
            color: rgba(54, 54, 54, 0.897);
        }
        .data-preview{
            margin-left: 10px;
            margin-top: 10px;
            color:rgb(146, 145, 145);
        }
        .yara-show{
            margin-left: 10px;
            margin-bottom: 10px;
            white-space: pre-line;
            color:rgb(247, 73, 20);
        }
        .header{
            border-radius: 10px;
            background-color: rgba(231, 224, 158, 0.322);
            box-shadow:3px 3px 3px rgb(146, 146, 146);
            color:navy;
        }
    </style>
</head>
<body>
    <div class="header">
        <div style="margin-top: 10px;margin-left: 10px;">
            <h3>Report</h3>
            <p>Warning:Suspicious SHELLCODE / PE </p>
        </div>
        <div style="margin-left: 10px;">
            <p>Time: {{report_time}} </p>
            <p>ID: {{report_id}} </p>
        </div>
    </div>
        % for x in dmp_div_list:
            {{!x}}
        %end
</body>
</html>

'''

def gen_dmp_info_html_node_list(dmp_meta_list:list)->list:
    html_node_list = []
    for m in dmp_meta_list:
        html = template(dmp_info_tpl,meta=m)
        html_node_list.append(html)

    return html_node_list

def gen_report(task_id:str,dmp_meta_list:list):
    date_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    dmp_html_node_list = gen_dmp_info_html_node_list(dmp_meta_list)
    report_html = template(report_tpl,report_time=date_time,report_id=task_id,dmp_div_list=dmp_html_node_list)
    f = open("report-" + task_id + ".html","w")
    f.write(report_html)
    f.close()
    print("[+]Report save to file:  report-" + task_id + ".html")
    
