import json
from time import *
import os
from re import *
from datetime import datetime
import shutil


def appDefiner(line,number):
    
    partss = line.split(" ")
    appName = partss[4]
    
    if search(r"postgres",line):
        postgresParse(line,number)
        
    elif search(r"apache-carbon-err-ssl",appName):
        apacheErrParse(line,"carbon",number)
    elif search(r"apache-carbon",appName):
        apacheParse(line,"carbon",number)
    
    elif search(r"apache-nfi-err-ssl",appName):
        apacheErrParse(line,"nfi",number)       
    elif search(r"apache-nfi",appName):
        apacheParse(line,"nfi",number)

    elif search(r"apache-ca-err-ssl",appName):
        apacheErrParse(line,"ca",number)
    elif search(r"apache-ca",appName):
        apacheParse(line,"ca",number)
    
    elif search(r"apache-localhost-err",appName):
        apacheErrParse(line,"localhost",line)
    elif search(r"apache-localhost",appName):
        apacheParse(line,"localhost",number)
    
    elif search(r"sshd",appName):
        sshdParse(line,number)
    elif search(r"sedispatch",appName):
        sedispatchParse(line,number)
    elif search(r"dacs",appName):
        dacsParse(line,number)

def fileWriter(json_data, appname, number):
    fileName = appname + ".json"
    '''if (number == 0):
        deleteContent("../Parsing/ParsedLogs")
        print 'deleting' '''
    file  = open("../Parsing/ParsedLogs/" + fileName,"a+")
    file.write(json_data)
    file.write("\n")
    file.close()

def deleteContent(fileName):
    folder = fileName
    for the_file in os.listdir(folder):
        file_path = os.path.join(folder, the_file)
        if os.path.isfile(file_path):
            os.unlink(file_path)
        
def postgresParse(line,number):
	return

def apacheParse(line,app,number):
    parts = line.split(" ")

    #change the indexes if there is an extra space in the datetime of the logs
    extraSpace = 0

    if(parts[1] != ""):
        pass
    elif(parts[1] == ""):
        extraSpace = 1

    timeStamp = " ".join(parts[0:4+extraSpace])

    appName = "apache-"+app+"-ssl"

    obj = {}
    
    if(search(r"4",parts[12+extraSpace])):
        obj['appName'] = appName
        obj['timestamp'] = timeStamp
        obj['message'] = '400 error'
    elif(search(r"3",parts[13+extraSpace])):
        obj['appName'] = appName
        obj['timestamp'] = timeStamp
        obj['message'] = {}
        obj['message']['method'] = parts[10+extraSpace]
        obj['message']['uri-stem'] = parts[11+extraSpace]
        obj['message']['user-agent'] = parts[16+extraSpace:]
        obj['message']['client-IP'] = parts[5+extraSpace]
        obj['message']['repeated'] = 0
    elif(search(r"message", parts[6+extraSpace])):
        obj['appName'] = appName
        obj['timestamp'] = timeStamp
        obj['message'] = {}
        obj['message']['method'] = parts[15+extraSpace]
        obj['message']['uri-stem'] = parts[16+extraSpace]
        obj['message']['user-agent'] = parts[21+extraSpace:]
        obj['message']['client-IP'] = parts[10+extraSpace]
        obj['message']['repeated'] = parts[8+extraSpace]
    else:
        obj['appName'] = appName
        obj['timestamp'] = timeStamp
        obj['message'] = {}
        obj['message']['method'] = parts[10+extraSpace]
        obj['message']['uri-stem'] = parts[11+extraSpace]
        obj['message']['user-agent'] = parts[16+extraSpace]
        obj['message']['client-IP'] = parts[5+extraSpace]
        obj['message']['repeated'] = 0
    
        json_data = json.dumps(obj)
        fileWriter(json_data,"apache-ssl",number)

def apacheErrParse(line,app,number):
    parts = line.split(" ")
    timeStamp = " ".join(parts[0:3])
    
    obj = {}
    
    message = " ".join(parts[15:])
    
    appName = "apache-"+app+"-err-ssl"
    
    obj['appName'] = appName
    obj['timestamp'] = timeStamp
    obj['message'] = message
    
    json_data = json.dumps(obj)
    fileWriter(json_data,"apache-err-ssl",number)

def dacsParse(line,number):
    parts = line.split(" ")
    timeStamp = " ".join(parts[0:3])
    
    obj = {}
    
    appName = "dacs"
    
    message = " ".join(parts[12:])
    
    obj['appName'] = appName
    obj['timestamp'] = timeStamp
    obj['message'] = message
    
    json_data = json.dumps(obj)
    fileWriter(json_data,"dacs",number)

def sedispatchParse(line,number):
    parts = line.split(" ")
    timeStamp = " ".join(parts[0:3])
    
    obj = {}
    
    appName = "sedispatch"
    
    message = " ".join(parts[4:])
    
    obj['appName'] = appName
    obj['timestamp'] = timeStamp
    obj['message'] = message
    
    json_data = json.dumps(obj)
    fileWriter(json_data,"sedispatch",number)

def sshdParse(line,number):
    parts = line.split(" ")
    timeStamp = " ".join(parts[0:3])
    
    obj = {}
    
    appName = "sshd"
    
    message = " ".join(parts[4:])
    
    obj['appName'] = appName
    obj['timestamp'] = timeStamp
    obj['message'] = message
    
    json_data = json.dumps(obj)
    fileWriter(json_data,"sshd",number)

if __name__ == "__main__":

    file = open("../stuff/all-messages.log","r")

    number = 0

    for line in file:
        appDefiner(line,number)
        number = number + 1
        #print number

    file.close()