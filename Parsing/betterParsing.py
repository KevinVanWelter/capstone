import json
from time import *
import os
from re import *
from datetime import datetime

def appDefiner(line):
	if search(r"postgres",line):
		postgresParse(line)
	elif search(r"apache-carbon-ssl",line):
		apacheParse(line,"carbon")
	elif search(r"apache-carbon-err-ssl",line):
		apacheErrParse(line,"carbon")
	elif search(r"apache-nfi-ssl",line):
		apacheParse(line,"nfi")
	elif search(r"apache-nfi-err-ssl",line):
		apacheErrParse(line,"nfi")
	elif search(r"apache-ca-ssl",line):
		apacheParse(line,"ca")
	elif search(r"apache-ca-err-ssl",line):
		apacheErrParse(line,"ca")
	elif search(r"sshd",line):
		sshdParse(line)
	elif search(r"sedispatch",line):
		sedispatchParse(line)
	elif search(r"dacs",line):
		dacsParse(line)

def fileWriter(json_data, appname, number):
    if (number == 0):
        deleteContent("../Parsing/ParsedLogs/" + fileName)
    fileName = appname + ".json"
    file  = open("../Parsing/ParsedLogs/" + fileName,"a")
    file.write(json_data)
    file.write("\n")
    file.close()

def deleteContent(fileName):
	with open(fileName,"w"):
		pass
        
def postgresParse(line):
	return

def apacheParse(line,app,number):
    parts = line.split(" ")
    timeStamp = " ".join(parts[0:3])

    appName = "apache-"+app+"-ssl"

    obj = {}
    

    if(search(r"4",parts[11])):
        obj['appName'] = appName
        obj['timestamp'] = timeStamp
        obj['message'] = '400 error'
    elif(search(r"message", parts[5])):
        obj['appName'] = appName
        obj['timestamp'] = timeStamp
        obj['message'] = {}
        obj['message']['method'] = parts[15]
        obj['message']['uri-stem'] = parts[16]
        obj['message']['user-agent'] = parts[21]
        obj['message']['client-IP'] = parts[10]
    else:
        obj['appName'] = appName
        obj['timestamp'] = timeStamp
        obj['message'] = {}
        obj['message']['method'] = parts[10]
        obj['message']['uri-stem'] = parts[11]
        obj['message']['user-agent'] = parts[16]
        obj['message']['client-IP'] = parts[5]
    
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

    n = 0

    for line in file:
        appDefiner(line,n)
        n = n + 1

    file.close()