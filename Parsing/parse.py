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

def deleteContent(fileName):
	with open(fileName,"w"):
		pass

def monthBuilder(month):
	if int(month) == 1:
		month = "Jan"
	elif int(month) == 2:
		month = "Feb"
	elif int(month) == 3:
		month = "Mar"
	elif int(month) == 4:
		month = "Apr"
	elif int(month) == 5:
		month = "May"
	elif int(month) == 6:
		month = "Jun"
	elif int(month) == 7:
		month = "Jul"
	elif int(month) == 8:
		month = "Aug"
	elif int(month) == 9:
		month = "Sep"
	elif int(month) == 10:
		month = "Oct"
	elif int(month) == 11:
		month = "Nov"
	elif int(month) == 12:
		month = "Dec"
	return month

def postgresParse(line):
	return

def apacheParse(line,app):
	timestampPattern = r"[[]\d\d.....\d\d\d\d[:]\d\d[:]\d\d[:]\d\d\s.\d\d\d\d[]]"
	
	timestamp = search(timestampPattern,line).group(0)
	appName = "apache-"+app+"-ssl"

	write = open("ParsedLogs/apache-ssl.json","a")

	stampParts = timestamp.split(" ")
	shitDate = stampParts[0]
	dateParts = shitDate.split("/")
	day = search(r"\d\d",dateParts[0]).group(0)
	month = dateParts[1]
	yearTime = dateParts[2].split(":")
	year = yearTime[0]
	hour = yearTime[1]
	minute = yearTime[2]
	second = yearTime[3]
	t = hour +":"+minute+":"+second
	date = month + " " + day + " " + year + " " + t
	

	parts = line.split(" ")
	#message = " ".join(parts[9:])
	
	if(search(r"4",parts[11])):
		obj = json.dumps([{"appName": appName, "timestamp": date, "message": '400 error'}])
	elif(search(r"message", parts[5])):
		obj = json.dumps([{"appName": appName, "timestamp": date, "message": [{"method": parts[15], "uri-stem": parts[16], "user-agent": parts[21], "client-IP": parts[10]}]}])
	else:
		obj = json.dumps([{"appName": appName, "timestamp": date, "message": [{"method": parts[10], "uri-stem": parts[11], "user-agent": parts[16], "client-IP": parts[5]}]}])
	
	write.write(obj + '\n')
	write.close()

def apacheErrParse(line,app):
	# search for timestamp and message in line and create list
	timestampPattern = r"[[](...\s...\s\d\d\s\d\d.\d\d.\d\d.\d\d\d\d\d\d\s\d\d\d\d[]])"
	timestamp = search(timestampPattern,line).group(0)
	appName = "apache-"+app+"-err-ssl"
	write = open("ParsedLogs/apache-err-ssl.json","a")
	stampParts = timestamp.split(" ")

	month = stampParts[1]
	day = stampParts[2]
	year = search(r"\d\d\d\d",stampParts[4]).group(0)
	t = search(r"\d\d[:]\d\d[:]\d\d",stampParts[3]).group(0)
	date = month + " " + day + " " + year + " " + t

	

	parts = line.split(" ")
	message = " ".join(parts[15:])
	obj = json.dumps([{"appName": appName, "timestamp": date, "message": message}])
	
	write.write(obj + '\n')
	write.close()

def dacsParse(line):
	# search for timestamp and message in line and create list
	timestampPattern = r"[[](...\s...\s\d\d\s\d\d.\d\d.\d\d\s\d\d\d\d)[]]"
	parts = line.split(" ")
	appName = "dacs"
	
	write = open("ParsedLogs/" + appName + ".json","a")
	
	timestamp = search(timestampPattern,line).group(0)
	message = " ".join(parts[12:])

	stampParts = timestamp.split(" ")

	month = stampParts[1]
	day = stampParts[2]
	year = search(r"\d\d\d\d",stampParts[4]).group(0)
	t = search(r"\d\d[:]\d\d[:]\d\d",stampParts[3]).group(0)
	date = month + " " + day + " " + year + " " + t
	
	obj = json.dumps([{"appName": appName, "timestamp": date, "message": message}])
	
	write.write(obj + '\n')
	write.close()

def sedispatchParse(line):
	parts = line.split(" ")
	appName = "sedispatch"
	
	write = open("ParsedLogs/" + appName + ".json","a")
	
	time = parts[2]
	date = parts[0] + " " + parts[1] + " " + str(datetime.now().year) + " " + time	
	message = " ".join(parts[4:])
	obj = json.dumps([{"appName": appName, "timestamp": date, "message": message}])
	write.write(obj + '\n')	
	write.close()

def sshdParse(line):
	parts = line.split(" ")
	timestamp = parts[0]
	appName = "sshd"
	
	write = open("ParsedLogs/" + appName + ".json","a")
	
	time = parts[2]
	date = parts[0] + " " + parts[1] + " " + str(datetime.now().year) + " " + time	
	message = " ".join(parts[4:])
	
	obj = json.dumps([{"appName": appName, "timestamp": date, "message": message}])
	
	write.write(obj + '\n')
	write.close()



if __name__ == "__main__":

	file = open("all-messages.log","r")
	
	fName = strftime("%d\%m\%Y-%H:%M")
	
	n = 0
	
	for line in file:
		appDefiner(line)
		n = n + 1
		print n
		
	file.close()