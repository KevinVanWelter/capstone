import json
from re import *

def appDefiner(line):
	parts = line.split(" ")
	app = parts[2]
	if search(r"postgres",app):
		postgresParse(line)
	elif search(r"apache-carbon-ssl",app):
		apacheCarbonParse(line)
	elif search(r"dacs",app):
		dacsParse(line)
	elif search(r"apache-carbon-err-ssl",app):
		apacheCarbonErrParse(line)
	elif search(r"sedispatch",app):
		sedispatchParse(line)
	elif search(r"sshd",app):
		sshdParse(line)


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

def apacheCarbonParse(line):
	timestampPattern = r"[[]\d\d.....\d\d\d\d[:]\d\d[:]\d\d[:]\d\d\s.\d\d\d\d[]]"
	timestamp = search(timestampPattern,line).group(0)
	appName = "apache-carbon-ssl"

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
	print date
	time.write(appName + " "  + timestamp + "\n")

	parts = line.split(" ")
	ip = parts[3]
	message = " ".join(parts[8:])
	obj = json.dumps([{"appName": appName, "timestamp": date, "message": message, "ip": ip}])
	
	write.write(obj + '\n')

def apacheCarbonErrParse(line):
	# search for timestamp and message in line and create list
	timestampPattern = r"[[](...\s...\s\d\d\s\d\d.\d\d.\d\d.\d\d\d\d\d\d\s\d\d\d\d[]])"
	timestamp = search(timestampPattern,line).group(0)
	stampParts = timestamp.split(" ")

	month = stampParts[1]
	day = stampParts[2]
	year = search(r"\d\d\d\d",stampParts[4]).group(0)
	t = search(r"\d\d[:]\d\d[:]\d\d",stampParts[3]).group(0)
	date = month + " " + day + " " + year + " " + t
	print date
	appName = "apache-carbon-err-ssl"

	time.write(appName + " "  + date + "\n")

	parts = line.split(" ")
	message = " ".join(parts[15:])
	ip = 0
	obj = json.dumps([{"appName": appName, "timestamp": date, "message": message, "ip": ip}])
	
	write.write(obj + '\n')

def dacsParse(line):
	# search for timestamp and message in line and create list
	timestampPattern = r"[[](...\s...\s\d\d\s\d\d.\d\d.\d\d\s\d\d\d\d)[]]"
	parts = line.split(" ")
	appName = "dacs"
	timestamp = search(timestampPattern,line).group(0)
	message = " ".join(parts[12:])

	stampParts = timestamp.split(" ")

	month = stampParts[1]
	day = stampParts[2]
	year = search(r"\d\d\d\d",stampParts[4]).group(0)
	t = search(r"\d\d[:]\d\d[:]\d\d",stampParts[3]).group(0)
	date = month + " " + day + " " + year + " " + t
	print date
	time.write(appName + " "  + date + "\n")

	ip = 0
	obj = json.dumps([{"appName": appName, "timestamp": date, "message": message, "ip": ip}])
	
	write.write(obj + '\n')

def sedispatchParse(line):
	parts = line.split(" ")
	timestamp = parts[0]
	appName = "sedispatch"
	time.write(appName + " "  + timestamp + "\n")
	message = " ".join(parts[3:])
	date = search(r"\d\d\d\d.\d\d.\d\d",timestamp).group(0)
	dateParts = date.split("-")
	year = dateParts[0]
	month = dateParts[1]
	day = dateParts[2]
	m = monthBuilder(month)
	t = search(r"\d\d[:]\d\d[:]\d\d",timestamp).group(0) 
	ip = 0
	date = m + " " + day + " " + year + " " + t 
	obj = json.dumps([{"appName": appName, "timestamp": date, "message": message, "ip": ip}])
	write.write(obj + '\n')

def sshdParse(line):
	parts = line.split(" ")
	timestamp = parts[0]
	appName = "sshd"

	message = " ".join(parts[3:])
	time.write(appName + " "  + timestamp + "\n")
	date = search(r"\d\d\d\d.\d\d.\d\d",timestamp).group(0)
	dateParts = date.split("-")
	year = dateParts[0]
	month = dateParts[1]
	day = dateParts[2]
	m = monthBuilder(month)
	t = search(r"\d\d[:]\d\d[:]\d\d",timestamp).group(0) 
	ip = 0
	date = m + " " + day + " " + year + " " + t 
	print date
	ip = 0
	obj = json.dumps([{"appName": appName, "timestamp": date, "message": message, "ip": ip}])
	
	write.write(obj + '\n')



if __name__ == "__main__":

	file = open("all-messages.log","r")
	time = open("stamps", "w")
	#change to append
	write = open("parsed.log","w")
	for line in file:
		appDefiner(line)
	file.close()
	write.close()
	time.close()