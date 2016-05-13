#																			#
#  This program takes in input from parsed NFIS logs						#
#  It outputs weather the NFIS web applications are under attack or not		#
#																			#
#  Developed by: Jacob van der Vliet, Kevin Van Welter						#
#																			#


from sklearn import tree
from re import *
from socket import *
import time, os, json

## _-_-_-_-_-_-_-_-_-_-_ Functions  _-_-_-_-_-_-_-_-_-_-_ ##


def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1
	
## _-_-_-_-_-_-_-_-_-_-_ Globals  _-_-_-_-_-_-_-_-_-_-_ ##


# [Method, directory, seen?, client-agent, msg-repeated]
# Method: 0 = GET, 1 = Other
# Directory: 0 = Root, 1 = Other
# Seen Before: 0 = Yes + Possible DDoS, 1 = Yes, 2 = No
# Client Agent: 0 = Not a Browser, 1 = Browser
# Msg-Repeated: # = amount of times it has been repeated
features = [
		[0,0,0,0,0], 
		[0,0,1,0,0],
		[0,1,0,0,0],
		[0,1,1,0,0],
		[1,0,0,0,0],
		[1,0,1,0,0],
		[1,1,0,0,0],
		[1,1,1,0,0],
		[0,0,2,0,0],
		[0,1,2,0,0],
		[1,0,2,0,0],
		[1,1,2,0,0],
		
		[0,0,0,1,0],
		[0,0,1,1,0],
		[0,1,0,1,0],
		[0,1,1,1,0],
		[1,0,0,1,0],
		[1,0,1,1,0],
		[1,1,0,1,0],
		[1,1,1,1,0],
		[0,0,2,1,0],
		[0,1,2,1,0],
		[1,0,2,1,0],
		[1,1,2,1,0],
		
		[0,0,0,0,5], 
		[0,0,1,0,10],
		[0,1,0,0,15],
		[0,1,1,0,20],
		[1,0,0,0,30],
		[1,0,1,0,137],
		[1,1,0,0,189],
		[1,1,1,0,79],
		[0,0,2,0,82],
		[0,1,2,0,13],
		[1,0,2,0,12],
		[1,1,2,0,11],
		
		[0,0,0,1,8],
		[0,0,1,1,5],
		[0,1,0,1,3],
		[0,1,1,1,7],
		[1,0,0,1,3],
		[1,0,1,1,23],
		[1,1,0,1,24],
		[1,1,1,1,389],
		[0,0,2,1,42],
		[0,1,2,1,43],
		[1,0,2,1,6],
		[1,1,2,1,9]
	] 

# 0 = Bad, 1 = Maybe, 2 = Good
labels = [
	  0,0,0,0,0,0,0,1,1,1,0,1,
	  0,1,0,1,0,1,0,2,2,2,1,2,
	  0,0,0,0,0,0,0,0,0,0,0,0,
	  0,1,0,1,0,1,0,2,2,2,1,2
	]
	
clf = tree.DecisionTreeClassifier()
clf = clf.fit(features, labels)

# Number of Requests before an IP is labeled as "bad"
# On Root
n = 10
# Not on Rroot
m = 40

# If # of bad requests exceeds this Alert
counterMax = 500

## _-_-_-_-_-_-_-_-_-_-_ Start of Execution  _-_-_-_-_-_-_-_-_-_-_ ##

while True:
	
	# Reset bad counter for new batch
	counter = 0
	
	# Parse the logs into JSON sleep to ensure it is finished
	os.system("../Parsing/parselogs.sh")
	time.sleep(5)
	
	# Sample output file ### REMOVE ###
	wFile = open("testing.txt","w")
	
	# Used for calculating percent completed
	x = 0
	lastPerc = 0

	try:
		
		# Total lines of parsed file (used for calculating completetion)
		totalLines = file_len("../Parsing/ParsedLogs/apache-ssl.json")
		
		# Open the JSON file for reading
		file = open("../Parsing/ParsedLogs/apache-ssl.json", "r")
		
		ips = {}

		browsers = [r'chrome',r'mozilla',r'explorer',r'edge',r'opera',r'safari',r'Chrome',r'Mozilla',r'Explorer',r'Edge',r'Opera',r'Safari']
		
		for jsonLine in file:
			
			# Calculate percent completed #
			x = x + 1
			percentage = 100 * x / totalLines
			if (percentage != lastPerc):
				print percentage, '%'
				lastPerc = percentage
			
			obj = json.loads(jsonLine)
			## _-_-_-_-_-_-_-_-_-_-_-_-_ ##
			
			msgRepeated = 0
			if obj['message'] == "400 error":
				senip = 0
				method = 0
				stem = 1
				brow = 0
				msgRepeated = 1
			else:
				cAgent = obj['message']['user-agent']
				for i in browsers:
					if (search(i, cAgent)):
						brow = 1
					else:
						brow = 0
					
				
				#check method
				if search(r"GET",obj['message']['method']):
					method = 0
					#check stem
					if (int(float(obj['message']['repeated'])) >= 10):
						msgRepeated = int(float(obj['message']['repeated']))
					if (obj['message']['uri-stem'] == '/' or obj['message']['uri-stem'] == '/en'):
						stem = 0
						#check if IP exists
						if obj['message']['client-IP'] in ips:
							ips[obj['message']['client-IP']] = ips[obj['message']['client-IP']] + 1

							#how many times has the ip been seen?
							if ips[obj['message']['client-IP']] > n:
								senip = 0
							else:
								senip = 1
						else:
							senip = 2
							ips[obj['message']['client-IP']] = 1

					#if stem is not root
					else:
						if (obj['message']['repeated'] >= 10):
							msgRepeated = 0
						stem = 1
						#check if ip exists
						if obj['message']['client-IP'] in ips:
							ips[obj['message']['client-IP']] = ips[obj['message']['client-IP']] + 1

							#how many times has the ip been seen?
							if ips[obj['message']['client-IP']] > m:
								senip = 0
							else:
								senip = 1
						else:
							senip = 2
							ips[obj['message']['client-IP']] = 1
				else:
					method = 1
					stem = 1
					senip = 1
					brow = 1
					msgRepeated = 1

			# _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_- #
			
			a = method
			b = stem
			c = senip
			d = brow
			e = msgRepeated
			
			label1 = 0

			if(clf.predict([a,b,c,d,e])==[0]):
				#print "bad"
				wFile.write("bad\n")	
				counter = counter + 1 + e
				label1 = 0
			elif(clf.predict([a,b,c,d,e])==[1]):
				#print "maybs"
				wFile.write("maybe\n")
				label1 = 1
			elif(clf.predict([a,b,c,d,e])==[2]):
				#print "good to go"
				wFile.write("safe\n")
				label1 = 2
			else:
				print "error"			
			
			# features.append([a,b,c,d])
			# labels.append(label1)
			# clf = tree.DecisionTreeClassifier()
			# clf = clf.fit(features, labels)
			
		if(counter > counterMax):
			wFile.write("Attack\n")
			print counter
			print "Attack"
		else:
			print counter
			counter = 0
			print "Safe"
		file.close()
		wFile.close()
		
		print "Done"
		time.sleep(15)


	except IOError as e:
		print "I/O error({0}): {1}".format(e.errno, e.strerror)	
