from sklearn import tree
import time
import json
import os
from re import *
from socket import *

def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1

t_end = time.time() + 15

#first index GET = 0, Other = 1 
#second index root dir = 0, other dir = 1     
#seen before 2=no 1=yes 0=yes+possible DDoS
#not browser = 0  browser = 1 

features = [
		[0,0,0,0], 
		[0,0,1,0],
		[0,1,0,0],
		[0,1,1,0],
		[1,0,0,0],
		[1,0,1,0],
		[1,1,0,0],
		[1,1,1,0],
		[0,0,2,0],
		[0,1,2,0],
		[1,0,2,0],
		[1,1,2,0],
		
		[0,0,0,1],
		[0,0,1,1],
		[0,1,0,1],
		[0,1,1,1],
		[1,0,0,1],
		[1,0,1,1],
		[1,1,0,1],
		[1,1,1,1],
		[0,0,2,1],
		[0,1,2,1],
		[1,0,2,1],
		[1,1,2,1]
	] 

labels = [
	  0,0,0,0,0,0,0,1,1,1,0,1,
	  0,1,0,1,0,1,0,2,2,2,1,2
	] #0-bad, 1-maybe, 2-good
clf = tree.DecisionTreeClassifier()
clf = clf.fit(features, labels)
#loop for 15 seconds 

## _-_-_-_-_-_-_-_-_-_-_ Start of Execution  _-_-_-_-_-_-_-_-_-_-_ ##
while True:
	counter = 0
	os.system("../Parsing/parselogs.sh")
	time.sleep(5)
	
	wFile = open("testing.txt","w")

	try:
		
		totalLines = file_len("../Parsing/ParsedLogs/apache-ssl.json")
		
		#convert json objects into ints
		file = open("../Parsing/ParsedLogs/apache-ssl.json", "r")

		#root
		n = 5

		#non-root
		m = 10

		ips = {}

		browsers = [r'chrome',r'mozilla',r'explorer',r'edge',r'opera',r'safari',r'Chrome',r'Mozilla',r'Explorer',r'Edge',r'Opera',r'Safari']
		
		x = 0
		lastPerc = 0
		
		for jsonLine in file:
			x = x + 1
			percentage = 100 * x / totalLines
			if (percentage != lastPerc):
				print percentage, '%'
				lastPerc = percentage
			
			obj = json.loads(jsonLine)
			
			if obj['message'] == "400 error":
				#print 'dad'
				senip = 0
				method = 0
				stem = 0
				brow = 0
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

			# _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_- #
			a = method
			b = stem
			c = senip
			d = brow
			label1 = 0

			if(clf.predict([a,b,c,d])==[0]):
				#print "bad"
				wFile.write("bad\n")	
				counter = counter + 1
				label1 = 0
			elif(clf.predict([a,b,c,d])==[1]):
				#print "maybs"
				wFile.write("maybe\n")
				label1 = 1
			elif(clf.predict([a,b,c,d])==[2]):
				#print "good to go"
				wFile.write("safe\n")
				label1 = 2
			else:
				print "error"
			features.append([a,b,c,d])
			labels.append(label1)
			clf = tree.DecisionTreeClassifier()
			clf = clf.fit(features, labels)
		#break;
		if(counter > 100):
			#if bad reaches limit, print "attack
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
