from sklearn import tree
import time
import json
import os
from re import *

t_end = time.time() + 15
counter = 0

#basic prediction algorithm
features = [
		[0,0,0],
		[0,0,1],
		[0,1,0],
		[0,1,1],
		[1,0,0],
		[1,0,1],
		[1,1,0],
		[1,1,1],
		[0,0,2],
		[0,1,2],
		[1,0,2],
		[1,1,2] 
	] 
#first index GET = 0, POST =1    second index root dir = 0, other dir = 1     seen before 2=no 1=yes 0=yes+possible DDoS
labels = [0,1,0,1,0,1,0,2,2,2,1,2] #0-bad, 1-maybe, 2-good
clf = tree.DecisionTreeClassifier()
clf = clf.fit(features, labels)
newFeatures = []

#loop for 15 seconds 

wFile = open("testing.txt","w")

try:
	
	#convert json objects into ints
	file = open("../Parsing/ParsedLogs/apache-ssl.json", "r")

	#root
	n = 5
	#non-root
	m = 10

	ips = {}

	for jsonLine in file:
		obj = json.loads(jsonLine)

		if obj['message'] == "400 error":
			#print 'dad'
			senip = 0
			method = 0
			stem = 0
		else:
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
							#print 'bad'
						else:
							senip = 1
							#print 'dad'
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
							#print 'bad'
						else:
							senip = 1
							#print 'dad'
					else:
						senip = 2
						ips[obj['message']['client-IP']] = 1
			else:
				method = 1

		newFeatures.append([method,stem,senip])
		
	
	print newFeatures
	# _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_- #
	label1 = 0
	
	for line in newFeatures:
		a = line[0]
		b = line[1]
		c = line[2]
		if(clf.predict([a,b,c])==[0]):
			#print "bad"
			wFile.write("bad\n")	
			counter = counter + 1
			label1 = 0
			if(counter > 10):
				#print counter
				#wFile.write("Count: " + counter)
				break;
		elif(clf.predict([a,b,c])==[1]):
			#print "maybs"
			wFile.write("maybe\n")
			label1 = 1
		elif(clf.predict([a,b,c])==[2]):
			#print "good to go"
			wFile.write("safe\n")
			label1 = 2
		else:
			print "error"
		features.append([a,b,c])
		labels.append(label1)
		clf = tree.DecisionTreeClassifier()
		clf = clf.fit(features, labels)
	#break;
	if(counter > 10):
		#if bad reaches limit, print "attack"
		#print "You're being attackeddddd!!!!!!!!!!!!!"
		wFile.write("Attack!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
	else:
		counter = 0
	file.close()
	wFile.close()
except IOError as e:
	print "I/O error({0}): {1}".format(e.errno, e.strerror)	