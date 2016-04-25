from sklearn import tree
import time

t_end = time.time() + 15
counter = 0

#basic prediction algorithm
features = [[0, 0],[0, 0],[0, 1],[1, 1]] #first index GET = 0, POST =1               second index root dir = 0, other dir = 1
labels = [0, 0, 1, 2] #0-bad, 1-maybe, 2-good
clf = tree.DecisionTreeClassifier()
clf = clf.fit(features, labels)

#convert json objects into ints
file = open("intTest", "r")

#loop for 15 seconds 
while time.time() < t_end:
	#add other elements
	for line in file:
		feature1 = int(line[1])
		feature2 = int(line[3])
		label1 = 0
		if(clf.predict([feature1,feature2])==[0]):
			print "bad"
			#start a counter on bad predictions
			counter = counter + 1
			label1 = 0
			if(counter > 10):
				print counter
				break;
		elif(clf.predict([feature1,feature2])==[1]):
			print "maybs"
			label1 = 1

		elif(clf.predict([feature1,feature2])==[2]):
			print "good to go"
			label1 = 2
		else:
			print "error"
		features.append([feature1, feature2])
		labels.append(label1)
		clf = tree.DecisionTreeClassifier()
		clf = clf.fit(features, labels)
	break;
if(counter > 10):
	#if bad reaches limit, print "attack"
	print "You're being attackeddddd!!!!!!!!!!!!!"
else:
	counter = 0