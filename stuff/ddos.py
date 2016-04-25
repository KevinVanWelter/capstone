import sklearn
import json
from time import *
import os
from re import *
from datetime import datetime

#   Apache-SSL, Apache-Err-SSL, DACS, Sedispatch

if __name__ == "__main__":

    file = open("../Parsing/ParsedLogs/apache-ssl.json", "r")

    #root
    n = 5
    #non-root
    m = 10
    
    ips = {}
    i=0
    for jsonLine in file:
        obj = json.loads(jsonLine)
        i= i + 1
        print i
        
        if obj['message'] == "400 error":
            print 'dad'
        else:
            if search(r"GET",obj['message']['method']):

                if (obj['message']['uri-stem'] == '/' or obj['message']['uri-stem'] == '/en'):
                    if obj['message']['client-IP'] in ips:
                        ips[obj['message']['client-IP']] = ips[obj['message']['client-IP']] + 1
                        if ips[obj['message']['client-IP']] > n:
                            print 'bad'
                        else:
                            print 'dad'
                    else:
                        ips[obj['message']['client-IP']] = 1

                else:
                    if obj['message']['client-IP'] in ips:
                        ips[obj['message']['client-IP']] = ips[obj['message']['client-IP']] + 1
                        if ips[obj['message']['client-IP']] > m:
                            print 'bad'
                        else:
                            print 'dad'
                    else:
                        ips[obj['message']['client-IP']] = 1