#!/usr/bin/env python

'''
VirusTotal Public API client
By Ilias el Matani 2014
This is version 0.1 (Concept)
'''

import time, sys, simplejson, json
import urllib, urllib2
import postfile, json
from prettytable import PrettyTable

jsonOutput = ""
file4Upload = ""
next = ""
resourceID = ""
sleepTimer = 0

x = PrettyTable(["Antivirus", "Result", "Virus", "Update"])
x.align["Antivirus"] = "l"
x.align["Result"] = "l"
x.align["Virus"] = "l"
x.align["Update"] = "l"
x.padding_width = 1

host = "www.virustotal.com"
selector = "https://www.virustotal.com/vtapi/v2/file/scan"
fields = [("apikey", "f054d3cc98b899225eef226dacc37036b846907e6206ae938ceac440195f916e")]
urlScan = "https://www.virustotal.com/vtapi/v2/file/report"
urlReport = "https://www.virustotal.com/vtapi/v2/file/report"

def main():
    if len(sys.argv) != 2:
        print 'Usage: python', sys.argv[0], '[File]'
        sys.exit(1)
    else:
        global file4Upload
        file4Upload = sys.argv[1]
        upload()

def upload():
    global md5sum
    global next
    try:
        file_to_send = open(file4Upload, "rb").read()
    except:
        print "file not found!"
        sys.exit(1)
    files = [("file", file4Upload, file_to_send)]
    output = postfile.post_multipart(host, selector, fields, files)
    joutput = json.loads(output)
    next = joutput['md5']
    getReport(next)

def getReport(n):
    global jsonOutput
    global next
    global sleepTimer
    global resourceID
    parameters = {"resource": n, "apikey": "f054d3cc98b899225eef226dacc37036b846907e6206ae938ceac440195f916e"}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(urlScan, data)
    response = urllib2.urlopen(req)
    try:
        jsonOutput = json.loads(response.read())
        
        if(jsonOutput['response_code'] ==1):
            sleepTimer = 0
            resourceID = n
            getReportNow()
        
    except:
        print "Our job is in the queue.."
        sleepTimer += 10
        time.sleep(sleepTimer)
        getReport(next)
    
def getReportNow():
    global jsonOutput
    for i in jsonOutput['scans']:   
        x.add_row(["%s " % i, str(jsonOutput['scans'][i]['result']), str(jsonOutput['scans'][i]['detected']), str(jsonOutput['scans'][i]['update'])])
    print x  
     
if __name__ == '__main__':
    main()
