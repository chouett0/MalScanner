#! /usr/bin/env python

import sys
import json
import urllib
import urllib2
import os
from time import sleep

class MalScanner():

	def __init__(self):
#		self.binaries = os.listdir("/data/dionaea/binaries")
#		self.resultDir = os.listdir("/home/t-pot/ScanResult")
		self.binaries = os.listdir("/home/t1N4/MalScanner/binaries")
		self.resultDir = os.listdir("/home/t1N4/MalScanner/result")
		self.VTurl = "https://www.virustotal.com/vtapi/v2/file/report"

		self.param = {"resource": None, "apikey": "VIRUSTOTAL_API"}

	def Scanner(self):
		print "[*] Start Scanning Malware..."
		for  file in self.binaries:
			self.param["resource"] = file
			print file , " : ",
			data 		= urllib.urlencode(self.param)
			request 	= urllib2.Request(self.VTurl, data)
			response = urllib2.urlopen(request)
			res = response.read()

			with open("/home/t1N4/MalScanner/result/" + str(file) + ".json", "w") as result:
				result.write(res)

			res = json.loads(res)

			print res['scans']['Kaspersky']['result']

			"""
			for key, value in res['scans'].items():
				print "Result: ",
				print value['result']
				print "Detected: ",
				print value['detected']
			"""

			sleep(15)

		print "[*] Finish Scan"

def main():
	ms = MalScanner()
	ms.Scanner()

if __name__ == "__main__":
	main()
