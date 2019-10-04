import os, sys, struct

def Bin2Bcd(hexList):
	return 16 * int(hexList[0]) + int(hexList[1])

if __name__ == '__main__':

	if(len(sys.argv) != 3):
		print("Usage: %s <Source HydraNFC TXT File> <Output CSV File>" \
		%os.path.basename(sys.argv[0]))
		sys.exit(2)

	infile = open(sys.argv[1], 'r')
	#outfile = open(sys.argv[2], 'w')
	
	allSrcDataList = []
	lineTokenList = []
	lineDecodedTokenList = []
	lineNum = 0
	timeMicroSec = 0
	timeMicroSecPrev = 0
	timeDeltaMicroSec = 0
	timeRelativeMicroSec = 0

	for line in infile:
		lineNum +=1
		tabCount = line.count('\t')
		#print("Count %d " %(tabCount))
		if(tabCount==2):
			lineTokenList=line.split('\t')
			lineDecodedTokenList.clear()
			
			# 10ms delay: 1680030 cycles. 1us = 168 CPU cycles
			if(timeMicroSecPrev==0):
				timeMicroSec = int(lineTokenList[0], 16)
				timeMicroSecPrev = timeMicroSec
			else:
				timeMicroSecPrev = timeMicroSec
				timeMicroSec = int(lineTokenList[0], 16)
				
			timeDeltaMicroSec = timeMicroSec - timeMicroSecPrev
			if(timeDeltaMicroSec<0):
				timeDeltaMicroSec += 2**32
				
			timeRelativeMicroSec += timeDeltaMicroSec
			
			lineDecodedTokenList.append(int(timeRelativeMicroSec/168))
			lineDecodedTokenList.append(int(timeDeltaMicroSec/168))
			
			print(lineTokenList+lineDecodedTokenList)
			allSrcDataList.append(lineTokenList)
		else:
			print("Malformed line %d ignored" %(lineNum))

		
	#print(allSrcDataList)
	infile.close()


