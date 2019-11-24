import os, sys, struct
import yaml

from enum import *

from bitmask import BitMask
from cmdprocessor import *
from apduprocessor import *

ConsoleDebugOutput = False
#ConsoleDebugOutput = True

bBinaryMode = False

class NoValue(Enum):
    def __repr__(self):
    	return '<%s.%s>' % (self.__class__.__name__, self.name)

class CouplingDevice(NoValue):
	PICC = 'PICC'
	PCD = 'PCD'
	UNK = 'Unknown'
	
#CouplingDevice.PICC.value will return 'PICC'
		
DecoderState = Enum('DecoderState', '''
INIT
REQAWUPA
ATQA
ANTICOL1
ANTICOL2
ANTICOL3
UID
SELECT1
SELECT2
SELECT3
SAK
RATS
ATS
PROT4
DESELECT
MIFAUTH
MIFTOKENRB
MIFTOKENAB
MIFTOKENBA
MIFENCRYPTED
MIFWRITEA
MIFWRITEB
MIFWRITEBA
MIFREAD
ANY
SAME
''')


def CRC_16A(msg):
	poly = 0x8408
	crc = 0x6363
	for byte in msg:
		for _ in range(8):
			if (byte ^ crc) & 1:
				crc = (crc >> 1) ^ poly
			else:
				crc >>= 1
			byte >>= 1
	return [crc & 0xFF, crc >> 8]


class FrameDecoder:
	def __init__(self, cmdDB, procClass, decoderState = DecoderState.INIT):
		self._state = decoderState
		self._frameSrc = CouplingDevice.UNK
		self._log = []
		self._logDetail = []
		self._frameDataL = []
		self._lineNum = 0
		self._db = cmdDB
		self._procClass = procClass
		
	@property
	def frameSrc(self):
		if(self._frameSrc == CouplingDevice.PCD):
			return "RDR"
		elif(self._frameSrc == CouplingDevice.PICC):
			return "TAG"
		else:
			return "UNK"
		
	def newFrame(self, frameData, frameSrc, lineN):
		self._frameData = frameData
		self._lineNum = lineN
		self._log.clear()
		self._logDetail.clear()
		
		if(frameSrc=="RDR"):
			self._frameSrc = CouplingDevice.PCD
		elif(frameSrc=="TAG"):
			self._frameSrc = CouplingDevice.PICC
		else:
			self._frameSrc = CouplingDevice.UNK
			
		self._frameDataL = [int(i, 16) for i in self._frameData]
		if (ConsoleDebugOutput):
			print("Current State ", self._state)
			print("======================================== Incoming Frame ", [hex(x) for x in self._frameDataL])
			print("Current input line ", self._lineNum)
			
		for self._entry in self._db:
			#print("checking entry ", self._entry)
			match = False
			# only look through list entries from the same source as current frame
			if (self._entry['src'] != self._frameSrc.value):
				continue
			#print("dbg ", self._entry['cmdlen'], self._state, self._entry['state_cur'])
			
			# need to eval if comes from YAML
			if (type(self._entry['state_cur']) is str):
				self._entry['state_cur'] = eval(self._entry['state_cur'])
			if (type(self._entry['state_nxt']) is str):
				self._entry['state_nxt'] = eval(self._entry['state_nxt'])

			# if value is an empty list then pick the first entry matching our state machine
			# script state cannot be DecoderState.ANY for wildcard match as there is nothing else for the search engine to latch on
			if (self._entry['value'] == [] and type(self._entry['state_cur']) is list and self._state in self._entry['state_cur']):
				match = True
			if (self._entry['value'] == [] and type(self._entry['state_cur']) is not list and self._state == self._entry['state_cur']):
				match = True
			if (match):
				if (ConsoleDebugOutput):
					print("match entry wildcard ", self._entry['label'])

				self.checkCRC()

				# allow state machine to retain it's previous state for DecoderState.SAME
				if (self._entry['state_nxt'] != DecoderState.SAME):
					self._state = self._entry['state_nxt']
					
				if ('log' in self._entry):
					self._log.append(self._entry['log'])
				if ('data' in self._entry):
					for testElem in self._entry['data']:
						# for negative offsets point at the data from the right, e.g. -1 points to the last byte
						if (testElem['offset'] < 0):
							dataOffset = testElem['offset']
						else:
							dataOffset = self._entry['cmdlen'] + testElem['offset']
							
						try:
							self._frameDataL[dataOffset]
							
							# add to log and execute a proc when either happens:
							# 1. test bits condition satisfied
							# 2. direct value vector matches
							# 1 and 2 are mutually exclusive
							logNproc = False
							
							# check for specific values given
							# if value is a list then check by elements in list
							# note in case of negative offset, value list should also be approcached 'from the right'
							# e.g. offset -1 and value 90 00 means 00 is at -1 and 90 is at -2
							if ('value' in testElem):
								if (type(testElem['value']) is list):
									if (testElem['offset'] < 0):
										offsetStart = 1+dataOffset-len(testElem['value'])
										offsetEnd = 1+dataOffset
										if (offsetEnd == 0):
											if (self._frameDataL[offsetStart:] == testElem['value']):
												self._logDetail.append('Value %s at offset %d' % (str(" ".join(["{0:02x}".format(x) for x in testElem['value']])), offsetStart))
												logNproc = True
										else:
											if (self._frameDataL[offsetStart:offsetEnd] == testElem['value']):
												self._logDetail.append('Value %s at offset %d' % (str(" ".join(["{0:02x}".format(x) for x in testElem['value']])), offsetStart))
												logNproc = True
									else:
										if (self._frameDataL[dataOffset:dataOffset+len(testElem['value'])] == testElem['value']):
											self._logDetail.append('Value %s at offset %d' % (str(" ".join(["{0:02x}".format(x) for x in testElem['value']])), offsetStart))
											logNproc = True
								else:
									if (self._frameDataL[dataOffset] == testElem['value']):
										self._logDetail.append('Value 0x%02x at offset %d' % (self._frameDataL[dataOffset], dataOffset))
										logNproc = True
										
							else:
								# if test bits not supplied then log the byte's value as a whole
								if ('test_bits_on' not in testElem and 'test_bits_off' not in testElem):
									self._logDetail.append('Value 0x%02x at offset %d' % (self._frameDataL[dataOffset], dataOffset))
								if ('test_bits_on' in testElem):
									# need to eval if comes from YAML
									if (type(testElem['test_bits_on']) is str):
										bitsOn = eval(testElem['test_bits_on'])
									else:
										bitsOn = testElem['test_bits_on']
									
									if ((self._frameDataL[dataOffset] & bitsOn) == bitsOn):
										bOn = 1
									else:
										bOn = 0
								else:
									bOn = 1
								if ('test_bits_off' in testElem):
									# need to eval if comes from YAML
									if (type(testElem['test_bits_off']) is str):
										bitsOff = eval(testElem['test_bits_off'])
									else:
										bitsOff = testElem['test_bits_off']
									bOff = self._frameDataL[dataOffset] & bitsOff
								else:
									bOff = 0
								if (bOn != 0 and bOff == 0):
									logNproc = True
							
							if (logNproc):
								if ('log' in testElem):
									self._logDetail.append(testElem['log'])
								if ('proc' in testElem):
									procLog = getattr(self._procClass, testElem['proc'])(self._frameDataL, dataOffset)
									if (type(procLog) is list and procLog != []):
										self._logDetail.extend(procLog)
							
						except IndexError:
							# TODO may want to know more about where and when it falls over
							pass
							
				break
				
			# if value is NOT an empty list then:
			# 1. check that we have a match of minimum length
			# 2. check entry's state matches our state machine's state unless DecoderState.ANY is given
			# 3. check 'command' value matches that of the input frame
			
			if ('frame_fixedlen' in self._entry):
				if (len(self._frameDataL) != self._entry['frame_fixedlen']):
					continue
			elif (len(self._frameDataL) < (self._entry['cmdlen'] + self._entry['datalen'])):
				continue
			
			if (self._frameDataL[0:self._entry['cmdlen']] == self._entry['value']):
				if (type(self._entry['state_cur']) is list and (self._state in self._entry['state_cur'] or DecoderState.ANY in self._entry['state_cur'])):
					match = True
				if (type(self._entry['state_cur']) is not list and (self._state == self._entry['state_cur'] or self._entry['state_cur'] == DecoderState.ANY)):
					match = True

				if (match):
					if (ConsoleDebugOutput):
						print("match entry ", self._entry['label'])
					
					self.checkCRC()
						
					# allow state machine to retain it's previous state for DecoderState.SAME
					if (self._entry['state_nxt'] != DecoderState.SAME):
						self._state = self._entry['state_nxt']
						
					if ('log' in self._entry):
						self._log.append(self._entry['log'])
					break
		
		else:
			self._log.append(',UNABLE TO INTERPRET')


	def status(self):
		print("State ", self._state)
		print("Frame came from ", self._frameSrc.value)
		print("Frame data ", [hex(x) for x in self._frameDataL])
		print("******************** LOG ********************** Frame info ", self._log)
		print("******************** LOG2 ********************* Frame info ", self._logDetail)
		
	def getLog(self):
		return self._log
		
	def getLogDetail(self):
		return self._logDetail
		
	def checkCRC(self):
		if ('crc' in self._entry and self._entry['crc'] != 0):
			crc16A = CRC_16A(self._frameDataL[0:-2])
			if (self._frameDataL[-2:] != crc16A):
				self._log.append('CRC MISMATCH: %s vs %s received' % (str(" ".join([hex(x) for x in crc16A])), str(" ".join([hex(x) for x in self._frameDataL[-2:]]))))
			else:
				self._log.append('CRC MATCH: (%s)' % str(" ".join([hex(x) for x in crc16A])))
		else:
			self._log.append('CRC N/A (or Short Frame)')


class FrameTime:
	def __init__(self):
		self._timeMicroSec = 0
		self._timeMicroSecPrev = 0
		self._timeDeltaMicroSec = 0
		self._timeRelativeMicroSec = 0

	def newFrameTime(self, cpuCycles):
		# 10ms delay: 1680030 cycles. 1us = 168 CPU cycles
		if(self._timeMicroSecPrev==0):
			self._timeMicroSec = int(cpuCycles, 16)
			self._timeMicroSecPrev = self._timeMicroSec
		else:
			self._timeMicroSecPrev = self._timeMicroSec
			self._timeMicroSec = int(cpuCycles, 16)
			
		self._timeDeltaMicroSec = self._timeMicroSec - self._timeMicroSecPrev
		if(self._timeDeltaMicroSec<0):
			self._timeDeltaMicroSec += 2**32
			
		self._timeRelativeMicroSec += self._timeDeltaMicroSec

	@property
	def timeRelativeMicroSec(self):
		return int(self._timeRelativeMicroSec/168)

	@property
	def timeDeltaMicroSec(self):
		return int(self._timeDeltaMicroSec/168)

	@timeRelativeMicroSec.setter
	def timeRelativeMicroSec(self, value):
		if value < 0:
			raise ValueError("not possible")
		print("Setting value")
		self._timeRelativeMicroSec = timeRelativeMicroSec


def getBinElement(binFile):
	fileSize = binFile.seek(-1, 2) + 1
	binFile.seek(0)
	if (ConsoleDebugOutput):
		print('File size is ', fileSize)
	#for fileOffest in range(0, fileSize):
	while (binFile.tell() < fileSize):
		bSuccess = False
		#fileOffest = binFile.tell()
		if (ConsoleDebugOutput):
			print('New element at ', binFile.tell())
		protOptionsB = binFile.read(1)
		if (protOptionsB != ''):
			protOptions = int.from_bytes(protOptionsB, byteorder='little')
			if (protOptions & BitMask.B3):
				bStartTimestamp = True
			else:
				bStartTimestamp = False
				
			if (protOptions & BitMask.B4):
				bEndTimestamp = True
			else:
				bEndTimestamp = False
				
			if (protOptions & BitMask.B5):
				bParity = True
			else:
				bParity = False
				
			protModulB = binFile.read(1)
			protModul = int.from_bytes(protModulB, byteorder='little')
			if (protModul != ''):
				if (protModul == 1):
					frameSrc = 'RDR'
				elif (protModul == 2):
					frameSrc = 'TAG'
				else:
					frameSrc = 'UNK'
					
				encLen = binFile.read(2)
				if (len(encLen) == 2):
					frameLen = int.from_bytes(encLen, byteorder='little')
					# already read 4 bytes (length is the length of entire frame)
					frameLen -= 4
					frameData = binFile.read(frameLen)
					if (ConsoleDebugOutput):
						print('frameLen ', frameLen)
						print('frameData ', str(" ".join(["{0:02x}".format(x) for x in list(frameData)])))
					
					if (len(frameData) == frameLen):
						dataStartPtr = 0
						dataEndPtr = frameLen
						if (bStartTimestamp):
							startTimestamp = int.from_bytes(frameData[0:4], byteorder='little')
							dataStartPtr += 4
						else:
							startTimestamp = 0
						if (bEndTimestamp):
							endTimestamp = int.from_bytes(frameData[-4:], byteorder='little')
							dataEndPtr -= 4
						else:
							endTimestamp = 0
							
						bSuccess = True
						dataBytes = b''
						parityBytes = b''
						if (bParity):
							dataAndParityList = bytearray(frameData[dataStartPtr:dataEndPtr])
							bOdd = False
							if ((dataEndPtr-dataStartPtr)%2 == 1):
								bOdd = True
								dataAndParityList.append(0)
								if (ConsoleDebugOutput):
									print('odd len at ', binFile.tell())
							try:
								frameDataIter = struct.iter_unpack('@cc', dataAndParityList)
							except struct.error:
								print('struct error! File offset ', binFile.tell())
								print('frameLen ', frameLen)
								print('frameData ', str(" ".join(["{0:02x}".format(x) for x in list(frameData)])))
								print('dataStartPtr ', dataStartPtr)
								print('dataEndPtr ', dataEndPtr)
							for byteAndParity in frameDataIter:
								dataBytes += byteAndParity[0]
								parityBytes += byteAndParity[1]
							parityDataSet = set(parityBytes)
							parityTestSet = set([0,1])
							diffSet = parityDataSet-parityTestSet
							if diffSet:
								print('Error! Parity bytes are not 0 or 1')
								print('set test ', diffSet)
								print('dataBytes ', dataBytes)
								print('parityBytes ', parityBytes)
						else:
							dataBytes = frameData[dataStartPtr:dataEndPtr]
							
		if (bSuccess):
			yield bSuccess, "{0:08x}".format(startTimestamp), "{0:08x}".format(endTimestamp), frameSrc, ["{0:02x}".format(x) for x in list(dataBytes)], list(parityBytes)
		else:
			yield bSuccess,

def logFrame():
	pass

        
if __name__ == '__main__':

	if(len(sys.argv) != 2):
		#print("Usage: %s <Source HydraNFC TXT File> <Output CSV File>" \
		print("Usage: %s <Source HydraNFC TXT (.txt) or BIN (.bin) File>" \
		%os.path.basename(sys.argv[0]))
		sys.exit(2)

	with open('data/db.yml', 'r') as f:
		decoderDB = yaml.load(f)
	
	with open('data/db_apdu.yml', 'r') as f:
		apduDB = yaml.load(f)
		
	#nameWoExt = os.path.splitext(sys.argv[1])[0]
	nameWoExt, extWoName = os.path.splitext(sys.argv[1])
	
	if (extWoName == '.bin'):
		bBinaryMode = True
		infile = open(sys.argv[1], 'rb')
	else:
		infile = open(sys.argv[1], 'r')
		
	outfile = open(nameWoExt+'.csv', 'w')
	#outfileApdu = open(nameWoExt+'.apdu', 'w')
	
	allSrcDataList = []
	lineTokenList = []
	lineDecodedTokenList = []
	dataFrameList = []
	lineNum = 0
	frameTimestamp = FrameTime()
	procCmdA = ProcessorCmdA()
	procApdu = ProcessorApdu()
	frameDec = FrameDecoder(decoderDB, procCmdA)
	frameDecApdu = FrameDecoder(apduDB, procApdu, DecoderState.PROT4)
	headerStr = 'CPU Cycles,Originator,Data Received,Time elapsed in uS,Time Delta in uS,CRC,Data Interpretation,Further Details,APDU,APDU Basic Info,APDU Detailed Info'
	outfile.write(headerStr+'\n')

	if (bBinaryMode):
		for binElement in getBinElement(infile):
			lineNum +=1
			if (ConsoleDebugOutput):
				print('element: ', binElement)
			if (binElement[0] == True):
				lineTokenList.clear()
				lineTokenList.append(binElement[1])
				lineTokenList.append(binElement[3])
				lineTokenList.append('\"'+" ".join(binElement[4])+'\"')
				
				lineDecodedTokenList.clear()

				frameTimestamp.newFrameTime(binElement[1])

				lineDecodedTokenList.append(frameTimestamp.timeRelativeMicroSec)
				lineDecodedTokenList.append(frameTimestamp.timeDeltaMicroSec)

				frameDec.newFrame(binElement[4], binElement[3], lineNum)
				
				if (ConsoleDebugOutput):
					frameDec.status()
					
				logMainL = lineTokenList+lineDecodedTokenList+frameDec.getLog()
				logMainStr = ''
				for logEntry in logMainL:
					logMainStr += str(logEntry)+','
				logMainStr += '\n'
				
				logDetailL = frameDec.getLogDetail()
				logDetailStr = ''
				if (logDetailL != []):
					for logEntry in logDetailL:
						logDetailStr += ',,,,,,,'+str(logEntry)+','+'\n'
						
				outfile.write(logMainStr)
				outfile.write(logDetailStr)
				
				# apdu details will follow
				if (procCmdA.isNewApdu):
					apduData = procCmdA.getNewApdu()
					#outfile.write(",,,,,,,,%s\n" %  str(" ".join(["{0:02x}".format(x) for x in apduData])))
					#if (ConsoleDebugOutput):
					#	print('New apdu ', str(" ".join(["{0:02x}".format(x) for x in apduData])))
					frameDecApdu.newFrame(apduData, frameDec.frameSrc, lineNum)
					
					if (ConsoleDebugOutput):
						print('APDU Frame status: ')
						frameDecApdu.status()
						
					logMainL = frameDecApdu.getLog()
					logMainStr = ''
					for logEntry in logMainL:
						logMainStr += ',,,,,,,,,'+str(logEntry)+','+'\n'
					
					logDetailL = frameDecApdu.getLogDetail()
					logDetailStr = ''
					if (logDetailL != []):
						for logEntry in logDetailL:
							logDetailStr += ',,,,,,,,,,'+str(logEntry)+','+'\n'
							
					outfile.write(logMainStr)
					outfile.write(logDetailStr)
			else:
				print('element parsing error at frame: ', lineNum)
	else:
		for line in infile:
			lineNum +=1
			tabCount = line.count('\t')
			if(tabCount==2):
				lineTokenList=line.split('\t')
				lineDecodedTokenList.clear()
				
				frameTimestamp.newFrameTime(lineTokenList[0])
				
				lineDecodedTokenList.append(frameTimestamp.timeRelativeMicroSec)
				lineDecodedTokenList.append(frameTimestamp.timeDeltaMicroSec)
				
				dataFrameList = lineTokenList[2].split()
				lineTokenList[2] = '\"'+" ".join(dataFrameList)+'\"'
				frameDec.newFrame(dataFrameList, lineTokenList[1], lineNum)
				
				if (ConsoleDebugOutput):
					frameDec.status()
					
				logMainL = lineTokenList+lineDecodedTokenList+frameDec.getLog()
				logMainStr = ''
				for logEntry in logMainL:
					logMainStr += str(logEntry)+','
				logMainStr += '\n'
				
				logDetailL = frameDec.getLogDetail()
				logDetailStr = ''
				if (logDetailL != []):
					for logEntry in logDetailL:
						logDetailStr += ',,,,,,,'+str(logEntry)+','+'\n'
						
				outfile.write(logMainStr)
				outfile.write(logDetailStr)
				
				# apdu details will follow
				if (procCmdA.isNewApdu):
					apduData = procCmdA.getNewApdu()
					#outfile.write(",,,,,,,,%s\n" %  str(" ".join(["{0:02x}".format(x) for x in apduData])))
					#if (ConsoleDebugOutput):
					#	print('New apdu ', str(" ".join(["{0:02x}".format(x) for x in apduData])))
					frameDecApdu.newFrame(apduData, frameDec.frameSrc, lineNum)
					
					if (ConsoleDebugOutput):
						print('APDU Frame status: ')
						frameDecApdu.status()
						
					logMainL = frameDecApdu.getLog()
					logMainStr = ''
					for logEntry in logMainL:
						logMainStr += ',,,,,,,,,'+str(logEntry)+','+'\n'
					
					logDetailL = frameDecApdu.getLogDetail()
					logDetailStr = ''
					if (logDetailL != []):
						for logEntry in logDetailL:
							logDetailStr += ',,,,,,,,,,'+str(logEntry)+','+'\n'
							
					outfile.write(logMainStr)
					outfile.write(logDetailStr)
			else:
				print("Malformed line %d ignored" %(lineNum))

	#for apduStr in procCmdA.getApdu():
	#	outfileApdu.write(apduStr)
	
	infile.close()
	outfile.close()
	#outfileApdu.close()
	
	print("All good, %d lines from input file processed" %(lineNum))


