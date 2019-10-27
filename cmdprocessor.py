from bitmask import BitMask

class ProcessorCmdA:
	def __init__(self):
		self._uid = []
		self._uidFinal = []
		self._isIso4 = False
		self._fsdi = 0
		self._fsd = 0
		self._cid = 0
		self._fsci = 0
		self._fsc = 0
		self._atsLen = 0
		self._isTA1 = False
		self._isTB1 = False
		self._isTC1 = False
		self._TA1 = 0x00
		self._TB1 = 0x00
		self._TC1 = 0x00
		self._atsHistBytes = []
		self._fwi = 0
		self._sfgi = 0
		self._apdu = []
		self._isNewApdu = False
		
	def uidCheckBCC(self, data, offset):
		log = []
		xored = data[offset-1] ^ data[offset-2] ^ data[offset-3] ^ data[offset-4]
		bcc = data[offset]
		if (bcc != xored):
			log.append("BCC mismatch %s vs %s" % (str(hex(bcc)), str(hex(xored))))
		else:
			log.append("BCC match %s" % str(hex(bcc)))
			
		return log

	def uidStorePart(self, data, offset):
		self._uid.append(data[offset-3])
		self._uid.append(data[offset-2])
		self._uid.append(data[offset-1])
		self._uid.append(data[offset])
		
	def uidClearParts(self, data, offset):
		self._uid.clear()
		self._uidFinal.clear()
		
	def uidFinalise(self, data, offset):
		log = []
		if (self._uidFinal == []):
			if (len(self._uid) == 8):
				self._uid.pop(0)
			if (len(self._uid) == 12):
				self._uid.pop(0)
				# at index 4 but now at 3 after 1 removal
				self._uid.pop(3)
			# shallow copy!
			self._uidFinal = self._uid[:]
			
		if (self._uidFinal != []):
			log.append("Full UID is: %s" % str(" ".join(["{0:02x}".format(x) for x in self._uidFinal])))
		return log

	def setIso4(self, data, offset):
		self._isIso4 = True

	def saveATSLen(self, data, offset):
		self._atsLen = data[offset]
		
	def saveFSDI(self, data, offset):
		log = []
		fsdL = [16,24,32,40,48,64,96,128,256]
		self._fsdi = data[offset] & (BitMask.B7|BitMask.B6|BitMask.B5|BitMask.B4)
		self._fsdi = self._fsdi >> 4
		if (self._fsdi > 8):
			log.append("FSDI value %s invalid (RFU)" % str(hex(self._fsdi)))
			self._fsdi = 8
			
		self._fsd = fsdL[self._fsdi]
		log.append("FSD value to be used: %s" % str(hex(self._fsd)))
		return log

	def saveFSCI(self, data, offset):
		log = []
		fscL = [16,24,32,40,48,64,96,128,256]
		self._fsci = data[offset] & (BitMask.B3|BitMask.B2|BitMask.B1|BitMask.B0)
		if (self._fsci > 8):
			log.append("FSCI value %s invalid (RFU)" % str(hex(self._fsci)))
			self._fsci = 8
			
		self._fsc = fscL[self._fsci]
		log.append("FSC value to be used: %s" % str(hex(self._fsc)))
		return log

	def saveCID(self, data, offset):
		log = []
		self._cid = data[offset] & (BitMask.B3|BitMask.B2|BitMask.B1|BitMask.B0)
		if (self._cid == 15):
			log.append("CID value %s invalid" % str(hex(self._cid)))
			
		log.append("CID value to be used: %s" % str(hex(self._cid)))
		if (self._cid != 0):
			log.append("Warning: non-Zero value for CID is not EMV compliant!")
		return log
		
	def includeATS_TA1(self, data, offset):
		self._isTA1 = True

	def includeATS_TB1(self, data, offset):
		self._isTB1 = True
		
	def includeATS_TC1(self, data, offset):
		self._isTC1 = True
		
	def parseATS(self, data, offset):
		# self._atsLen is total ATS len including itself minus CRC
		# offset is set past T0
		log = []
		if (self._isTA1):
			self._TA1 = data[offset]
			log.extend(self.parseTA1(self._TA1))
			log.append('Value 0x%02x at offset %d' % (data[offset], offset))			
			offset += 1
		if (self._isTB1):
			self._TB1 = data[offset]
			log.extend(self.parseTB1(self._TB1))
			log.append('Value 0x%02x at offset %d' % (data[offset], offset))			
			offset += 1
		if (self._isTC1):
			self._TC1 = data[offset]
			log.extend(self.parseTC1(self._TC1))
			log.append('Value 0x%02x at offset %d' % (data[offset], offset))			
			offset += 1
			
		if (self._atsLen > offset):
			self._atsHistBytes = data[offset:self._atsLen]
			log.append("ATS Historical bytes: %s" %  str(" ".join([hex(x) for x in self._atsHistBytes])))
		else:
			log.append("No ATS Historical bytes transmitted")
		return log
			

	def parseTA1(self, value):
		log = []
		if (value & BitMask.B7):
			log.append("TA(1) Bit7: Only the same bit rate divisor for both directions is supported")
		else:
			log.append("TA(1) Bit7: Different bit rate divisor for each direction is supported")
			
		if (value & BitMask.B6):
			log.append("TA(1) Bit6: D PICC->PCD = 8 supported")
		if (value & BitMask.B5):
			log.append("TA(1) Bit5: D PICC->PCD = 4 supported")
		if (value & BitMask.B4):
			log.append("TA(1) Bit4: D PICC->PCD = 2 supported")
			
		if (value & BitMask.B3):
			log.append("TA(1) Bit3: RFU is set; TA1 forced to 0x00")
			self._TA1 = 0x00 #ugly hack
			
		if (value & BitMask.B2):
			log.append("TA(1) Bit2: D PCD->PICC = 8 supported")
		if (value & BitMask.B1):
			log.append("TA(1) Bit1: D PCD->PICC = 4 supported")
		if (value & BitMask.B0):
			log.append("TA(1) Bit0: D PCD->PICC = 2 supported")
		return log
			
	def parseTB1(self, value):
		log = []
		self._fwi =  value & (BitMask.B7|BitMask.B6|BitMask.B5|BitMask.B4)
		self._fwi = self._fwi >> 4
		log.append("TB(1) Bit7..4: FWI %s" % str(hex(self._fwi)))
		self._sfgi = value & (BitMask.B3|BitMask.B2|BitMask.B1|BitMask.B0)
		log.append("TB(1) Bit3..0: SFGI %s" % str(hex(self._sfgi)))
			
		return log

	def parseTC1(self, value):
		log = []
		if (value & BitMask.B1):
			log.append("TC(1) Bit1: CID supported")
		if (value & BitMask.B0):
			log.append("TC(1) Bit0: NAD supported")
			
		return log
	
	def savePCBI_PCD(self, data, offset):
		log = []
		# make it a separate column
		log.append(",%s" %  str(" ".join(["{0:02x}".format(x) for x in data[offset+1:-2]])))
		self._apdu.append(data[offset+1:-2])
		self._isNewApdu = True
		return log

	def savePCBI_PICC(self, data, offset):
		log = []
		# make it a separate column
		log.append(",%s" %  str(" ".join(["{0:02x}".format(x) for x in data[offset+1:-2]])))
		self._apdu.append(data[offset+1:-2])
		self._isNewApdu = True
		return log

	def readULData(self, data, offset):
		log = []
		log.append("DATA: %s" %  str(" ".join(["{0:02x}".format(x) for x in data[:-2]])))
		return log
	
	def getApduAsStr(self):
		for ApduEntry in self._apdu:
			yield str(("%s\n" %  str(" ".join(["{0:02x}".format(x) for x in ApduEntry]))))

	def getNewApdu(self):
		self._isNewApdu = False
		return [str("{0:02x}".format(x)) for x in self._apdu[-1]]
			
	@property
	def isNewApdu(self):
		return self._isNewApdu
			
			
			
			
		
