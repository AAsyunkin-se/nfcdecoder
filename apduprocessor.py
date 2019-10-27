from bitmask import BitMask

class ProcessorApdu:
		
	def parseCLA3210(self, data, offset):
		log = []
		if ((data[offset] & (BitMask.B3|BitMask.B2)) == (BitMask.B3|BitMask.B2)):
			log.append('Bits 3..2 ISO secure messaging; header authentic')			
		elif ((data[offset] & (BitMask.B3|BitMask.B2)) == BitMask.B3):
			log.append('Bits 3..2 ISO secure messaging; header not authentic')			
		elif ((data[offset] & (BitMask.B3|BitMask.B2)) == BitMask.B2):
			log.append('Bits 3..2 Non-ISO secure messaging using a private method')			
		else:
			log.append('Bits 3..2 Secure messaging not used')
						
		log.append('Bits 1..0 Logical Channel %d' % (data[offset] & (BitMask.B1|BitMask.B0)))			
		return log

	def parseApduDataPCD(self, data, offset):
		log = []
		#log.append("APDU DATA: %s" %  str(" ".join(["{0:02x}".format(x) for x in data[offset:]])))

		try:
			# case where neither Lc nor Data not Le given - don't bother
			# TODO Lc and Le extensions (3 bytes 00 xx xx)
			data[offset]
			if (len(data)-offset == 1):
				# we have offset set to the last byte - this is Le
				log.append('Byte %d length of response data Le (0=Maximum) %d' % (offset, data[offset]))
			else:
				Lc = data[offset]
				log.append('Byte %d length of command data Lc %d' % (offset, data[offset]))
				log.append("Command Data: %s" %  str(" ".join(["{0:02x}".format(x) for x in data[offset+1:Lc+offset+1]])))
				if (len(data)-(Lc+offset+1) == 1):
					log.append('Byte %d length of response data Le (0=Maximum) %d' % (Lc+offset+1, data[Lc+offset+1]))
			
		except IndexError:
			# case where neither Lc nor Data not Le given - don't bother
			pass
			
		return log
		
	def parseApduDataPICC(self, data, offset):
		log = []
		if (data[offset:-2] != []):
			log.append("TLV content: %s" %  str(" ".join(["{0:02x}".format(x) for x in data[offset:-2]])))
		return log
		
