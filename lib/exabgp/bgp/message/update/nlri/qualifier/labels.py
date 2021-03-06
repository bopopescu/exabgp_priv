# encoding: utf-8
"""
labels.py

Created by Thomas Mangin on 2012-07-08.
Copyright (c) 2009-2015 Exa Networks. All rights reserved.
"""

from struct import pack
from struct import unpack


# ======================================================================= Labels
# RFC 3107

class Labels (object):
	MAX = pow(2,20)-1

	__slots__ = ['labels','packed','_len']

	def __init__ (self, labels, bos=True):
		self.labels = labels
		packed = []
		for label in labels:
			# shift to 20 bits of the label to be at the top of three bytes and then truncate.
			packed.append(pack('!L',label << 4)[1:])
		# Mark the bottom of stack with the bit
		if packed and bos:
			packed.pop()
			packed.append(pack('!L',(label << 4) | 1)[1:])
		self.packed = ''.join(packed)
		self._len = len(self.packed)

	def pack (self):
		return self.packed

	def __len__ (self):
		return self._len

	def json (self):
		if self._len > 1:
			return '"label": [ %s ]' % ', '.join([str(_) for _ in self.labels])
		else:
			return ''

	def __str__ (self):
		if self._len > 1:
			return ' label [ %s ]' % ' '.join([str(_) for _ in self.labels])
		elif self._len == 1:
			return ' label %s' % self.labels[0]
		else:
			return ''

	@classmethod
	def unpack (cls, data):
		labels = []
		while True:
			label = unpack('!L',data[4:])
			labels.append(label >> 4)
			if label & 0x001:
				break
		return cls(labels,True)

Labels.NOLABEL = Labels([])
