from elftools.elf.elffile import ELFFile
import glob
from enum import IntEnum
from dataclasses import dataclass
from typing import Optional, Callable

class InstFmt(IntEnum):
  R = 1  # register-register operations
  I = 2  # immediate ops and loads
  S = 3  # stores
  SB = 4 # conditional branches
  U = 5  # upper immediate
  UJ = 6 # jumps

class Opcode(IntEnum):
  LUI      = 0b0110111
  AUIPC    = 0b0010111
  JAL      = 0b1101111
  JALR     = 0b1100111
  BRANCH   = 0b1100011  # BEQ/BNE/BLT/BGE/BLTU/BGEU (funct3 selects)
  LOAD     = 0b0000011  # LB/LH/LW/LBU/LHU (funct3 selects)
  STORE    = 0b0100011  # SB/SH/SW (funct3 selects)
  OP_IMM   = 0b0010011  # ADDI/SLTI/…/SLLI/SRLI/SRAI (funct3/funct7)
  OP       = 0b0110011  # ADD/SUB/… (funct3/funct7)
  MISC_MEM = 0b0001111  # FENCE/FENCE.I
  SYSTEM   = 0b1110011  # ECALL/EBREAK/CSR*

FMT_BY_OPCODE = {
  Opcode.LUI:      InstFmt.U,
  Opcode.AUIPC:    InstFmt.U,
  Opcode.JAL:      InstFmt.UJ,
  Opcode.JALR:     InstFmt.I,
  Opcode.BRANCH:   InstFmt.SB,
  Opcode.LOAD:     InstFmt.I,
  Opcode.STORE:    InstFmt.S,
  Opcode.OP_IMM:   InstFmt.I,
  Opcode.OP:       InstFmt.R,
  Opcode.MISC_MEM: InstFmt.I,
  Opcode.SYSTEM:   InstFmt.I,
}

SYSCALL_EXIT = 93  # a7==93, a0==0 -> pass; a0!=0 -> fail

class TestDone(Exception):
  def __init__(self, passed: bool, code: int):
    super().__init__()
    self.passed = passed
    self.code = code

# x0..x31
regfile = [0] * 32
PC = 0
mem = bytearray(64 * 1024)  # small RAM window
mem_base = 0
code_end = 0

def read32(pc: int) -> Optional[int]:
  if pc < mem_base or pc + 4 > code_end:
    return None
  off = pc - mem_base
  return int.from_bytes(mem[off:off+4], 'little')

# sign/zero helpers
def sext(val, bits):
  sign = 1 << (bits - 1)
  return (val ^ sign) - sign

def zext(val, bits=None):
  return val if bits is None else (val & ((1 << bits) - 1))

def bits(val, hi, low):
  return (val >> low) & ((1 << (hi - low + 1)) - 1)

def build_imm(ins, spec, width):
  imm = 0
  for (hi, low, pos) in spec:
    imm |= (bits(ins, hi, low) << pos)
  return sext(imm, width)

def u32(x: int) -> int:
  return x & 0xFFFFFFFF

def s32(x: int) -> int:
  x &= 0xFFFFFFFF
  return x if x < 0x80000000 else x - 0x100000000

def dump():
  lines = []
  for i, r in enumerate(regfile):
    label = f"{f'x{i}':>3}"
    val = f"{r:#010x}"
    lines.append(f"{label}: {val}\t")
    if i % 4 == 3:
      lines.append("\n")
  print(''.join(lines))
  print(f"PC: {hex(PC)}")

def wb(rd, val):
  if rd == 0:
    return
  regfile[rd] = val & 0xFFFFFFFF

def mem_read8(addr: int) -> int:
  off = addr - mem_base
  if 0 <= off < len(mem):
    return mem[off]
  return 0

def mem_read16(addr: int) -> int:
  off = addr - mem_base
  if 0 <= off + 1 < len(mem):
    return int.from_bytes(mem[off:off+2], 'little', signed=False)
  return 0

def mem_read32(addr: int) -> int:
  off = addr - mem_base
  if 0 <= off + 3 < len(mem):
    return int.from_bytes(mem[off:off+4], 'little', signed=False)
  return 0

def mem_write8(addr: int, val: int) -> None:
  off = addr - mem_base
  if 0 <= off < len(mem):
    mem[off] = val & 0xFF

def mem_write16(addr: int, val: int) -> None:
  off = addr - mem_base
  if 0 <= off + 1 < len(mem):
    mem[off:off+2] = (val & 0xFFFF).to_bytes(2, 'little')

def mem_write32(addr: int, val: int) -> None:
  off = addr - mem_base
  if 0 <= off + 3 < len(mem):
    mem[off:off+4] = (val & 0xFFFFFFFF).to_bytes(4, 'little')

@dataclass
class Decoded:
  raw: int
  opcode: Opcode
  fmt: InstFmt
  rd: Optional[int] = None
  rs1: Optional[int] = None
  rs2: Optional[int] = None
  funct3: Optional[int] = None
  funct7: Optional[int] = None
  shamt: Optional[int] = None
  imm: Optional[int] = None
  length: int = 4

def decode(ins: int) -> Decoded:
  opc_val = ins & 0x7F
  opcode = Opcode(opc_val)
  fmt = FMT_BY_OPCODE[opcode]
  d = Decoded(raw=ins, opcode=opcode, fmt=fmt)

  SB_SPEC = ((31,31,12), (30,25,5), (7,7,11), (11,8,1))
  UJ_SPEC = ((31,31,20), (19,12,12), (20,20,11), (30,21,1))
  S_SPEC  = ((31,25,5), (11,7,0))

  if fmt is InstFmt.R:
    d.rd     = bits(ins, 11, 7)
    d.funct3 = bits(ins, 14, 12)
    d.rs1    = bits(ins, 19, 15)
    d.rs2    = bits(ins, 24, 20)
    d.funct7 = bits(ins, 31, 25)

  elif fmt is InstFmt.I:
    d.rd     = bits(ins, 11, 7)
    d.funct3 = bits(ins, 14, 12)
    d.rs1    = bits(ins, 19, 15)
    d.imm    = sext(bits(ins, 31, 20), 12)
    d.funct7 = bits(ins, 31, 25)
    d.shamt  = bits(ins, 24, 20) & 0x1F

  elif fmt is InstFmt.S:
    d.funct3 = bits(ins, 14, 12)
    d.rs1    = bits(ins, 19, 15)
    d.rs2    = bits(ins, 24, 20)
    d.imm    = build_imm(ins, S_SPEC, width=12)

  elif fmt is InstFmt.SB:
    d.funct3 = bits(ins, 14, 12)
    d.rs1    = bits(ins, 19, 15)
    d.rs2    = bits(ins, 24, 20)
    d.imm    = build_imm(ins, SB_SPEC, width=13)

  elif fmt is InstFmt.U:
    d.rd  = bits(ins, 11, 7)
    d.imm = bits(ins, 31, 12) << 12

  elif fmt is InstFmt.UJ:
    d.rd  = bits(ins, 11, 7)
    d.imm = build_imm(ins, UJ_SPEC, width=21)

  return d

def exec_LUI(d: Decoded, pc0: int) -> int:
  wb(d.rd, d.imm)
  return pc0 + d.length

def exec_AUIPC(d: Decoded, pc0: int) -> int:
  wb(d.rd, u32(pc0 + d.imm))
  return pc0 + d.length

def exec_JAL(d: Decoded, pc0: int) -> int:
  if d.rd is not None:
    wb(d.rd, pc0 + d.length)
  return pc0 + d.imm

def exec_JALR(d: Decoded, pc0: int) -> int:
  target = (regfile[d.rs1] + d.imm) & ~1
  if d.rd is not None:
    wb(d.rd, pc0 + d.length)
  return u32(target)

def exec_OP_IMM(d: Decoded, pc0: int) -> int:
  a = regfile[d.rs1]
  imm = u32(d.imm)
  f3 = d.funct3
  if f3 == 0b000:       # ADDI
    wb(d.rd, a + imm)
  elif f3 == 0b010:     # SLTI
    wb(d.rd, 1 if s32(a) < s32(imm) else 0)
  elif f3 == 0b011:     # SLTIU
    wb(d.rd, 1 if u32(a) < u32(imm) else 0)
  elif f3 == 0b100:     # XORI
    wb(d.rd, a ^ imm)
  elif f3 == 0b110:     # ORI
    wb(d.rd, a | imm)
  elif f3 == 0b111:     # ANDI
    wb(d.rd, a & imm)
  elif f3 == 0b001:     # SLLI
    sh = d.shamt & 0x1F
    wb(d.rd, u32(a << sh))
  elif f3 == 0b101:     # SRLI / SRAI
    sh = d.shamt & 0x1F
    if d.funct7 == 0b0000000:
      wb(d.rd, u32(a) >> sh)
    elif d.funct7 == 0b0100000:
      wb(d.rd, u32(s32(a) >> sh))
    else:
      raise NotImplementedError("OP-IMM shift funct7")
  else:
    raise NotImplementedError("OP-IMM funct3")
  return pc0 + d.length

def exec_OP(d: Decoded, pc0: int) -> int:
  a = regfile[d.rs1]
  b = regfile[d.rs2]
  f3 = d.funct3
  f7 = d.funct7
  if f3 == 0b000 and f7 == 0b0000000:   # ADD
    wb(d.rd, a + b)
  elif f3 == 0b000 and f7 == 0b0100000: # SUB
    wb(d.rd, a - b)
  elif f3 == 0b001 and f7 == 0b0000000: # SLL
    wb(d.rd, u32(a << (b & 0x1F)))
  elif f3 == 0b010 and f7 == 0b0000000: # SLT
    wb(d.rd, 1 if s32(a) < s32(b) else 0)
  elif f3 == 0b011 and f7 == 0b0000000: # SLTU
    wb(d.rd, 1 if u32(a) < u32(b) else 0)
  elif f3 == 0b100 and f7 == 0b0000000: # XOR
    wb(d.rd, a ^ b)
  elif f3 == 0b101 and f7 == 0b0000000: # SRL
    wb(d.rd, u32(a) >> (b & 0x1F))
  elif f3 == 0b101 and f7 == 0b0100000: # SRA
    wb(d.rd, u32(s32(a) >> (b & 0x1F)))
  elif f3 == 0b110 and f7 == 0b0000000: # OR
    wb(d.rd, a | b)
  elif f3 == 0b111 and f7 == 0b0000000: # AND
    wb(d.rd, a & b)
  else:
    raise NotImplementedError("OP variant")
  return pc0 + d.length

def exec_BRANCH(d: Decoded, pc0: int) -> int:
  a = regfile[d.rs1]
  b = regfile[d.rs2]
  f3 = d.funct3
  take = False
  if f3 == 0b000: take = (a == b)                     # BEQ
  elif f3 == 0b001: take = (a != b)                   # BNE
  elif f3 == 0b100: take = (s32(a) < s32(b))          # BLT
  elif f3 == 0b101: take = (s32(a) >= s32(b))         # BGE
  elif f3 == 0b110: take = (u32(a) < u32(b))          # BLTU
  elif f3 == 0b111: take = (u32(a) >= u32(b))         # BGEU
  else:
    raise NotImplementedError("BRANCH funct3")
  return (pc0 + d.imm) if take else (pc0 + d.length)

def exec_LOAD(d: Decoded, pc0: int) -> int:
  EA = u32(regfile[d.rs1] + d.imm)
  f3 = d.funct3
  if f3 == 0b000:   # LB
    wb(d.rd, sext(mem_read8(EA), 8))
  elif f3 == 0b001: # LH
    wb(d.rd, sext(mem_read16(EA), 16))
  elif f3 == 0b010: # LW
    wb(d.rd, mem_read32(EA))
  elif f3 == 0b100: # LBU
    wb(d.rd, mem_read8(EA))
  elif f3 == 0b101: # LHU
    wb(d.rd, mem_read16(EA))
  else:
    raise NotImplementedError("LOAD funct3")
  return pc0 + d.length

def exec_STORE(d: Decoded, pc0: int) -> int:
  EA = u32(regfile[d.rs1] + d.imm)
  val = u32(regfile[d.rs2])
  f3 = d.funct3
  if f3 == 0b000:   # SB
    mem_write8(EA, val)
  elif f3 == 0b001: # SH
    mem_write16(EA, val)
  elif f3 == 0b010: # SW
    mem_write32(EA, val)
  else:
    raise NotImplementedError("STORE funct3")
  return pc0 + d.length

def exec_MISC_MEM(d: Decoded, pc0: int) -> int:
  return pc0 + d.length

def exec_SYSTEM(d: Decoded, pc0: int) -> int:
  # Minimal: detect ECALL exit convention used by rv32ui-p
  if d.funct3 == 0 and d.imm == 0:
    a7 = u32(regfile[17])  # x17
    a0 = u32(regfile[10])  # x10
    if a7 == SYSCALL_EXIT:
      raise TestDone(a0 == 0, int(a0))
  # CSR ops and others: no-op for these tests
  return pc0 + d.length

Handler = Callable[[Decoded, int], int]
DISPATCH: dict[Opcode, Handler] = {
  Opcode.LUI:      exec_LUI,
  Opcode.AUIPC:    exec_AUIPC,
  Opcode.JAL:      exec_JAL,
  Opcode.JALR:     exec_JALR,
  Opcode.OP_IMM:   exec_OP_IMM,
  Opcode.OP:       exec_OP,
  Opcode.BRANCH:   exec_BRANCH,
  Opcode.LOAD:     exec_LOAD,
  Opcode.STORE:    exec_STORE,
  Opcode.MISC_MEM: exec_MISC_MEM,
  Opcode.SYSTEM:   exec_SYSTEM,
}

def step():
  global PC
  pc0 = PC
  raw = read32(pc0)
  if raw is None:
    return False
  d = decode(raw)
  handler = DISPATCH[d.opcode]
  if not handler:
    raise NotImplementedError(f"opcode {d.opcode} not implemented")
  PC = u32(handler(d, pc0))
  return True

if __name__ == "__main__":
  tests = glob.glob("/Users/boop/code/python/riscv-em/riscv-tests/isa/rv32ui-p-*")
  n = len([t for t in tests if not t.endswith(".dump")])
  passed = 0

  for t in sorted(tests):
    if t.endswith(".dump"):
      continue

    # fresh state per test
    regfile[:] = [0] * 32
    mem[:] = b"\x00" * len(mem)

    with open(t, 'rb') as f:
      elf = ELFFile(f)
      phdrs = [ph for ph in elf.iter_segments() if ph.header.p_type == "PT_LOAD"]
      assert phdrs, "no PT_LOAD segments?"
      mem_base = min(ph.header.p_vaddr for ph in phdrs)
      mem_limit = max(ph.header.p_vaddr + ph.header.p_memsz for ph in phdrs)
      need = mem_limit - mem_base
      assert len(mem) >= need, f"not enough memory, need {need} bytes"
      mem[:need] = b"\x00" * need
      for ph in phdrs:
        off = ph.header.p_vaddr - mem_base 
        data = ph.data()
        mem[off:off+len(data)] = data
        bss = ph.header.p_memsz - ph.header.p_filesz
      code_end = mem_base + need
      PC = int(elf.header['e_entry'])

      try:
        while step(): pass
        # fell off without ECALL exit
        print(f"{t.split('/')[-1]}: fail (no exit)")
      except TestDone as td:
        if td.passed:
          passed += 1
          print(f"{t.split('/')[-1]}: pass")
        else:
          print(f"{t.split('/')[-1]}: fail (code {td.code})")
  print(f"passed {passed}/{n} | {passed/n:.00%}")
