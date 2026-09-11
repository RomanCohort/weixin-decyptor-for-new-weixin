"""反汇编 Weixin.dll 中指定 RVA 的函数，并注解 call 目标与 RIP-relative 字符串引用。

用法: python tools/disasm_func.py <起始RVA> [长度] [dll路径]
RVA 支持 0x 前缀，例如 0x1018FF0。

未指定 dll 路径时，自动在常见安装目录下按版本号找最新的 Weixin.dll。
依赖: pip install capstone
"""
import glob
import os
import re
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

IB = 0x180000000

DLL_ROOTS = [
    r"C:\Program Files\Tencent\Weixin",
    r"C:\Program Files (x86)\Tencent\Weixin",
    r"D:\Program Files\Tencent\Weixin",
    r"D:\Tencent\Weixin",
    r"D:\weixin",
    r"E:\weixin",
]


def find_weixin_dll():
    """按版本号找最新的 Weixin.dll。"""
    cands = []
    for root in DLL_ROOTS:
        if not os.path.isdir(root):
            continue
        for d in glob.glob(os.path.join(root, "*")):
            dll = os.path.join(d, "Weixin.dll")
            if os.path.isfile(dll):
                cands.append(dll)
        direct = os.path.join(root, "Weixin.dll")
        if os.path.isfile(direct):
            cands.append(direct)
    if not cands:
        return None

    def ver_key(p):
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", p)
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)

    cands.sort(key=ver_key)
    return cands[-1]


def load(dll):
    raw = open(dll, "rb").read()
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    nsec = struct.unpack_from("<H", raw, pe + 6)[0]
    optsz = struct.unpack_from("<H", raw, pe + 20)[0]
    secs = []
    so = pe + 24 + optsz
    for _ in range(nsec):
        name = raw[so:so + 8].rstrip(b"\x00").decode("latin1")
        vsz, va, rsz, ptr = struct.unpack_from("<IIII", raw, so + 8)
        secs.append((name, va, vsz, ptr, rsz))
        so += 40
    return raw, secs


def rva_to_off(secs, rva):
    for _n, va, vsz, ptr, rsz in secs:
        if va <= rva < va + vsz:
            return ptr + (rva - va)
    return None


def off_to_rva(secs, off):
    for _n, va, vsz, ptr, rsz in secs:
        if ptr <= off < ptr + rsz:
            return va + (off - ptr)
    return None


def sec_of(secs, rva):
    for n, va, vsz, ptr, rsz in secs:
        if va <= rva < va + vsz:
            return n
    return None


def load_pdata(raw, secs):
    for n, va, vsz, ptr, rsz in secs:
        if n == ".pdata":
            funcs = []
            for i in range(rsz // 12):
                b, e, _u = struct.unpack_from("<III", raw, ptr + i * 12)
                if b:
                    funcs.append((b, e))
            funcs.sort()
            return funcs
    return []


def owner(funcs, rva):
    lo, hi = 0, len(funcs) - 1
    while lo <= hi:
        m = (lo + hi) // 2
        b, e = funcs[m]
        if rva < b:
            hi = m - 1
        elif rva >= e:
            lo = m + 1
        else:
            return b, e
    return None


def read_cstr(raw, secs, va):
    rva = va - IB
    off = rva_to_off(secs, rva)
    if off is None:
        return None
    end = raw.find(b"\x00", off)
    if end < 0 or end - off > 200:
        return None
    b = raw[off:end]
    if len(b) < 3 or not all(32 <= x < 127 for x in b):
        return None
    return b.decode("latin1")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    start = int(sys.argv[1], 0)
    length = int(sys.argv[2], 0) if len(sys.argv) > 2 else 912
    dll = sys.argv[3] if len(sys.argv) > 3 else find_weixin_dll()
    if not dll or not os.path.isfile(dll):
        print("[!] 找不到 Weixin.dll，请显式传入路径", file=sys.stderr)
        sys.exit(1)
    print(f"[*] 目标: {dll}")

    raw, secs = load(dll)
    funcs = load_pdata(raw, secs)
    off = rva_to_off(secs, start)
    if off is None:
        print(f"[!] RVA 0x{start:X} 不在任何节中")
        sys.exit(1)

    o = owner(funcs, start)
    print(f"[*] 函数 RVA 0x{start:X}  节={sec_of(secs, start)}  大小={length}")
    if o:
        print(f"[*] .pdata 范围 0x{o[0]:X}..0x{o[1]:X} ({o[1]-o[0]} 字节)")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    code = raw[off:off + length]
    for ins in md.disasm(code, IB + start):
        ann = ""
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                tgt = ins.address + ins.size + op.mem.disp
                s = read_cstr(raw, secs, tgt)
                if s:
                    ann = f'   ; "{s}"'
                else:
                    trva = tgt - IB
                    fs = owner(funcs, trva) if trva > 0 else None
                    ann = f"   ; ->0x{trva:X}"
                    if fs and fs[0] == trva:
                        ann += " (函数入口)"
        if ins.mnemonic == "call" and ins.operands and ins.operands[0].type == 2:  # IMM
            tgt = ins.operands[0].imm
            trva = tgt - IB
            if 0 < trva < 0x8000000:
                fs = owner(funcs, trva)
                ann = f"   ; sub_{trva:X}"
                if fs and fs[0] == trva:
                    ann += "  <-- 函数入口"
        print(f"  0x{ins.address - IB:07X}  {ins.mnemonic:<8} {ins.op_str}{ann}")


if __name__ == "__main__":
    main()
