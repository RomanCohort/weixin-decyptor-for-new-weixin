"""静态推导微信 4.1.11+ codec 配置函数的 RVA —— 无需运行 Frida / 无需启动微信。

背景
----
微信 4.1.11+ 不再在内存中缓存 `x'<64hex_enc_key><32hex_salt>'` 字符串，
原有内存扫描方案失效。新方案需要 hook codec 配置函数入口，该函数
参数结构的前 32 字节即为 KDF 用的 password：

    enc_key = PBKDF2-HMAC-SHA512(password, salt, 256000, 32)
    salt    = 数据库文件头前 16 字节

社区方案把目标函数偏移硬编码（如 4.1.12.26 的 0x3486140），
微信每次更新都会失效。本脚本改为静态推导：

    1. 在 Weixin.dll 里定位 "MMV1" 魔数字符串，算出它的 VA
    2. 全 .text 扫描 RIP-relative 引用，找到引用该字符串的指令
    3. 用 .pdata（x64 异常表）反查该指令所属函数的起始 RVA

输出即为可用的 hook 偏移，且换版本后重新运行即可，无需人工逆向。

用法
----
    python scripts/find_wechat_codec_offset.py [Weixin.dll 路径]

未指定路径时，自动在常见安装目录下按版本号找最新的 Weixin.dll。
"""
import argparse
import binascii
import glob
import os
import re
import struct
import sys

SECTION_HDR_SZ = 40
RIP_REL_LEN = 4          # disp32 长度
MAGIC = b"MMV1"


def find_weixin_dll():
    """在常见安装目录下按版本号排序，返回最新的 Weixin.dll。"""
    roots = [
        r"D:\weixin",
        r"C:\Program Files\Tencent\Weixin",
        r"C:\Program Files (x86)\Tencent\Weixin",
    ]
    candidates = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        # 版本目录形式：<root>/4.1.13.65/Weixin.dll
        for d in glob.glob(os.path.join(root, "*")):
            dll = os.path.join(d, "Weixin.dll")
            if os.path.isfile(dll):
                candidates.append(dll)
        direct = os.path.join(root, "Weixin.dll")
        if os.path.isfile(direct):
            candidates.append(direct)
    if not candidates:
        return None

    def ver_key(path):
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", path)
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)

    candidates.sort(key=ver_key)
    return candidates[-1]


def parse_pe(raw):
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("不是有效的 PE 文件")
    nsec = struct.unpack_from("<H", raw, pe + 6)[0]
    optsz = struct.unpack_from("<H", raw, pe + 20)[0]
    magic = struct.unpack_from("<H", raw, pe + 24)[0]
    if magic != 0x20B:
        raise ValueError(f"只支持 PE32+ (x64)，当前 magic=0x{magic:X}")
    image_base = struct.unpack_from("<Q", raw, pe + 24 + 24)[0]

    sections = {}
    so = pe + 24 + optsz
    for _ in range(nsec):
        name = raw[so:so + 8].rstrip(b"\x00").decode("latin1")
        vsz, va, rsz, ptr = struct.unpack_from("<IIII", raw, so + 8)
        sections[name] = {"va": va, "vsz": vsz, "ptr": ptr, "rsz": rsz}
        so += SECTION_HDR_SZ
    return image_base, sections


def file_off_to_va(sections, image_base, off):
    for name, s in sections.items():
        if s["ptr"] <= off < s["ptr"] + s["rsz"]:
            return name, image_base + s["va"] + (off - s["ptr"])
    return None, None


def va_to_file_off(sections, image_base, va):
    for name, s in sections.items():
        sec_va = image_base + s["va"]
        if sec_va <= va < sec_va + s["vsz"]:
            return s["ptr"] + (va - sec_va)
    return None


def find_magic_vas(raw, sections, image_base):
    """返回 .rdata 中 MMV1 字符串的 VA 列表（代码段内的内联常量不算）。"""
    vas = []
    start = 0
    while True:
        i = raw.find(MAGIC, start)
        if i < 0:
            break
        sec, va = file_off_to_va(sections, image_base, i)
        if sec and not sec.startswith(".text"):
            vas.append(va)
        start = i + 1
    return vas


def find_rip_rel_refs(raw, sections, image_base, target_va):
    """在 .text 内查找所有 RIP-relative 引用 target_va 的指令位置。"""
    t = sections[".text"]
    text = raw[t["ptr"]:t["ptr"] + t["rsz"]]
    hits = []
    try:
        import numpy as np
        arr = np.frombuffer(text, dtype=np.uint8)
        if len(arr) < RIP_REL_LEN:
            return hits
        disp = (arr[:-3].astype(np.int64)
                | (arr[1:-2].astype(np.int64) << 8)
                | (arr[2:-1].astype(np.int64) << 16)
                | (arr[3:].astype(np.int64) << 24))
        disp = np.where(disp >= 0x80000000, disp - 0x100000000, disp)
        idx = np.arange(len(disp), dtype=np.int64)
        targets = image_base + t["va"] + idx + RIP_REL_LEN + disp
        for i in np.nonzero(targets == target_va)[0]:
            hits.append(int(t["ptr"] + i))
    except ImportError:
        for i in range(len(text) - RIP_REL_LEN):
            d = struct.unpack_from("<i", text, i)[0]
            if image_base + t["va"] + i + RIP_REL_LEN + d == target_va:
                hits.append(t["ptr"] + i)
    return hits


def load_pdata(raw, sections):
    """读取 .pdata 的 RUNTIME_FUNCTION 表，返回 (begin_rva, end_rva) 有序列表。"""
    if ".pdata" not in sections:
        return []
    p = sections[".pdata"]
    n = p["rsz"] // 12
    funcs = []
    for i in range(n):
        b, e, _u = struct.unpack_from("<III", raw, p["ptr"] + i * 12)
        if b:
            funcs.append((b, e))
    funcs.sort()
    return funcs


def owner_function(funcs, rva):
    lo, hi = 0, len(funcs) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        b, e = funcs[mid]
        if rva < b:
            hi = mid - 1
        elif rva >= e:
            lo = mid + 1
        else:
            return b, e
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dll", nargs="?", help="Weixin.dll 路径（省略则自动查找）")
    args = ap.parse_args()

    dll = args.dll or find_weixin_dll()
    if not dll or not os.path.isfile(dll):
        print("[!] 找不到 Weixin.dll，请显式传入路径", file=sys.stderr)
        sys.exit(1)

    ver = re.search(r"[\\/](\d+\.\d+\.\d+(?:\.\d+)?)[\\/]", dll)
    print(f"[*] 目标: {dll}")
    if ver:
        print(f"[*] 微信版本: {ver.group(1)}")
    raw = open(dll, "rb").read()
    print(f"[*] 大小: {len(raw)/1024/1024:.1f} MB")

    image_base, sections = parse_pe(raw)
    print(f"[*] ImageBase: 0x{image_base:X}")
    if ".text" not in sections or ".pdata" not in sections:
        print("[!] 缺少 .text 或 .pdata 节，无法继续", file=sys.stderr)
        sys.exit(1)

    magic_vas = find_magic_vas(raw, sections, image_base)
    if not magic_vas:
        print("[!] 未找到 MMV1 魔数字符串", file=sys.stderr)
        sys.exit(1)
    print(f"[*] MMV1 字符串 VA: {[hex(v) for v in magic_vas]}")

    funcs = load_pdata(raw, sections)
    print(f"[*] .pdata 函数条目: {len(funcs)}")

    found = False
    for va in magic_vas:
        refs = find_rip_rel_refs(raw, sections, image_base, va)
        for off in refs:
            _sec, ref_va = file_off_to_va(sections, image_base, off)
            if ref_va is None:
                continue
            ref_rva = ref_va - image_base
            owner = owner_function(funcs, ref_rva)
            if not owner:
                print(f"[~] 引用点 RVA 0x{ref_rva:X} 不在 .pdata 内，跳过")
                continue
            b, e = owner
            found = True
            print()
            print(f"[+] 引用点(disp32) RVA 0x{ref_rva:X}")
            print(f"[+] 所属函数       RVA 0x{b:X} .. 0x{e:X}  ({e - b} 字节)")
            print(f"[+] hook 偏移      Weixin.dll + 0x{b:X}")
            print(f"    指令附近字节: {binascii.hexlify(raw[off - 4:off + 8]).decode()}")

    if not found:
        print("[!] 未能在 .pdata 中定位到引用 MMV1 的函数", file=sys.stderr)
        sys.exit(1)

    print()
    print("说明: 上述偏移为候选 hook 点。hook 入口时其第一个参数指向的")
    print("      结构前 32 字节即 password，需经 PBKDF2-HMAC-SHA512")
    print("      (password, salt, 256000, 32) 派生才能得到 enc_key。")


if __name__ == "__main__":
    main()
