"""hwbp_debugger.py —— 非注入式密钥捕获：Windows 调试 API + 硬件断点

与 Frida 方案的区别
------------------
  Frida Interceptor.attach  -> 加载 agent DLL 进目标进程 + 给目标代码打补丁
  本脚本                    -> CreateProcess(DEBUG_ONLY_THIS_PROCESS) 启动，
                               断点写在 CPU 的 DR0 寄存器里

【不是注入】不向目标加载任何模块。
【不改代码】硬件断点不修改目标内存一个字节 —— 比 Frida 的 inline hook 更轻。

目标
----
在 Weixin.dll + 0x3634F10（引用 "MMV1" 的高频分发函数，见 docs/03）入口下
硬件执行断点，断下时读 rcx 指向的内存并记录，按 rcx 去重。

用法（管理员终端）
----------------
    python hwbp_debugger.py [--rva 0x3634F10] [--seconds 300] [--out hwbp.jsonl]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import sys
import time
from ctypes import c_uint8, c_uint16, c_uint32, c_uint64, byref, sizeof

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

# 显式声明签名，否则 ctypes 默认按 int 处理、会截断 64 位指针
k32.WaitForDebugEvent.argtypes = [ctypes.c_void_p, wt.DWORD]
k32.WaitForDebugEvent.restype = wt.BOOL
k32.ContinueDebugEvent.argtypes = [wt.DWORD, wt.DWORD, wt.DWORD]
k32.ContinueDebugEvent.restype = wt.BOOL
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenProcess.restype = wt.HANDLE
k32.GetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.GetThreadContext.restype = wt.BOOL
k32.SetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.SetThreadContext.restype = wt.BOOL
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wt.BOOL
k32.DebugActiveProcess.argtypes = [wt.DWORD]
k32.DebugActiveProcess.restype = wt.BOOL
k32.DebugActiveProcessStop.argtypes = [wt.DWORD]
k32.DebugActiveProcessStop.restype = wt.BOOL
k32.DebugSetProcessKillOnExit.argtypes = [wt.BOOL]
k32.DebugSetProcessKillOnExit.restype = wt.BOOL
k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenThread.restype = wt.HANDLE
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.CloseHandle.restype = wt.BOOL


DLL_ROOTS = [
    r"C:\Program Files\Tencent\Weixin",
    r"C:\Program Files (x86)\Tencent\Weixin",
    r"D:\Program Files\Tencent\Weixin",
    r"D:\Tencent\Weixin",
    r"D:\weixin",
    r"E:\weixin",
]


def find_weixin_exe():
    for root in DLL_ROOTS:
        p = os.path.join(root, "Weixin.exe")
        if os.path.isfile(p):
            return p
    return None


def find_weixin_dll():
    """按版本号找最新的 Weixin.dll。"""
    import glob, re as _re
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

    def vk(p):
        m = _re.search(r"(\d+)\.(\d+)\.(\d+)", p)
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)

    cands.sort(key=vk)
    return cands[-1]


# ---------------------------------------------------------------- 常量
DEBUG_PROCESS = 0x00000001              # 调试整个进程树（含子进程）
DEBUG_ONLY_THIS_PROCESS = 0x00000002
CREATE_NEW_CONSOLE = 0x00000010
DBG_CONTINUE = 0x00010002
EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
CONTEXT_ALL = 0x0010001F


# ---------------------------------------------------------------- 结构
class CONTEXT64(ctypes.Structure):
    _fields_ = (
        [("P1Home", c_uint64), ("P2Home", c_uint64), ("P3Home", c_uint64),
         ("P4Home", c_uint64), ("P5Home", c_uint64), ("P6Home", c_uint64),
         ("ContextFlags", c_uint32), ("MxCsr", c_uint32),
         ("SegCs", c_uint16), ("SegDs", c_uint16), ("SegEs", c_uint16),
         ("SegFs", c_uint16), ("SegGs", c_uint16), ("SegSs", c_uint16),
         ("EFlags", c_uint32),
         ("Dr0", c_uint64), ("Dr1", c_uint64), ("Dr2", c_uint64), ("Dr3", c_uint64),
         ("Dr6", c_uint64), ("Dr7", c_uint64),
         ("Rax", c_uint64), ("Rcx", c_uint64), ("Rdx", c_uint64), ("Rbx", c_uint64),
         ("Rsp", c_uint64), ("Rbp", c_uint64), ("Rsi", c_uint64), ("Rdi", c_uint64),
         ("R8", c_uint64), ("R9", c_uint64), ("R10", c_uint64), ("R11", c_uint64),
         ("R12", c_uint64), ("R13", c_uint64), ("R14", c_uint64), ("R15", c_uint64),
         ("Rip", c_uint64),
         ("FltSave", c_uint8 * 512),
         ("VectorRegister", c_uint8 * 416),
         ("VectorControl", c_uint64),
         ("DebugControl", c_uint64), ("LastBranchToRip", c_uint64),
         ("LastBranchFromRip", c_uint64), ("LastExceptionToRip", c_uint64),
         ("LastExceptionFromRip", c_uint64)]
    )


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", c_uint32), ("dwProcessId", c_uint32),
                ("dwThreadId", c_uint32), ("_pad", c_uint32),
                ("u", c_uint8 * 160)]


class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", c_uint32), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR),
                ("lpTitle", wt.LPWSTR), ("dwX", c_uint32), ("dwY", c_uint32),
                ("dwXSize", c_uint32), ("dwYSize", c_uint32),
                ("dwXCountChars", c_uint32), ("dwYCountChars", c_uint32),
                ("dwFillAttribute", c_uint32), ("dwFlags", c_uint32),
                ("wShowWindow", c_uint16), ("cbReserved2", c_uint16),
                ("lpReserved2", ctypes.POINTER(c_uint8)), ("hStdInput", wt.HANDLE),
                ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                ("dwProcessId", c_uint32), ("dwThreadId", c_uint32)]


# ---------------------------------------------------------------- 工具
def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(int(addr)), buf, size, byref(n)):
        return buf.raw[:n.value]
    return None


def pe_sizeof_image(h, base):
    """读目标进程里某个模块的 SizeOfImage（用于识别 Weixin.dll，避开 ASLR）。"""
    hdr = read_mem(h, base, 0x400)
    if not hdr or hdr[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
    if e_lfanew + 0x60 > len(hdr) or hdr[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    optsz = struct.unpack_from("<H", hdr, e_lfanew + 20)[0]
    magic = struct.unpack_from("<H", hdr, e_lfanew + 24)[0]
    if magic != 0x20B:
        return None
    return struct.unpack_from("<I", hdr, e_lfanew + 24 + 56)[0]


def set_hwbp(thread_handle, addr):
    """在指定线程上设置 DR0 = addr，DR7 使能 L0 执行断点。"""
    ctx = CONTEXT64()
    ctx.ContextFlags = CONTEXT_ALL
    if not k32.GetThreadContext(thread_handle, byref(ctx)):
        return False
    ctx.Dr0 = addr
    ctx.Dr7 = (ctx.Dr7 & ~0xF0000) | 0x1     # L0=1, R/W0=00(执行), LEN0=00(1字节)
    ctx.ContextFlags = CONTEXT_ALL
    return bool(k32.SetThreadContext(thread_handle, byref(ctx)))


def clear_hwbp(thread_handle):
    ctx = CONTEXT64()
    ctx.ContextFlags = CONTEXT_ALL
    if not k32.GetThreadContext(thread_handle, byref(ctx)):
        return
    ctx.Dr0 = 0
    ctx.Dr7 &= ~0x1
    ctx.ContextFlags = CONTEXT_ALL
    k32.SetThreadContext(thread_handle, byref(ctx))


# ---------------------------------------------------------------- 附加模式
def find_module_base(hproc, want_size):
    """在目标进程里按 SizeOfImage 找 Weixin.dll 的基址（附加模式下用）。"""
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    arr = (ctypes.c_void_p * 1024)()
    need = ctypes.c_uint32(0)
    if not psapi.EnumProcessModulesEx(hproc, byref(arr), sizeof(arr),
                                      byref(need), 0x03):   # 0x03 = 全部模块
        return None
    n = min(need.value // sizeof(ctypes.c_void_p), 1024)
    for i in range(n):
        b = arr[i]
        if b and pe_sizeof_image(hproc, b) == want_size:
            return b
    return None


def enum_thread_ids(pid):
    """用 Toolhelp 枚举进程内所有线程 ID。"""
    TH32CS_SNAPTHREAD = 0x00000004

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", c_uint32), ("cntUsage", c_uint32),
                    ("th32ThreadID", c_uint32), ("th32OwnerProcessID", c_uint32),
                    ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long),
                    ("dwFlags", c_uint32)]

    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == wt.HANDLE(-1).value or not snap:
        return []
    out = []
    try:
        te = THREADENTRY32()
        te.dwSize = sizeof(te)
        k32.Thread32First.argtypes = [wt.HANDLE, ctypes.c_void_p]
        k32.Thread32Next.argtypes = [wt.HANDLE, ctypes.c_void_p]
        if k32.Thread32First(snap, byref(te)):
            while True:
                if te.th32OwnerProcessID == pid:
                    out.append(te.th32ThreadID)
                if not k32.Thread32Next(snap, byref(te)):
                    break
    finally:
        k32.CloseHandle(snap)
    return out


def mode_attach(pid, rva, seconds, out_path, dump_len, dll_path):
    """附加到【已在运行】的微信进程，设置硬件断点。不注入、不改代码。"""
    want_size = None
    raw_dll = None
    try:
        raw_dll = open(dll_path, "rb").read()
        e = struct.unpack_from("<I", raw_dll, 0x3C)[0]
        want_size = struct.unpack_from("<I", raw_dll, e + 24 + 56)[0]
    except Exception:
        pass

    if not k32.DebugActiveProcess(pid):
        print(f"[!] DebugActiveProcess 失败: {ctypes.get_last_error()}", file=sys.stderr)
        return 1
    # 关键：调试器退出时不要连带杀掉目标（否则会关掉你的微信）
    k32.DebugSetProcessKillOnExit(False)
    print(f"[*] 已附加到 PID={pid}（不注入、不改代码）")

    out = open(out_path, "w", encoding="utf-8")
    hproc = None
    threads = {}
    bp_addr = None
    seen = set()
    hits = 0
    ev = DEBUG_EVENT()
    t0 = time.time()
    steps = 0

    try:
        while time.time() - t0 < seconds:
            if not k32.WaitForDebugEvent(byref(ev), 1000):
                continue
            code = ev.dwDebugEventCode
            u = bytes(ev.u)
            cont = DBG_CONTINUE
            steps += 1

            if code == CREATE_PROCESS_DEBUG_EVENT:
                hproc = ctypes.c_void_p(struct.unpack_from("<Q", u, 8)[0])
                threads[ev.dwThreadId] = ctypes.c_void_p(
                    struct.unpack_from("<Q", u, 16)[0])
                base = find_module_base(hproc, want_size) if want_size else None
                if base:
                    bp_addr = base + rva
                    print(f"    [+] Weixin.dll @ 0x{base:X}")
                    print(f"    [+] 断点地址 = 0x{bp_addr:X}")
                    # 校验：目标内存里的字节应与磁盘上该 RVA 的字节一致
                    live = read_mem(hproc, bp_addr, 8)
                    disk_off = 0x400 + (rva - 0x1000)
                    disk = raw_dll[disk_off:disk_off + 8] if raw_dll else None
                    if live and disk:
                        ok = live == disk
                        print(f"    字节校验: 目标={live.hex()} 磁盘={disk.hex()} "
                              f"{'✅ 一致' if ok else '❌ 不一致'}")
                for tid in enum_thread_ids(pid):
                    th = k32.OpenThread(0x0002 | 0x0008 | 0x0010, False, tid)
                    if th:
                        threads[tid] = th
                        if bp_addr:
                            set_hwbp(th, bp_addr)
                if bp_addr:
                    n = sum(1 for th in threads.values() if set_hwbp(th, bp_addr))
                    print(f"    [+] 已在 {n} 个线程设置断点")

            elif code == CREATE_THREAD_DEBUG_EVENT:
                th = ctypes.c_void_p(struct.unpack_from("<Q", u, 0)[0])
                threads[ev.dwThreadId] = th
                if bp_addr:
                    set_hwbp(th, bp_addr)

            elif code == EXCEPTION_DEBUG_EVENT:
                ec = struct.unpack_from("<I", u, 0)[0]
                ea = struct.unpack_from("<Q", u, 16)[0]
                if ec == EXCEPTION_SINGLE_STEP and bp_addr and ea == bp_addr:
                    ht = threads.get(ev.dwThreadId)
                    if ht:
                        ctx = CONTEXT64()
                        ctx.ContextFlags = CONTEXT_ALL
                        if k32.GetThreadContext(ht, byref(ctx)):
                            ctx.EFlags |= 0x10000
                            ctx.ContextFlags = CONTEXT_ALL
                            k32.SetThreadContext(ht, byref(ctx))
                            rcx = ctx.Rcx
                            if rcx and rcx not in seen:
                                seen.add(rcx)
                                hits += 1
                                data = read_mem(hproc, rcx, dump_len)
                                out.write(json.dumps({
                                    "kind": "hit", "rva": rva, "addr": hex(rcx),
                                    "t": round(time.time() - t0, 2),
                                    "tid": ev.dwThreadId,
                                    "dump": [data.hex() if data else None],
                                }) + "\n")
                                out.flush()
                                print(f"  [{time.time()-t0:6.1f}s] hit #{hits} "
                                      f"rcx=0x{rcx:X}")

            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
    except KeyboardInterrupt:
        print("\n[*] 手动中断")
    finally:
        try:
            k32.DebugActiveProcessStop(pid)
        except Exception:
            pass
        out.close()

    print(f"\n[+] 结束: 事件 {steps}, 唯一 rcx {hits}")
    print(f"[+] 日志: {os.path.abspath(out_path)}")
    return 0


def list_weixin_pids():
    """返回 [(pid, mem_kb)]，微信未运行则空列表。"""
    import subprocess
    try:
        r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe",
                            "/FO", "CSV", "/NH"],
                           capture_output=True, text=True, timeout=15)
    except Exception:
        return []
    out = []
    for line in r.stdout.strip().split("\n"):
        if not line.strip():
            continue
        p = line.strip('"').split('","')
        if len(p) >= 5:
            try:
                out.append((int(p[1]),
                            int(p[4].replace(',', '').replace(' K', '').strip() or '0')))
            except ValueError:
                pass
    return out


def mode_attach_all(rva, seconds, out_path, dump_len, dll_path):
    """附加到【所有】Weixin.exe 进程，并持续监视新出现的进程。

    为什么这样做：实测发现微信在登出/登录时会替换主进程，
    只附加一个 PID 会随登录一起失效。把整族进程全部附加即可覆盖。
    同样不注入、不改代码（硬件断点）。
    """
    want_size = None
    raw_dll = None
    try:
        raw_dll = open(dll_path, "rb").read()
        e = struct.unpack_from("<I", raw_dll, 0x3C)[0]
        want_size = struct.unpack_from("<I", raw_dll, e + 24 + 56)[0]
    except Exception as exc:
        print(f"[!] 读取 {dll_path} 失败: {exc}", file=sys.stderr)

    out = open(out_path, "w", encoding="utf-8")
    attached = set()
    procs = {}
    seen = set()
    hits = 0
    ev = DEBUG_EVENT()
    t0 = time.time()
    last_scan = -10.0
    events = 0

    print("[*] 全进程附加模式：不注入、不改代码")
    print("[*] 现在请正常使用微信：退出登录 -> 扫码重登（无需用特定窗口）")

    try:
        while time.time() - t0 < seconds:
            now = time.time()
            if now - last_scan >= 1.0:
                last_scan = now
                for pid, mem_kb in list_weixin_pids():
                    if pid in attached:
                        continue
                    if k32.DebugActiveProcess(pid):
                        k32.DebugSetProcessKillOnExit(False)
                        attached.add(pid)
                        print(f"    [+] 附加 PID={pid} ({mem_kb // 1024}MB)"
                              f"  已附加 {len(attached)} 个")

            if not k32.WaitForDebugEvent(byref(ev), 100):
                continue
            code = ev.dwDebugEventCode
            u = bytes(ev.u)
            cont = DBG_CONTINUE
            events += 1
            st = procs.get(ev.dwProcessId)

            if code == CREATE_PROCESS_DEBUG_EVENT:
                h = ctypes.c_void_p(struct.unpack_from("<Q", u, 8)[0])
                st = {"h": h, "bp": None, "threads": {}}
                procs[ev.dwProcessId] = st
                base = find_module_base(h, want_size) if want_size else None
                if base:
                    st["bp"] = base + rva
                    live = read_mem(h, st["bp"], 8)
                    disk = (raw_dll[0x400 + (rva - 0x1000):
                                    0x400 + (rva - 0x1000) + 8] if raw_dll else None)
                    tag = " ✅" if (live and disk and live == disk) else ""
                    print(f"    [+] PID {ev.dwProcessId}: Weixin.dll @ 0x{base:X}"
                          f"  BP=0x{st['bp']:X}{tag}")
                    n = 0
                    for tid in enum_thread_ids(ev.dwProcessId):
                        th = k32.OpenThread(0x0002 | 0x0008 | 0x0010, False, tid)
                        if th:
                            st["threads"][tid] = th
                            if set_hwbp(th, st["bp"]):
                                n += 1
                    print(f"        已在 {n} 个线程设置断点")

            elif code == LOAD_DLL_DEBUG_EVENT and st is not None:
                base = struct.unpack_from("<Q", u, 8)[0]
                if want_size and st.get("bp") is None and st.get("h"):
                    if pe_sizeof_image(st["h"], base) == want_size:
                        st["bp"] = base + rva
                        print(f"    [+] PID {ev.dwProcessId}: Weixin.dll 后加载"
                              f" @ 0x{base:X}")
                        for tid in enum_thread_ids(ev.dwProcessId):
                            th = k32.OpenThread(0x0002 | 0x0008 | 0x0010, False, tid)
                            if th:
                                st["threads"][tid] = th
                                set_hwbp(th, st["bp"])

            elif code == CREATE_THREAD_DEBUG_EVENT and st is not None:
                th = ctypes.c_void_p(struct.unpack_from("<Q", u, 0)[0])
                st["threads"][ev.dwThreadId] = th
                if st.get("bp"):
                    set_hwbp(th, st["bp"])

            elif code == EXCEPTION_DEBUG_EVENT and st is not None:
                ec = struct.unpack_from("<I", u, 0)[0]
                ea = struct.unpack_from("<Q", u, 16)[0]
                if ec == EXCEPTION_SINGLE_STEP and st.get("bp") and ea == st["bp"]:
                    ht = st["threads"].get(ev.dwThreadId)
                    if ht:
                        ctx = CONTEXT64()
                        ctx.ContextFlags = CONTEXT_ALL
                        if k32.GetThreadContext(ht, byref(ctx)):
                            ctx.EFlags |= 0x10000
                            ctx.ContextFlags = CONTEXT_ALL
                            k32.SetThreadContext(ht, byref(ctx))
                            rcx = ctx.Rcx
                            if rcx and rcx not in seen:
                                seen.add(rcx)
                                hits += 1
                                data = read_mem(st["h"], rcx, dump_len)
                                out.write(json.dumps({
                                    "kind": "hit", "rva": rva, "addr": hex(rcx),
                                    "pid": ev.dwProcessId,
                                    "t": round(time.time() - t0, 2),
                                    "tid": ev.dwThreadId,
                                    "dump": [data.hex() if data else None]},
                                    ensure_ascii=False) + "\n")
                                out.flush()
                                if hits <= 20 or hits % 200 == 0:
                                    print(f"  [{time.time()-t0:6.1f}s] hit #{hits} "
                                          f"pid={ev.dwProcessId} rcx=0x{rcx:X}")

            elif code == EXIT_PROCESS_DEBUG_EVENT:
                procs.pop(ev.dwProcessId, None)

            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

            if events % 20000 == 0:
                print(f"    ... {time.time()-t0:.0f}s, 事件 {events}, "
                      f"附加 {len(attached)}, 命中 {hits}", flush=True)
    except KeyboardInterrupt:
        print("\n[*] 手动中断")
    finally:
        out.close()
        for pid in list(attached):
            try:
                k32.DebugActiveProcessStop(pid)
            except Exception:
                pass

    print(f"\n[+] 结束: 事件 {events}, 附加过 {len(attached)} 个进程, 唯一 rcx {hits}")
    print(f"[+] 日志: {os.path.abspath(out_path)}")
    return 0


# ---------------------------------------------------------------- 主流程
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=None, help="省略则自动探测")
    ap.add_argument("--rva", default="0x3634F10")
    ap.add_argument("--seconds", type=int, default=300)
    ap.add_argument("--out", default="hwbp.jsonl")
    ap.add_argument("--dump", type=int, default=64)
    ap.add_argument("--attach-all", action="store_true",
                    help="附加到所有 Weixin.exe 进程并持续监视新进程（推荐）")
    ap.add_argument("--attach", type=int, default=None,
                    help="附加到已在运行的 PID（不重启微信、不扫码）")
    ap.add_argument("--dll", default=None, help="省略则自动探测")
    args = ap.parse_args()
    rva = int(args.rva, 0)
    args.exe = args.exe or find_weixin_exe()
    args.dll = args.dll or find_weixin_dll()
    if not args.dll:
        print('[!] 找不到 Weixin.dll，请用 --dll 指定', file=sys.stderr)
        return 1

    if args.attach_all:
        return mode_attach_all(rva, args.seconds, args.out, args.dump, args.dll)
    if args.attach:
        return mode_attach(args.attach, rva, args.seconds, args.out,
                           args.dump, args.dll)

    want_size = None
    raw_dll = None
    try:
        raw_dll = open(args.dll, "rb").read()
        e = struct.unpack_from("<I", raw_dll, 0x3C)[0]
        want_size = struct.unpack_from("<I", raw_dll, e + 24 + 56)[0]
    except Exception as exc:
        print(f"[!] 读取 {args.dll} 失败: {exc}", file=sys.stderr)

    si = STARTUPINFO()
    si.cb = sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = k32.CreateProcessW(None, ctypes.c_wchar_p(args.exe), None, None, False,
                            DEBUG_PROCESS, None, None, byref(si), byref(pi))
    if not ok:
        print(f"[!] CreateProcess 失败: {ctypes.get_last_error()}", file=sys.stderr)
        return 1
    print(f"[*] 已以调试方式启动 PID={pi.dwProcessId}（DEBUG_PROCESS：整个进程树）")
    print(f"[*] 目标断点 RVA = 0x{rva:X}")
    print(f"[*] ⚠️  请使用【这个】微信窗口登录，不要点桌面图标")

    out = open(args.out, "w", encoding="utf-8")
    procs = {}          # pid -> {"h": hproc, "bp": addr, "threads": {}}
    seen = set()
    hits = 0
    ev = DEBUG_EVENT()
    t0 = time.time()
    steps = 0

    def arm(pid_state, pid):
        """给某进程的全部线程挂上断点。"""
        if not pid_state.get("bp"):
            return
        n = 0
        for tid in enum_thread_ids(pid):
            th = k32.OpenThread(0x0002 | 0x0008 | 0x0010, False, tid)
            if th:
                pid_state["threads"][tid] = th
                if set_hwbp(th, pid_state["bp"]):
                    n += 1
        print(f"    [+] PID {pid}: 已在 {n} 个线程设置断点")

    try:
        while time.time() - t0 < args.seconds:
            if not k32.WaitForDebugEvent(byref(ev), 1000):
                continue
            code = ev.dwDebugEventCode
            u = bytes(ev.u)
            cont = DBG_CONTINUE
            steps += 1
            st = procs.get(ev.dwProcessId)

            if code == CREATE_PROCESS_DEBUG_EVENT:
                h = ctypes.c_void_p(struct.unpack_from("<Q", u, 8)[0])
                st = {"h": h, "bp": None, "threads": {}}
                procs[ev.dwProcessId] = st
                # 该进程可能已加载 Weixin.dll（attach 场景），也可能稍后加载
                base = find_module_base(h, want_size) if want_size else None
                if base:
                    st["bp"] = base + rva
                    live = read_mem(h, st["bp"], 8)
                    disk = raw_dll[0x400 + (rva - 0x1000):0x400 + (rva - 0x1000) + 8] if raw_dll else None
                    tag = ""
                    if live and disk:
                        tag = " ✅" if live == disk else " ❌"
                    print(f"    [+] PID {ev.dwProcessId}: Weixin.dll @ 0x{base:X} "
                          f"BP=0x{st['bp']:X} 字节校验{tag}")
                    arm(st, ev.dwProcessId)

            elif code == LOAD_DLL_DEBUG_EVENT and st is not None:
                base = struct.unpack_from("<Q", u, 8)[0]
                if want_size and st.get("bp") is None and st.get("h"):
                    if pe_sizeof_image(st["h"], base) == want_size:
                        st["bp"] = base + rva
                        print(f"    [+] PID {ev.dwProcessId}: Weixin.dll 后加载 "
                              f"@ 0x{base:X} BP=0x{st['bp']:X}")
                        arm(st, ev.dwProcessId)

            elif code == CREATE_THREAD_DEBUG_EVENT and st is not None:
                th = ctypes.c_void_p(struct.unpack_from("<Q", u, 0)[0])
                st["threads"][ev.dwThreadId] = th
                if st.get("bp"):
                    set_hwbp(th, st["bp"])

            elif code == EXCEPTION_DEBUG_EVENT and st is not None:
                ec = struct.unpack_from("<I", u, 0)[0]
                ea = struct.unpack_from("<Q", u, 16)[0]
                if ec == EXCEPTION_SINGLE_STEP and st.get("bp") and ea == st["bp"]:
                    ht = st["threads"].get(ev.dwThreadId)
                    if ht:
                        ctx = CONTEXT64()
                        ctx.ContextFlags = CONTEXT_ALL
                        if k32.GetThreadContext(ht, byref(ctx)):
                            ctx.EFlags |= 0x10000
                            ctx.ContextFlags = CONTEXT_ALL
                            k32.SetThreadContext(ht, byref(ctx))
                            rcx = ctx.Rcx
                            if rcx and rcx not in seen:
                                seen.add(rcx)
                                hits += 1
                                data = read_mem(st["h"], rcx, args.dump)
                                rec = {"kind": "hit", "rva": rva, "addr": hex(rcx),
                                       "pid": ev.dwProcessId,
                                       "t": round(time.time() - t0, 2),
                                       "tid": ev.dwThreadId,
                                       "dump": [data.hex() if data else None]}
                                out.write(json.dumps(rec) + "\n")
                                out.flush()
                                if hits <= 20 or hits % 200 == 0:
                                    print(f"  [{time.time()-t0:6.1f}s] hit #{hits} "
                                          f"pid={ev.dwProcessId} rcx=0x{rcx:X}")

            elif code == EXIT_PROCESS_DEBUG_EVENT:
                procs.pop(ev.dwProcessId, None)

            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
    except KeyboardInterrupt:
        print("\n[*] 手动中断")
    finally:
        out.close()

    print(f"\n[+] 结束: 事件 {steps}, 进程 {len(procs)}, 唯一 rcx {hits}")
    print(f"[+] 日志: {os.path.abspath(args.out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
