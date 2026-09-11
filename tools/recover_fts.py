"""
recover_fts.py - 独立 CLI：从 message_fts.db 补齐 messages.json 中缺失的近期消息。

适用场景
--------
微信 4.1.11+ 起数据库密钥不再驻留内存，社区内存扫描方案失效。当微信新建
消息分片（message_1.db …）时，如果解密环节拿不到新分片的密钥，就会静默
跳过，导致导出的 messages.json **丢失最近的全部消息**，而使用者往往毫无
察觉（总数看起来只是"少了一点"）。

本工具读取已解密目录中的 message_fts.db（全文索引，独立加密，密钥可能
仍然可用），自动定位目标会话并把缺失的部分补进 messages.json。

安全说明
--------
- 全程本地运行，不联网、不上传任何数据。
- 只读取本机已解密的数据库文件，不接触原始加密库。
- 默认先输出到 *_recovered.json，确认无误后再覆盖原文件（--in-place）。

用法
----
    # 预览：不修改原文件，输出到 data/messages_recovered.json
    python tools/recover_fts.py --decrypted-dir <解密目录> --messages data/messages.json

    # 直接就地更新
    python tools/recover_fts.py --decrypted-dir <解密目录> --messages data/messages.json --in-place
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fts_fallback import recover_missing, merge_into  # noqa: E402


def main():
    ap = argparse.ArgumentParser(
        description="从 message_fts.db 补齐 messages.json 中缺失的近期消息")
    ap.add_argument("--decrypted-dir", required=True,
                    help="解密后的数据库目录（含 message/message_fts.db）")
    ap.add_argument("--messages", required=True,
                    help="已有的 messages.json 路径")
    ap.add_argument("--in-place", action="store_true",
                    help="就地覆盖原文件（默认输出到 *_recovered.json）")
    ap.add_argument("--min-hits", type=int, default=3,
                    help="会话锚点匹配的最低命中数，低于此值放弃（默认 3）")
    args = ap.parse_args()

    with open(args.messages, encoding="utf-8") as f:
        bundle = json.load(f)
    messages = bundle.get("messages") if isinstance(bundle, dict) else bundle
    if not messages:
        print("[!] messages.json 中没有消息，无法做锚点匹配", file=sys.stderr)
        sys.exit(1)

    if args.min_hits != 3:
        # recover_missing 内部用默认阈值；此处仅在自定义时提示
        print(f"[*] 注意: --min-hits={args.min_hits} 当前未生效（模块内固定为 3）",
              file=sys.stderr)

    result = recover_missing(args.decrypted_dir, messages)
    if not result["ok"]:
        print(f"[!] 未能补齐: {result['reason']}", file=sys.stderr)
        sys.exit(2)

    new = result["messages"]
    if not new:
        print("[*] FTS 中没有比现有记录更新的消息，无需补齐")
        return

    merged = merge_into(messages, new)
    if isinstance(bundle, dict):
        bundle["messages"] = merged
        bundle["total"] = len(merged)
        bundle["fts_fallback"] = {
            "session_id": result["session_id"],
            "match_hits": result["match_hits"],
            "recovered": len(new),
        }
        out_obj = bundle
    else:
        out_obj = merged

    out_path = args.messages if args.in_place else os.path.splitext(args.messages)[0] + "_recovered.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, ensure_ascii=False, indent=2)

    print(f"[+] 补出 {len(new)} 条新消息（锚点命中 {result['match_hits']} 条）")
    print(f"[+] 已写入 {out_path}")
    if not args.in_place:
        print("[*] 确认无误后可加 --in-place 直接覆盖原文件")


if __name__ == "__main__":
    main()
