# FTS 兜底方案

当消息分片密钥不可得时，从 `message_fts.db` 补齐缺失的近期消息。

## 为什么可行

微信的数据库**各自独立加密**，每库一把密钥。这意味着：

- 新分片 `message_1.db` 拿不到密钥 → 跳过
- 但 `message_fts.db`（全文索引）**可能仍保有可用密钥**
- 而 FTS 索引了**所有**消息的正文

所以新分片打不开时，消息正文仍可能从 FTS 拿到。

## 代价（必须知道）

| 有 | 无 |
|---|---|
| 文字内容（完整） | 非文本消息的完整元数据 |
| 时间戳（精确） | 图片/语音/表情的原始字段 |
| 发送者（准确） | 部分非文本消息可能整体缺失 |

对本仓库的目标场景（聊天记录分析）来说，文字 + 时间 + 发送者已经足够；
但**不要**把它当作完整备份方案。

## ID 空间陷阱（本方案最容易踩的坑）

> ⚠️ FTS 的 `session_id` / `sender_id` **不是** `message_0.db` 里
> `Name2Id` 表的 rowid。

实测同一个联系人：

```
FTS   中该联系人的 session_id = 325
message_0.db 的 Name2Id 中，rowid 325 = 另一个人，该联系人实际是 326
```

换句话说，**任何硬编码的 ID 映射都会指错人**。

### 解决：锚点匹配

`fts_fallback.py` 不依赖任何 ID 映射，改用数据自身对齐：

1. 从主库已经提取出的消息中取 `(local_id, create_time)` 集合作为锚点
2. 遍历 FTS 中每一个 `session_id`，统计其行与该锚点集合的命中数
3. 命中数最高的 session 即目标会话
4. 在该 session 内，用锚点消息已知的 `sender` 反推 `sender_id → me/them` 的映射

这样无论 ID 空间如何变化，都能自动对齐。

实测命中率：

```
锚点命中 817 条 / 原有 917 条（约 89%）
```

（未命中的部分是 FTS 不索引的非文本消息，属预期。）

## 用法

### 独立 CLI

```bash
# 预览（不覆盖原文件）
python tools/recover_fts.py --decrypted-dir <解密目录> --messages data/messages.json

# 就地更新
python tools/recover_fts.py --decrypted-dir <解密目录> --messages data/messages.json --in-place
```

### 作为模块

```python
from fts_fallback import recover_missing, merge_into

result = recover_missing(decrypted_dir, known_messages)
if result["ok"]:
    messages = merge_into(known_messages, result["messages"])
```

`recover_missing` 返回：

```python
{
    "ok": bool,
    "reason": str,          # ok=False 时的原因
    "session_id": int,
    "match_hits": int,      # 锚点命中数，越高越可信
    "messages": [...],      # 可直接追加的记录
}
```

## FTS 表结构

分片表名形如 `message_fts_v4_0` … `message_fts_v4_N`，随数据增长自动增加。
本模块**动态发现**分片，不硬编码数量。

字段：

| 字段 | 说明 |
|---|---|
| `acontent` | 消息正文（含 `\x08` 分隔控制字符，需清理） |
| `message_local_id` | 对应主库的 local_id |
| `create_time` | 秒级时间戳 |
| `session_id` | 会话 ID（**注意：非 Name2Id 空间**） |
| `sender_id` | 发送者 ID（**同上**） |
| `local_type` | 消息类型，与主库一致（1=文本 等） |

## 建议

FTS 兜底应该视为**降级路径**，不是等价替代。理想行为是：

1. 主库能解密 → 用主库（完整）
2. 主库缺密钥 → **告警**，并自动降级到 FTS
3. 两种来源都不可得 → 明确失败，而不是返回不完整结果

当前 `extract_messages.py` 已按此实现（默认开启，`--no-fts-fallback` 关闭）。
