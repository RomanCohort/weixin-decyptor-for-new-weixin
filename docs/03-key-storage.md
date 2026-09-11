# 密钥持久化位置与包装结构（4.1.13.65 实测）

本文档记录微信 4.1.11+ 密钥持久化位置的定位结果，以及对其包装结构的分析。
**结论是负面的，但过程可复现** —— 目的是省掉后来人的重复劳动。

> 本文档不包含任何个人数据、账号标识、密钥值或聊天内容。

## 一、位置

```
<xwechat_files>/all_users/login/<wxid>/key_info.db
```

**它是明文 SQLite**（不是 SQLCipher）：

```
文件头: 53514c69746520666f726d6174203300  =  "SQLite format 3\0"
WAL 头: 377f0682  =  合法 SQLite WAL magic
```

直接 `sqlite3.connect()` 就能打开，**不需要任何密钥**。

### 表结构

```sql
CREATE TABLE LoginKeyInfoTable(
    user_name_md5 TEXT,
    key_md5       TEXT,
    key_info_md5  TEXT,
    key_info_data BLOB
);
CREATE UNIQUE INDEX LoginKeyInfoTable_USER_KEYINFO
    ON LoginKeyInfoTable(user_name_md5, key_info_md5);
```

实测：

- `user_name_md5` = `md5(wxid)`
- `key_info_md5` = **`md5(key_info_data)`**（203/203 命中，纯内容哈希，用于去重）
- `key_md5` 在实测样本中为空
- 条数随使用量累积（实测一个常用账号 203 行，另一个账号 1 行）

## 二、`key_info_data` 的结构

每个 blob 固定 **180 字节**。对比同机两个不同账号的 blob，
可分离出「跨账号常量」与「逐条变化」两区：

```
偏移        性质              长度    说明
[  0:  3)   常量              3       0a a8 01  = protobuf field1, LEN=168
[  3: 17)   跨账号相同        14      疑似格式头/版本
[ 17: 31)   逐条变化          14      疑似 nonce / IV
[ 31: 32)   常量              1       0x20 (=32)
[ 32: 35)   常量              3       00 00 00
[ 35: 67)   跨账号相同        32      ★ 32 字节全局常量
[ 67:171)   逐条变化         104      疑似密文
[171:175)   常量              4
[175:179)   逐条变化          4
[179:180)   常量              1
```

**注意 [35:67) 那 32 字节：它在同一台机器的两个不同账号之间完全相同。**
这暗示它是设备级或硬编码常量，而非账号专属。

## 三、已排除的假设（全部有 oracle 校验）

关键前提：我们手上有 18 组已知的 `(salt, enc_key)` 对应关系
（来自密钥尚未变更时期的快照），**因此任何解开的结果都能立即验证**。

### ① 密钥明文就在 blob 里

对 **180 字节内每一个 32 字节窗口**做 PBKDF2-HMAC-SHA512(候选, salt, 256000, 32)，
与已知 enc_key 比对：

```
校验 149 个候选窗口，耗时 29.6s
未命中。
```

### ② 全局 32 字节常量就是包装密钥

以 [35:67) 为密钥，交叉尝试：

- 算法：AES-256-GCM / AES-256-CBC / AES-256-CTR / ChaCha20
- nonce/IV 候选：[17:29)、[17:31)、[17:33)、[3:17)、[17:8)
- 密文切片候选：[67:171)、[66:170)、[71:167)、[67:163)、[3:171)、[31:171)
- 对 5 个不同 blob 样本重复

结果：**全部未命中**（解出的明文里既无已知 salt，也无已知 enc_key）。

### ③ 常量是设备标识的派生

以本机 `MachineGuid` / 用户 `SID` / 计算机名 / 用户名 / wxid 为材料，
单值 + 两两组合，UTF-8 与 UTF-16-LE 两种编码，
分别取 SHA-256 / SHA-512[:32] / MD5：

结果：**全部未命中**。

### ④ DPAPI 包装

搜索 DPAPI blob 特征头 `d08c9ddf0115d1118c7a00c79eb...`：

```
0/203 命中
```

### ⑤ 已知密钥出现在其他本地存储

对以下位置搜索过已知 salt / enc_key 的原始字节与 hex 形式，均无命中：

- 全部 MMKV 文件
- `all_users/config/{client_config,global_config,upgrade_v4}`

## 四、密码学侧的证据

`Weixin.dll` 的导入表**只有 `KERNEL32.dll` 一个条目** —— 所有加密 API
均为运行时动态解析（典型反分析设计）。

但加密实现是**静态链接的**（BoringSSL 特征）：

| 常量 | 出现 |
|---|---|
| AES 逆 S-box | 2 |
| ChaCha20 `expand 32-byte k` | 1 |
| `aes_` 前缀符号 | 16 |
| `gcm` / `GCM` | 33 / 101 |

即：包装用的是**标准 AEAD**（AES-GCM 或 ChaCha20-Poly1305），无自创密码学。

## 五、为什么离线解不开

**这不是「算法不够复杂」的问题。** AES-GCM 是公开标准，任何人都能实现——
**算法的公开性正是其安全性的来源**。加密的设计目标就是：没有密钥时，
密文与随机数在计算上不可区分。

缺的不是「实现算法的能力」，是**那 32 字节的包装密钥**。

从 `key_info.db` 的设计可以推断其生命周期：

```
每次登录 → 获得会话主密钥（服务器下发 / 由登录凭据派生）
   ↓  用它把各 db 密钥打包
写入 key_info.db
   ↓
退出登录 → 主密钥从内存消失，磁盘上不留
```

**主密钥不落盘** —— 这解释了为什么在 MMKV、config、key_info.db 中
都搜不到它。

## 六、给继续研究的人

定位到的相关代码（可直接用 `tools/disasm_func.py` 反汇编）：

| 用途 | RVA |
|---|---|
| 引用 `LoginKeyInfoTable` | `Weixin.dll + 0x30789A0` (1102 字节) |
| 引用 `LoginKeyInfoTable` | `Weixin.dll + 0x3078F40` (3042 字节) |
| 引用 `LoginKeyInfoTable` | `Weixin.dll + 0x307A4A0` (2689 字节) |
| 引用 `key_info_data` | `Weixin.dll + 0x1018FF0` (912 字节) |

（`0x1018FF0` 经确认只是 **ORM 的 schema 注册器**，不含加密逻辑；
读写的实现在另外三个函数里。）

### 尚未尝试、但可能有价值的方向

1. **确认 [35:67) 那 32 字节常量的性质** —— 在另一台机器上比对，
   若不同则说明它是设备派生；若相同则是硬编码。
   若为设备派生，逆向出派生算法即可离线复现。
2. **动态确认包装算法** —— 对上述三个函数下断点，观察其对
   `key_info_data` 的读写路径。
3. **运行时捕获** —— 即社区现有的 Frida 方案（见 README 风险说明）。

### 复现本文档所需的工具

- `tools/disasm_func.py` —— 带注解的 x64 反汇编器（自动标注 call 目标与字符串引用）
- `tools/find_wechat_codec_offset.py` —— 静态推导 codec 函数偏移
