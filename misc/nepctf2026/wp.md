# NepCTF 2026 Misc — novel

## 题目描述

给了一个 `novel.txt`，是一篇看起来"正常"的修真网文。但仔细看能发现每个中文字符后面都跟着一个不可见的 Unicode 字符。

## 分析

用 `xxd` 或 Python 读取十六进制，可以发现每个 CJK 字符后都嵌入了一个 Unicode **变体选择器 (Variation Selector)**：

- 范围：U+FE00 ~ U+FE0F
- 共 16 个（VS1 ~ VS16）
- 每个可以表示 4 位 (nibble)，即 0~15 中的一个值

这 16 个字符在正常的文本渲染中是不可见的，肉眼看上去只是一篇普通小说，但实际携带了隐藏信息。

## 解码原理

1. 提取所有 U+FE00 ~ U+FE0F 范围内的字符
2. 映射 VS1=0, VS2=1, ..., VS16=15
3. 每两个 VS 组成一个字节（大端序：前一个为高 4 位，后一个为低 4 位）
4. 解码得到 ASCII 字符串

## 解题脚本

```python
with open('novel.txt', 'r', encoding='utf-8') as f:
    content = f.read()

# 提取 VS1-VS16 变体选择器
vs = [ord(ch) - 0xFE00 for ch in content if 0xFE00 <= ord(ch) <= 0xFE0F]

# 大端序 nibble 对 -> 字节
raw = bytes([(vs[i] << 4) | vs[i+1] for i in range(0, len(vs), 2)])

# Flag 起始于偏移 5 字节处
flag = raw[5:5+53].decode('ascii')
print(flag)
```

## Flag

```
NepCTF{var1at10n_s3l3ct0rs_h4unt_th3_n0v3l-afk6324}
```

## 总结

本题考察 **Unicode 隐写术 (Unicode Steganography)**，利用 Variation Selectors（U+FE00~U+FE0F）在可见文本中嵌入二进制数据。这是 CTF misc 中一类经典的隐写手法，关键在于识别出不可见字符的存在并正确解码。
