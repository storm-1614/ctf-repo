with open('novel.txt', 'r', encoding='utf-8') as f:
    content = f.read()

# 提取 VS1-VS16 变体选择器
vs = [ord(ch) - 0xFE00 for ch in content if 0xFE00 <= ord(ch) <= 0xFE0F]

# 大端序 nibble 对 -> 字节
raw = bytes([(vs[i] << 4) | vs[i+1] for i in range(0, len(vs), 2)])

# Flag 起始于偏移 5 字节处
flag = raw[5:5+53].decode('ascii')
print(flag)

