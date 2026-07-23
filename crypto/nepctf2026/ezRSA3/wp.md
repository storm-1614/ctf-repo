# ezRSA3 Writeup

## 题目描述

RSA 加密，已知 `e = 65537`，给出 `sops`（10000 个 50-bit 素数）、`N`、`c`。

`p` 的生成方式存在漏洞：

```python
n = 10000
k = 10

sops = sorted(s)  # 10000 个 50-bit 素数

def get_p():
    while True:
        p = 2 * prod(sample(sops, k)) - 1  # k = 10
        if is_prime(p) and gcd(p - 1, e) == 1:
            return p

def get_q():
    while True:
        q = getPrime(512)
        if gcd(q - 1, e) == 1:
            return q
```

## 漏洞分析

核心漏洞在于 `p` 的构造方式：

$$p = 2 \times \prod_{i=1}^{10} r_i - 1$$

其中 $r_i$ 是从 `sops` 中随机选取的 10 个 50-bit 素数。

这意味着：

$$p + 1 = 2 \times \prod_{i=1}^{10} r_i$$

**`p+1` 的所有素因子都在已知集合 `sops` 中，即 `p+1` 是光滑的（B-smooth）。**

这恰好符合 **Williams' p+1 因子分解算法** 的攻击场景。

## Williams' p+1 算法

### Lucas 序列

定义 Lucas 序列 $V_n(P, Q)$，本题取 $Q = 1$：

$$V_0 = 2,\quad V_1 = P,\quad V_{n+1} = P \cdot V_n - V_{n-1}$$

### 关键性质

1. **倍乘公式**：
   $$V_{2n} = V_n^2 - 2$$
   $$V_{2n+1} = V_n \cdot V_{n+1} - P$$

2. **组合性质**：
   $$V_m(V_n(P), 1) = V_{m \cdot n}(P, 1)$$

3. **核心定理**：若 Legendre 符号 $\left(\frac{P^2-4}{p}\right) = -1$，则：
   $$V_{p+1}(P) \equiv 2 \pmod{p}$$

   进而对任意 $p+1$ 的倍数 $K$：
   $$V_K(P) \equiv 2 \pmod{p}$$

### 攻击思路

由于 $p+1 \mid 2 \times \prod_{r \in \text{sops}} r$，我们可以迭代计算：

1. 令 $V = P$（选取一个起始值，如 $P = 7, 9, 11, \ldots$）
2. $V \leftarrow V_2(V) = V^2 - 2 \pmod{N}$（乘以因子 2）
3. 对每个 $r \in \text{sops}$：$V \leftarrow V_r(V) \pmod{N}$（乘以素因子 $r$）

由组合性质，最终 $V = V_{2 \cdot \prod r}(P) \pmod{N}$。

由于 $p+1 \mid 2 \cdot \prod r$，有 $V \equiv 2 \pmod{p}$。

计算 $\gcd(V - 2, N)$ 即可得到 $p$（概率约 1/2，取决于 Legendre 符号）。

## 攻击实现

```python
#!/usr/bin/env python3
from math import gcd

exec(open('out.py').read())  # 读取 sops, N, c

def lucas_V_binary(k, P, N):
    """用二进制法（快速幂）计算 Lucas 序列 V_k(P, 1) mod N"""
    if k == 0:
        return 2 % N
    if k == 1:
        return P % N

    v_n = P % N              # V_1
    v_np1 = (P * P - 2) % N  # V_2

    bits = bin(k)[3:]  # 跳过 '0b1'，从次高位开始

    for bit in bits:
        if bit == '0':
            # n → 2n
            v_2n   = (v_n * v_n - 2) % N
            v_2np1 = (v_n * v_np1 - P) % N
            v_n, v_np1 = v_2n, v_2np1
        else:
            # n → 2n+1
            v_2np1 = (v_n * v_np1 - P) % N
            v_2np2 = (v_np1 * v_np1 - 2) % N
            v_n, v_np1 = v_2np1, v_2np2

    return v_n


def williams_pp1(N, sops, start_P):
    """Williams' p+1 分解"""
    V = start_P % N
    V = (V * V - 2) % N       # 乘以因子 2 → V_2
    for r in sops:            # 乘以所有 10000 个素数
        V = lucas_V_binary(r, V, N)
    return V


# 尝试不同起始值 P（Legendre符号条件，概率约 1/2）
for P in [7, 9, 11, 13, 17, 19, 23, 29, 31]:
    V = williams_pp1(N, sops, start_P=P)
    g = gcd(V - 2, N)
    if g != 1 and g != N:
        p = g
        q = N // p
        break

# RSA 解密
e = 65537
d = pow(e, -1, (p - 1) * (q - 1))
m = pow(c, d, N)
flag = m.to_bytes((m.bit_length() + 7) // 8, 'big')
print(flag.decode())
```

## 复杂度分析

- `sops` 包含 $10000$ 个素数，每个约 $50$ 比特
- 对每个素数，二进制法需约 $50$ 次迭代
- 每次迭代 $2$ 次模乘（$1008$ 比特模数）
- 总运算量：$10000 \times 50 \times 2 \approx 10^6$ 次模乘
- Python 内置大整数（基于 GMP）在 $1000$ 比特级别每次模乘约 $1\text{--}2\mu s$
- **实际运行时间：约 2 秒**

## 结果

```
N bits: 1008
Trying P = 7...   gcd(V-2, N) = 1
Trying P = 9...   gcd(V-2, N) = 174275...  ✅

p = 174275...  (496 bits)
q = 926530...  (512 bits)

FLAG: NepCTF{5m0o7h_m4k3s_w1lliam_gr34t}
```

## Flag

```
NepCTF{5m0o7h_m4k3s_w1lliam_gr34t}
```

## 总结

| 知识点 | 说明 |
|--------|------|
| **漏洞类型** | `p+1` 光滑（smooth） |
| **攻击方法** | Williams' p+1 因子分解 |
| **核心技巧** | Lucas 序列组合性质 + 快速幂 |
| **关键条件** | `p+1` 的所有素因子在已知集合中 |
| **防御措施** | 生成素数时确保 `p±1` 至少有一个大素因子 |

当 RSA 的素因子 $p$ 满足 $p+1$（或 $p-1$）仅包含小素因子时，可分别被 **Williams' p+1** 或 **Pollard's p−1** 算法高效分解。本题通过 $p = 2 \cdot \prod r_i - 1$ 的构造，使 $p+1$ 的素因子全部暴露在已知集合 `sops` 中，从而在数秒内被攻破。
