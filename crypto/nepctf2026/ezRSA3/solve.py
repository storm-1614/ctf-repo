#!/usr/bin/env python3
"""
Williams' p+1 factorization attack.

p = 2 * prod(10 primes from sops) - 1
=> p+1 = 2 * product_of_10_primes_from_sops

Since p+1 is smooth with all factors in the known set sops,
we can use Williams' p+1 method with Lucas sequences.

For Lucas V sequence with parameters (P, 1):
  V_0 = 2, V_1 = P
  V_{n+1} = P * V_n - V_{n-1}
  V_{2n} = V_n^2 - 2

Composition property: V_m(V_n(P)) = V_{m*n}(P)

If (P^2 - 4 | p) = -1 (Legendre symbol), then:
  V_{p+1} ≡ 2 (mod p)
  and for any multiple k of p+1: V_k ≡ 2 (mod p)

So we compute V_{2 * prod(all_sops)} iteratively:
  V ← V_2(V) then V ← V_r(V) for each r in sops
  Then gcd(V - 2, N) = p
"""

import sys
from math import gcd

# Read data
exec(open('out.py').read())

def lucas_V_binary(k, P, N):
    """
    Compute V_k for Lucas sequence with parameters (P, 1) modulo N.
    Uses binary exponentiation method.

    Maintains (V_n, V_{n+1}) and doubles/increments based on bits of k.
    """
    if k == 0:
        return 2 % N
    if k == 1:
        return P % N

    v_n = P % N           # V_1
    v_np1 = (P * P - 2) % N  # V_2

    # Process bits of k from second-most-significant to least
    bits = bin(k)[3:]  # skip '0b1'

    for bit in bits:
        if bit == '0':
            # n -> 2n:  (V_n, V_{n+1}) -> (V_{2n}, V_{2n+1})
            v_2n = (v_n * v_n - 2) % N
            v_2np1 = (v_n * v_np1 - P) % N
            v_n, v_np1 = v_2n, v_2np1
        else:
            # n -> 2n+1:  (V_n, V_{n+1}) -> (V_{2n+1}, V_{2n+2})
            v_2np1 = (v_n * v_np1 - P) % N
            v_2np2 = (v_np1 * v_np1 - 2) % N
            v_n, v_np1 = v_2np1, v_2np2

    return v_n


def williams_pp1(N, sops, start_P=7):
    """
    Williams' p+1 factorization.

    Computes V_{2 * prod(all sops)}(start_P) mod N.
    Since p+1 divides 2 * prod(all sops), we get V ≡ 2 (mod p).
    """
    V = start_P % N

    # Multiply by 2: V → V_2(V)
    V = (V * V - 2) % N
    print(f"  After factor 2: processed")

    for i, r in enumerate(sops):
        V = lucas_V_binary(r, V, N)
        if (i + 1) % 1000 == 0:
            print(f"  Processed {i+1}/{len(sops)} primes...")

    return V


if __name__ == '__main__':
    print(f"[*] N bits: {N.bit_length()}")
    print(f"[*] Number of primes in sops: {len(sops)}")
    print(f"[*] Each prime is ~50 bits")
    print(f"[*] p+1 = 2 * product of 10 primes from sops")
    print()

    # Try different starting values for P
    for P in [7, 9, 11, 13, 17, 19, 23, 29, 31]:
        print(f"[*] Trying P = {P}...")
        V = williams_pp1(N, sops, start_P=P)
        g = gcd(V - 2, N)
        print(f"    gcd(V-2, N) = {g}")

        if g != 1 and g != N:
            p = g
            q = N // p
            print(f"\n[+] FACTOR FOUND!")
            print(f"    p = {p}")
            print(f"    q = {q}")
            print(f"    p bits: {p.bit_length()}")
            print(f"    q bits: {q.bit_length()}")

            # Verify
            assert p * q == N
            assert p != 1 and q != 1

            # Decrypt
            e = 65537
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            m = pow(c, d, N)
            flag = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            print(f"\n[+] FLAG: {flag.decode()}")
            sys.exit(0)

    print("[-] Failed to factor with tried P values")
