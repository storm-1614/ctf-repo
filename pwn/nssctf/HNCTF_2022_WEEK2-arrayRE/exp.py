def decode(a1, a2):
    return ((35 * (a1 - 48) + 18 * (a2 - 48) + 2) % 10)

s = ""

for i in range(len(s)):
    s[i + 1] = (decode(s[i], (i + s[i])) + v3 + 3) % 10 + 48
