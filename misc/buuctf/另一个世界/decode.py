a = "01101011011011110110010101101011011010100011001101110011"
a = "\n".join(a[i : i + 8] for i in range(0, len(a), 8))


b = ""

for i in a.split("\n"):
    b += chr(int(i, 2))
print(b)
