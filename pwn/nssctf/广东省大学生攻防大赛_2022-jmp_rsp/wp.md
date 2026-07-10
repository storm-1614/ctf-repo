很巧妙的 ret2shellcode

把 buf 填充然后打断点到 main 函数的 ret 位置，查看寄存器状态：  

![](1.png)

发现 rsi 指向 buf 的最开始。  
如果 push rsi 入栈，这样接下来 rip 开始执行就会跳到 buf 开头执行。所以在 buf 位置放下 shellcode 即可。  
所以不要着急呀，要细心，寄存器都得看看。  
