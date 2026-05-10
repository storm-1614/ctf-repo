# tcache(thread local cache)
用于在提升 glibc 的小块分配释放速度。  
是 glibc 内存分配器在 2.26 引入的一种线程本地缓存机制，旨在显著提升多线程程序的内存分配与释放速度。  
tcache 使用单链表实现，glibc 为每个使用堆的线程分配一个 tcache 管理结构，放在线程的堆段开头：  
``` c
typedef struct tcache_perthread_struct {
    uint16_t counts[TCACHE_MAX_BINS];   // 每个大小类别的 chunk 数量
    tcache_entry *entries[TCACHE_MAX_BINS]; // 指向各个链表的头指针
} tcache_perthread_struct;
```


