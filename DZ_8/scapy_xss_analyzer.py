#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DZ 8 (этапы 2–4). Перехват и анализ HTTP-трафика, поиск следов XSS в pcap.

Важно:
- Скрипт рассчитан на HTTP (tcp/80). Для HTTPS содержимое не будет видно без MITM.
- Для перехвата на Linux обычно нужен запуск от root: sudo python3 scapy_xss_analyzer.py ...
- Учебный скрипт. Запускайте только на стендах/целевых учебных ресурсах.

Функциональность:
- --capture HOSTNAME: перехват HTTP-трафика до HOSTNAME (tcp/80) и сохранение в pcap
- --analyze FILE.pcap: анализ pcap, извлечение HTTP сообщений, декодирование gzip/chunked, поиск XSS-паттернов
- --send URL: отправка базового HTTP запроса (GET либо кастомного raw HTTP через --request)

Автор: укажи ФИО
"""

import argparse
import socket
import random
import time
import re
import gzip
from io import BytesIO
from urllib.parse import urlparse, unquote_plus

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
from scapy.all import sniff, wrpcap, rdpcap


def resolve_hostname(hostname: str):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка DNS для '{hostname}': {e}")
        return None


def parse_url(url_arg: str):
    """Парсит URL и извлекает hostname, path и scheme."""
    if not url_arg.startswith('http://') and not url_arg.startswith('https://'):
        url_arg = 'http://' + url_arg
    try:
        parsed = urlparse(url_arg)
        hostname = parsed.hostname
        path = parsed.path if parsed.path else '/'
        if parsed.query:
            path = f"{path}?{parsed.query}"
        scheme = parsed.scheme or 'http'
        return hostname, path, scheme
    except Exception as e:
        print(f"Ошибка парсинга URL: {e}")
        return None, None, None


def send_http_request(hostname: str, path: str, custom_request: str | None = None):
    """Отправляет HTTP-запрос через Scapy (tcp/80)."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None

    port = 80
    client_sport = random.randint(1025, 65500)

    if custom_request:
        http_request_str = custom_request
    else:
        http_request_str = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"

    syn = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags='S')
    syn_ack = sr1(syn, timeout=5, verbose=False)

    if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
        print(f"Не удалось установить TCP-соединение с {hostname}")
        return None

    client_seq = syn_ack[TCP].ack
    client_ack = syn_ack[TCP].seq + 1

    ack_packet = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='A'
    )
    send(ack_packet, verbose=False)
    time.sleep(0.05)

    http_request = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='PA'
    ) / http_request_str

    send(http_request, verbose=False)
    return dest_ip, port, client_sport


def capture_traffic(hostname: str, timeout: int = 30, output_file: str | None = None, iface: str | None = None):
    """Перехватывает HTTP-трафик (tcp/80) до указанного hostname и сохраняет в pcap."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None

    print(f"Начало перехвата HTTP-трафика для {hostname} ({dest_ip})...")
    print(f"Фильтр: tcp port 80 and host {dest_ip}")

    bpf_filter = f"tcp port 80 and host {dest_ip}"
    packets = sniff(filter=bpf_filter, timeout=timeout, iface=iface)
    print(f"Перехвачено пакетов: {len(packets)}")

    if output_file and len(packets) > 0:
        wrpcap(output_file, packets)
        print(f"Трафик сохранён: {output_file}")

    return packets


_HTTP_REQ_RE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/\d\.\d", re.I)
_HTTP_RESP_RE = re.compile(r"^HTTP/\d\.\d\s+(\d{3})\s+(.*)$", re.I)


def _split_headers_body(raw: bytes):
    sep = b"\r\n\r\n"
    idx = raw.find(sep)
    if idx == -1:
        return raw, b"""
    return raw[:idx], raw[idx + 4:]


def _parse_headers(header_bytes: bytes):
    text = header_bytes.decode('iso-8859-1', errors='replace')
    lines = text.split("\r\n")
    start_line = lines[0] if lines else ""
    headers = {}
    for ln in lines[1:]:
        if ':' in ln:
            k, v = ln.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    return start_line, headers


def _decode_chunked(body: bytes):
    """Простейший декодер Transfer-Encoding: chunked."""
    out = bytearray()
    i = 0
    while True:
        j = body.find(b"\r\n", i)
        if j == -1:
            break
        size_line = body[i:j].split(b";", 1)[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            break
        i = j + 2
        if size == 0:
            break
        out += body[i:i + size]
        i += size + 2
    return bytes(out)


def _maybe_decompress(body: bytes, headers: dict):
    enc = headers.get('content-encoding', '').lower()
    te = headers.get('transfer-encoding', '').lower()

    data = body
    if 'chunked' in te:
        data = _decode_chunked(data)

    if 'gzip' in enc:
        try:
            data = gzip.decompress(data)
        except Exception:
            try:
                with gzip.GzipFile(fileobj=BytesIO(data)) as f:
                    data = f.read()
            except Exception:
                return body
    return data


def _classify_http(start_line: str):
    if _HTTP_REQ_RE.match(start_line):
        return 'request'
    if _HTTP_RESP_RE.match(start_line):
        return 'response'
    return 'unknown'


def _extract_http_messages_from_packets(packets):
    msgs = []
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer('Raw')):
            continue

        raw = bytes(pkt['Raw'].load)
        if b'HTTP/' not in raw and not raw.startswith(b'GET ') and not raw.startswith(b'POST '):
            continue

        hdr_b, body_b = _split_headers_body(raw)
        start_line, headers = _parse_headers(hdr_b)
        kind = _classify_http(start_line)
        if kind == 'unknown':
            continue

        direction = 'client->server' if int(pkt[TCP].dport) == 80 else 'server->client'
        decoded = _maybe_decompress(body_b, headers)

        msgs.append({
            'direction': direction,
            'src': (pkt[IP].src, int(pkt[TCP].sport)),
            'dst': (pkt[IP].dst, int(pkt[TCP].dport)),
            'start_line': start_line,
            'headers': headers,
            'body_raw': body_b,
            'body_decoded': decoded,
            'kind': kind,
        })
    return msgs


DEFAULT_XSS_PATTERNS = [
    r"<\s*script\b",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
    r"document\.cookie",
    r"javascript\s*:",
    r"<\s*img\b",
    r"<\s*svg\b",
]


def _search_patterns(text: str, patterns: list[str]):
    hits = []
    for p in patterns:
        if re.search(p, text, flags=re.I):
            hits.append(p)
    return hits


def _extract_query_params_from_start_line(start_line: str):
    m = _HTTP_REQ_RE.match(start_line)
    if not m:
        return ''
    path = m.group(2)
    if '?' not in path:
        return ''
    return path.split('?', 1)[1]


def analyze_packets(packets, xss_patterns: list[str] | None = None, max_preview: int = 500):
    """Базовый анализ перехваченных пакетов + XSS scan (этап 4)."""
    if not packets:
        print('Нет пакетов для анализа')
        return

    xss_patterns = xss_patterns or DEFAULT_XSS_PATTERNS
    msgs = _extract_http_messages_from_packets(packets)

    print(f"Найдено HTTP-сообщений: {len(msgs)}")

    for i, m in enumerate(msgs[:3], 1):
        print(f"\nHTTP-сообщение {i}")
        print(f"Направление: {m['direction']}")
        print(m['start_line'])
        for hk in ['host', 'content-type', 'content-encoding', 'transfer-encoding', 'content-length']:
            if hk in m['headers']:
                print(f"{hk}: {m['headers'][hk]}")
        body_text = m['body_decoded'].decode('utf-8', errors='ignore')
        if body_text:
            print('Тело (превью):')
            print(body_text[:max_preview])

    req_with_hits = []
    resp_with_hits = []

    for m in msgs:
        body_text = m['body_decoded'].decode('utf-8', errors='ignore')
        haystack = m['start_line'] + "\n" + body_text
        hits = _search_patterns(haystack, xss_patterns)
        if hits:
            if m['kind'] == 'request':
                req_with_hits.append((m, hits))
            elif m['kind'] == 'response':
                resp_with_hits.append((m, hits))

    print(f"\nXSS-паттерны: запросов с совпадениями: {len(req_with_hits)}")
    for idx, (m, hits) in enumerate(req_with_hits[:10], 1):
        print(f"\nЗапрос с совпадениями #{idx}")
        print(m['start_line'])
        q = _extract_query_params_from_start_line(m['start_line'])
        if q:
            try:
                print('Query-параметры (url-decoded):', unquote_plus(q)[:300])
            except Exception:
                pass
        btxt = m['body_decoded'].decode('utf-8', errors='ignore')
        if btxt:
            print('Тело (превью):')
            print(btxt[:max_preview])
        print('Совпавшие паттерны:', ', '.join(hits))

    print(f"\nXSS-паттерны: ответов с совпадениями: {len(resp_with_hits)}")
    for idx, (m, hits) in enumerate(resp_with_hits[:10], 1):
        print(f"\nОтвет с совпадениями #{idx}")
        print(m['start_line'])
        ctype = m['headers'].get('content-type', '')
        if ctype:
            print('content-type:', ctype)
        btxt = m['body_decoded'].decode('utf-8', errors='ignore')
        if btxt:
            print('Тело (превью):')
            print(btxt[:max_preview])
        print('Совпавшие паттерны:', ', '.join(hits))

    reflected = []
    request_markers = []

    for (m, _) in req_with_hits:
        q = _extract_query_params_from_start_line(m['start_line'])
        if q:
            request_markers.append(unquote_plus(q))
        btxt = m['body_decoded'].decode('utf-8', errors='ignore')
        if btxt:
            request_markers.append(btxt)

    for (resp, _) in resp_with_hits:
        rtxt = resp['body_decoded'].decode('utf-8', errors='ignore')
        for marker in request_markers:
            if marker and len(marker) >= 8 and marker in rtxt:
                reflected.append((marker[:120], resp['start_line']))
                break

    print(f"\nОтражение (эвристика): найдено возможных reflected совпадений: {len(reflected)}")
    for i, (marker, resp_line) in enumerate(reflected[:10], 1):
        print(f"{i}) marker='{marker}...' в ответе: {resp_line}")


def analyze_saved_traffic(pcap_file: str):
    print(f"Анализ трафика из файла: {pcap_file}")
    packets = rdpcap(pcap_file)
    analyze_packets(packets)


def main():
    parser = argparse.ArgumentParser(
        description='DZ8: HTTP capture/analyze + XSS pattern scan (Scapy)',
        formatter_class=argparse.RawDescriptionHelpFormat,
        epilog="""
Примеры:
  python3 scapy_xss_analyzer.py --send google-gruyere.appspot.com/XXXXX
  sudo python3 scapy_xss_analyzer.py --capture google-gruyere.appspot.com --timeout 60 --output pcap/traffic.pcap
  python3 scapy_xss_analyzer.py --analyze pcap/traffic.pcap
"""
    )

    parser.add_argument('--send', metavar='URL', help='Отправить HTTP-запрос на указанный URL (tcp/80)')
    parser.add_argument('--capture', metavar='HOSTNAME', help='Перехватить HTTP-трафик для указанного хоста (tcp/80)')
    parser.add_argument('--analyze', metavar='PCAP_FILE', help='Проанализировать сохранённый трафик из .pcap')
    parser.add_argument('--timeout', type=int, default=30, help='Таймаут перехвата, сек (по умолчанию: 30)')
    parser.add_argument('--output', metavar='FILE', help='Файл для сохранения трафика (.pcap)')
    parser.add_argument('--request', metavar='HTTP_REQUEST', help='Кастомный raw HTTP-запрос для --send')
    parser.add_argument('--iface', metavar='IFACE', help='Интерфейс для sniff (eth0/wlan0). По умолчанию auto.')

    args = parser.parse_args()

    if not any([args.send, args.capture, args.analyze]):
        parser.print_help()
        return

    if args.send:
        hostname, path, scheme = parse_url(args.send)
        if not hostname:
            print('Ошибка: не удалось распарсить URL')
            return
        if scheme != 'http':
            print('Предупреждение: указан https, но скрипт отправляет только http на 80 порт.')
        print(f"Отправка HTTP-запроса на {hostname}{path}")
        result = send_http_request(hostname, path, args.request)
        print('HTTP-запрос отправлен' if result else 'Ошибка при отправке HTTP-запроса')

    if args.capture:
        packets = capture_traffic(args.capture, args.timeout, args.output, args.iface)
        if packets:
            analyze_packets(packets)

    if args.analyze:
        analyze_saved_traffic(args.analyze)


if __name__ == '__main__':
    main()
