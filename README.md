"""Захват HTTP/1.x в PCAP и автономный анализ трафика учебного Gruyere."""

from __future__ import annotations

import argparse
import gzip
import io
import ipaddress
import json
import math
import sys
import zlib
from collections import defaultdict, deque
from email.parser import BytesHeaderParser
from functools import lru_cache
from pathlib import Path
from typing import TextIO
from urllib.parse import parse_qs

MAX_BODY_BYTES = 8 * 1024 * 1024
Flow = tuple[str, int, str, int]


@lru_cache(maxsize=1)
def load_scapy():
    """Не инициализировать сетевые интерфейсы для обычного --help."""
    try:
        import scapy.all as scapy
        from scapy.layers import http
        from scapy.sessions import TCPSession
    except ImportError as error:
        raise RuntimeError(
            "Установите зависимости: python -m pip install -r requirements.txt"
        ) from error
    return scapy, http, TCPSession


@lru_cache(maxsize=1)
def stream_http_layer():
    _, http, _ = load_scapy()

    class CompleteHeaderHTTP(http.HTTP):
        @classmethod
        def tcp_reassemble(cls, data, metadata, session):
            # Длинная строка GET может не поместиться в первый TCP-сегмент.
            # Не позволяем HTTP-диссектору принять неполный заголовок за Raw.
            if b"\r\n\r\n" not in data:
                return None
            return super().tcp_reassemble(data, metadata, session)

    return CompleteHeaderHTTP


def as_text(value: bytes | str | None) -> str:
    if isinstance(value, bytes):
        return value.decode("iso-8859-1", errors="replace")
    return value or ""


def unchunk(data: bytes) -> bytes:
    """Снять HTTP chunked-разметку, включая расширения размеров и trailers."""
    result = bytearray()
    offset = 0
    while True:
        line_end = data.find(b"\r\n", offset)
        if line_end < 0:
            raise ValueError("Не получена строка размера HTTP-чанка")
        size_line = data[offset:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError as error:
            raise ValueError("Некорректный размер HTTP-чанка") from error
        if size < 0:
            raise ValueError("Отрицательный размер HTTP-чанка")
        offset = line_end + 2
        if size == 0:
            tail = data[offset:]
            if not tail.startswith(b"\r\n") and b"\r\n\r\n" not in tail:
                raise ValueError("Не получен конец chunked-тела")
            return bytes(result)
        if len(result) + size > MAX_BODY_BYTES:
            raise ValueError("Тело после dechunking превышает лимит 8 МиБ")
        end = offset + size
        if end + 2 > len(data) or data[end : end + 2] != b"\r\n":
            raise ValueError("HTTP-чанк получен не полностью")
        result.extend(data[offset:end])
        offset = end + 2


def inflate(data: bytes, window_bits: int) -> bytes:
    decoder = zlib.decompressobj(window_bits)
    result = decoder.decompress(data, MAX_BODY_BYTES + 1)
    if len(result) > MAX_BODY_BYTES or decoder.unconsumed_tail:
        raise ValueError("Распакованное тело превышает лимит 8 МиБ")
    if not decoder.eof:
        raise ValueError("Сжатое тело получено не полностью")
    return result


def decode_codings(body: bytes, header: str) -> bytes:
    """Снимать кодировки в обратном порядке их применения."""
    for coding in reversed(header.lower().split(",")):
        coding = coding.strip()
        if coding in ("", "identity"):
            continue
        if coding == "chunked":
            body = unchunk(body)
        elif coding in ("gzip", "x-gzip"):
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                body = stream.read(MAX_BODY_BYTES + 1)
        elif coding == "deflate":
            try:
                body = inflate(body, zlib.MAX_WBITS)
            except zlib.error:
                body = inflate(body, -zlib.MAX_WBITS)
        else:
            raise ValueError(f"Не поддерживается кодировка HTTP-тела: {coding}")
        if len(body) > MAX_BODY_BYTES:
            raise ValueError("Распакованное тело превышает лимит 8 МиБ")
    return body


def decode_body(message) -> tuple[bytes, str]:
    """Восстановить тело: Transfer-Encoding -> Content-Encoding -> charset."""
    original = message.original or bytes(message)
    raw_headers = original.partition(b"\r\n")[2].split(b"\r\n\r\n", 1)[0]
    headers = BytesHeaderParser().parsebytes(raw_headers)
    # Автоматическое преобразование HTTP в Scapy отключено: здесь wire-байты.
    body = bytes(message.payload)
    if not body:
        return b"", ""
    body = decode_codings(body, headers.get("Transfer-Encoding", ""))
    body = decode_codings(body, headers.get("Content-Encoding", ""))
    if len(body) > MAX_BODY_BYTES:
        raise ValueError("HTTP-тело превышает лимит отображения 8 МиБ")
    charset = headers.get_content_charset() or "utf-8"
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    return body, text


class HTTPAnalyzer:
    """Вывод сообщений HTTP/1.x и сопоставление ответов с запросами."""

    def __init__(
        self,
        port: int = 8008,
        limit: int = 12000,
        host: str | None = None,
        output: TextIO | None = None,
    ) -> None:
        self.scapy, self.http, _ = load_scapy()
        self.port = port
        self.limit = limit
        self.host = host
        self.output = output if output is not None else sys.stdout
        self.number = 0
        self.errors = 0
        self.pending: defaultdict[Flow, deque[tuple[str, str]]] = defaultdict(deque)

    def write(self, text: str = "") -> None:
        print(text, file=self.output)

    def print_parameters(self, label: str, data: str) -> None:
        try:
            parameters = parse_qs(data, keep_blank_values=True, max_num_fields=1000)
            self.write(f"{label}: {json.dumps(parameters, ensure_ascii=False)}")
        except ValueError as error:
            self.write(f"{label}: {error}")

    def __call__(self, packet) -> None:
        scapy, http = self.scapy, self.http
        if scapy.TCP not in packet:
            return
        tcp = packet[scapy.TCP]
        if self.port not in (tcp.sport, tcp.dport):
            return
        network = packet.getlayer(scapy.IP) or packet.getlayer(scapy.IPv6)
        if network is None:
            return
        if self.host and self.host not in (network.src, network.dst):
            return
        flow = (network.src, tcp.sport, network.dst, tcp.dport)
        reverse_flow = (network.dst, tcp.dport, network.src, tcp.sport)
        # Новый SYN на повторно использованном порту начинает новое соединение.
        if int(tcp.flags) & 0x02 and not int(tcp.flags) & 0x10:
            self.pending.pop(flow, None)
            self.pending.pop(reverse_flow, None)
        if http.HTTPRequest not in packet and http.HTTPResponse not in packet:
            return

        self.number += 1
        self.write(f"\n{'=' * 70}\nHTTP-сообщение №{self.number}")
        self.write(f"{network.src}:{tcp.sport} -> {network.dst}:{tcp.dport}")
        is_request = http.HTTPRequest in packet
        if is_request:
            message = packet[http.HTTPRequest]
            method = as_text(message.Method)
            target = as_text(message.Path)
            host = as_text(message.Host) or f"{network.dst}:{tcp.dport}"
            url = (
                target
                if target.startswith(("http://", "https://"))
                else f"http://{host}{target}"
            )
            self.pending[flow].append((method, url))
            self.write(f"Метод: {method}\nURL: {url}")
            self.print_parameters("Параметры URL", target.partition("?")[2])
        else:
            message = packet[http.HTTPResponse]
            status = as_text(message.Status_Code)
            self.write(f"Ответ: {status} {as_text(message.Reason_Phrase)}")
            queue = self.pending.get(reverse_flow)
            if queue:
                method, url = queue[0]
                self.write(f"На запрос: {method} {url}")
                if not status.startswith("1") or status == "101":
                    queue.popleft()
                    if not queue:
                        del self.pending[reverse_flow]

        original = message.original or bytes(message)
        headers = original.split(b"\r\n\r\n", 1)[0]
        self.write("\nСтартовая строка и заголовки:\n" + as_text(headers))
        try:
            body, text = decode_body(message)
        except (OSError, EOFError, ValueError, zlib.error) as error:
            self.errors += 1
            self.write(f"\nНе удалось декодировать тело: {error}")
            self.write(f"Начало исходного тела: {bytes(message.payload)[:128]!r}")
            return

        self.write(f"\nТело после декодирования: {len(body)} байт")
        if not body:
            self.write("<пусто>")
            return
        content_type = as_text(message.Content_Type).lower()
        if is_request and "application/x-www-form-urlencoded" in content_type:
            self.print_parameters("Параметры формы", text)
        if content_type.startswith(("image/", "audio/", "video/")):
            self.write(f"Бинарное тело, первые 128 байт: {body[:128].hex(' ')}")
            return
        self.write(text[: self.limit] if self.limit else text)
        if self.limit and len(text) > self.limit:
            self.write("[Вывод сокращён; --limit 0 выводит текст целиком]")


def configure_http(port: int) -> None:
    scapy, http, _ = load_scapy()
    layer = stream_http_layer()
    for previous in (http.HTTP, layer):
        scapy.split_layers(scapy.TCP, previous, dport=port)
        scapy.split_layers(scapy.TCP, previous, sport=port)
    scapy.bind_layers(scapy.TCP, layer, dport=port)
    scapy.bind_layers(scapy.TCP, layer, sport=port)
    # Сохраняем исходные байты; декодирование явно выполняет decode_body().
    scapy.conf.contribs["http"]["auto_compression"] = False
    scapy.conf.contribs["http"]["auto_chunk"] = False


def analyze(
    path: Path,
    port: int = 8008,
    limit: int = 12000,
    host: str | None = None,
    output: TextIO | None = None,
) -> int:
    if not path.is_file():
        raise FileNotFoundError(f"PCAP не найден: {path}")
    configure_http(port)
    scapy, _, session = load_scapy()
    analyzer = HTTPAnalyzer(port, limit, host, output)
    scapy.sniff(offline=str(path), session=session, prn=analyzer, store=False)
    analyzer.write(f"\nРазобрано HTTP-сообщений: {analyzer.number}")
    analyzer.write(f"Ошибок декодирования тела: {analyzer.errors}")
    if not analyzer.number:
        analyzer.write("Проверьте порт, интерфейс, полноту захвата и HTTP/HTTPS.")
    return analyzer.number


def capture(args: argparse.Namespace) -> int:
    configure_http(args.port)
    scapy, _, _ = load_scapy()
    interface = scapy.conf.loopback_name if args.iface == "loopback" else args.iface
    bpf = f"tcp port {args.port}"
    if args.host:
        bpf += f" and host {args.host}"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    stream = args.out.open("wb" if args.overwrite else "xb")
    writer = scapy.PcapWriter(stream, append=False, sync=True)
    count = 0

    def save(packet) -> None:
        nonlocal count
        writer.write(packet)
        count += 1

    print(f"Интерфейс: {interface}\nФильтр: {bpf}")
    print(f"PCAP: {args.out.resolve()}")
    print("Работайте с HTTP-стендом в браузере. Ctrl+C завершает запись.")
    try:
        scapy.sniff(
            iface=interface,
            filter=bpf,
            prn=save,
            store=False,
            timeout=args.seconds or None,
        )
    except KeyboardInterrupt:
        pass
    finally:
        writer.close()
        stream.close()
    print(f"Сохранено пакетов: {count}")
    return count


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interfaces", action="store_true", help="Список интерфейсов")
    parser.add_argument(
        "--iface",
        default="loopback",
        help="loopback (по умолчанию), lo, eth0 или Npcap",
    )
    parser.add_argument("--port", type=int, default=8008, help="HTTP-порт стенда")
    parser.add_argument("--host", type=ipaddress.ip_address, help="IP сервера")
    parser.add_argument("--out", type=Path, default=Path("captures/gruyere.pcap"))
    parser.add_argument("--read", type=Path, help="Разобрать готовый PCAP без захвата")
    parser.add_argument("--report", type=Path, help="Сохранить разбор в UTF-8")
    parser.add_argument("--seconds", type=float, default=0, help="0 = до Ctrl+C")
    parser.add_argument(
        "--limit", type=int, default=12000, help="Символов тела; 0 = все"
    )
    parser.add_argument(
        "--overwrite", action="store_true", help="Разрешить замену выходных файлов"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Порт должен быть от 1 до 65535")
    if args.seconds < 0 or not math.isfinite(args.seconds) or args.limit < 0:
        parser.error("seconds и limit должны быть неотрицательными конечными числами")
    source = args.read if args.read else args.out
    if args.report and args.report.resolve() == source.resolve():
        parser.error("PCAP и текстовый отчёт должны иметь разные пути")
    if args.read and not args.read.is_file():
        parser.error(f"PCAP не найден: {args.read}")

    report = None
    try:
        if args.interfaces:
            scapy, _, _ = load_scapy()
            scapy.show_interfaces()
            return 0
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            report = args.report.open("w" if args.overwrite else "x", encoding="utf-8")
        if args.read or capture(args):
            analyze(
                source,
                args.port,
                args.limit,
                str(args.host) if args.host else None,
                report,
            )
        else:
            print("Пакеты не получены. Проверьте HTTP-порт и выбранный интерфейс.")
        if report:
            print(f"Текстовый разбор: {args.report.resolve()}")
        return 0
    except FileExistsError as error:
        print(f"Файл уже существует: {error.filename}", file=sys.stderr)
        print("Укажите другое имя или добавьте --overwrite.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        # На границе CLI сообщаем и об ошибках драйвера/Scapy без потери PCAP.
        print(f"Ошибка: {error}", file=sys.stderr)
        print(
            "Для захвата проверьте права, Npcap (Windows) или libpcap (Linux). "
            "HTTPS этот инструмент не расшифровывает.",
            file=sys.stderr,
        )
        return 1
    finally:
        if report:
            report.close()


if __name__ == "__main__":
    raise SystemExit(main())
