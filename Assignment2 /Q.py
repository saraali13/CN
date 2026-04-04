import random
import re
import socket
import struct
import subprocess
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime


@dataclass
class DNSMessage:
    """Simple DNS-like protocol message header with two required 16-bit fields."""

    identification: int
    flags: int
    qname: str
    qtype: str
    answers: list[str] | None = None

    def to_bytes(self) -> bytes:
        """Serialize as: ID(16-bit) + FLAGS(16-bit) + UTF-8 payload."""
        qname_bytes = self.qname.encode("utf-8")
        qtype_bytes = self.qtype.encode("utf-8")
        payload = struct.pack("!H", len(qname_bytes)) + qname_bytes
        payload += struct.pack("!H", len(qtype_bytes)) + qtype_bytes

        answers = self.answers or []
        payload += struct.pack("!H", len(answers))
        for answer in answers:
            ans_bytes = answer.encode("utf-8")
            payload += struct.pack("!H", len(ans_bytes)) + ans_bytes

        header = struct.pack("!HH", self.identification, self.flags)
        return header + payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "DNSMessage":
        """Deserialize bytes into DNSMessage."""
        identification, flags = struct.unpack("!HH", data[:4])
        index = 4

        qname_len = struct.unpack("!H", data[index : index + 2])[0]
        index += 2
        qname = data[index : index + qname_len].decode("utf-8")
        index += qname_len

        qtype_len = struct.unpack("!H", data[index : index + 2])[0]
        index += 2
        qtype = data[index : index + qtype_len].decode("utf-8")
        index += qtype_len

        ans_count = struct.unpack("!H", data[index : index + 2])[0]
        index += 2

        answers = []
        for _ in range(ans_count):
            ans_len = struct.unpack("!H", data[index : index + 2])[0]
            index += 2
            answers.append(data[index : index + ans_len].decode("utf-8"))
            index += ans_len

        return cls(
            identification=identification,
            flags=flags,
            qname=qname,
            qtype=qtype,
            answers=answers,
        )


class DNSCache:
    """Thread-safe LRU cache with TTL and auto-flush when full."""

    def __init__(self, max_size: int = 3, ttl_seconds: int = 120):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: OrderedDict[tuple[str, str], dict] = OrderedDict()
        self.lock = threading.Lock()

    def get(self, domain: str, rtype: str):
        key = (domain.lower(), rtype.upper())
        with self.lock:
            if key not in self.cache:
                print(f"[Cache] MISS -> {key}")
                return None

            entry = self.cache[key]
            age = (datetime.now() - entry["timestamp"]).total_seconds()
            if age >= self.ttl_seconds:
                del self.cache[key]
                print(f"[Cache] EXPIRED -> {key}")
                return None

            self.cache.move_to_end(key)
            print(f"[Cache] HIT -> {key}")
            return entry["value"]

    def put(self, domain: str, rtype: str, value):
        key = (domain.lower(), rtype.upper())
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            elif len(self.cache) >= self.max_size:
                flushed_key, _ = self.cache.popitem(last=False)
                print(f"[Cache] AUTO-FLUSH -> removed oldest {flushed_key}")

            self.cache[key] = {
                "value": value,
                "timestamp": datetime.now(),
            }

    def show(self):
        with self.lock:
            print("\n-- LOCAL CACHE --")
            print(f"size={len(self.cache)}/{self.max_size}, ttl={self.ttl_seconds}s")
            if not self.cache:
                print("(empty)")
                return
            for key, entry in self.cache.items():
                age = (datetime.now() - entry["timestamp"]).total_seconds()
                print(f"{key} -> age={age:.1f}s")


class RootServer:
    """Root level DNS server simulation."""

    def __init__(self):
        self.tld_referrals = {
            "com": "TLD-.com",
            "org": "TLD-.org",
            "net": "TLD-.net",
            "edu": "TLD-.edu",
            "pk": "TLD-.pk",
        }

    def handle_query(self, msg: DNSMessage):
        print("[Root] received query")
        domain = msg.qname.lower().rstrip(".")
        tld = domain.split(".")[-1] if "." in domain else ""
        target = self.tld_referrals.get(tld)
        return target


class TLDServer:
    """Top-level DNS server simulation."""

    def __init__(self, tld: str):
        self.tld = tld

    def handle_query(self, msg: DNSMessage):
        print(f"[TLD .{self.tld}] received query")
        domain = msg.qname.lower().rstrip(".")
        if not domain.endswith(f".{self.tld}"):
            return None
        return "Authoritative"


class AuthoritativeServer:
    """Authoritative resolver using real DNS data from system tools."""

    def _run_nslookup(self, domain: str, query_type: str) -> str:
        command = ["nslookup", "-type=" + query_type, domain]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=8)
        output = (completed.stdout or "") + "\n" + (completed.stderr or "")
        return output

    def _parse_a_records(self, output: str):
        records = []
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        in_answer_block = False

        for line in lines:
            lower = line.lower()
            if lower.startswith("non-authoritative answer"):
                in_answer_block = True
                continue

            if "name:" in lower:
                in_answer_block = True
                continue

            if in_answer_block and lower.startswith("address:"):
                candidate = line.split(":", 1)[1].strip()
                if self._is_ipv4(candidate):
                    records.append(candidate)

            if in_answer_block and lower.startswith("addresses:"):
                # Sometimes nslookup prints first IP on this line and next lines as plain values.
                first = line.split(":", 1)[1].strip()
                if self._is_ipv4(first):
                    records.append(first)

        # Fallback parse for outputs that only include "Address:" lines.
        if not records:
            for line in lines:
                lower = line.lower()
                if lower.startswith("address:"):
                    candidate = line.split(":", 1)[1].strip()
                    if self._is_ipv4(candidate):
                        records.append(candidate)

        return self._dedupe(records)

    def _parse_ns_records(self, output: str):
        records = []
        for line in output.splitlines():
            line = line.strip()
            lower = line.lower()
            if "nameserver" in lower and "=" in line:
                host = line.split("=", 1)[1].strip().rstrip(".") + "."
                records.append(host)
        return self._dedupe(records)

    def _parse_mx_records(self, output: str):
        records = []
        for line in output.splitlines():
            line = line.strip()
            lower = line.lower()
            if "mail exchanger" not in lower:
                continue

            # Handles lines like:
            # google.com MX preference = 10, mail exchanger = smtp.google.com
            # or variants with extra spaces.
            match = re.search(r"preference\s*=\s*(\d+)\s*,\s*mail exchanger\s*=\s*([^\s]+)", line, re.IGNORECASE)
            if match:
                pref = match.group(1)
                host = match.group(2).rstrip(".") + "."
                records.append(f"{pref} {host}")
                continue

            if "=" in line:
                host = line.split("=")[-1].strip().rstrip(".") + "."
                records.append(host)
        return self._dedupe(records)

    @staticmethod
    def _dedupe(items):
        seen = set()
        out = []
        for item in items:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        try:
            socket.inet_aton(value)
            return value.count(".") == 3
        except OSError:
            return False

    def query_records(self, domain: str):
        # Pulling DNS data from the local resolver ensures records are real-time rather than guessed.
        a_records = []
        try:
            _canonical, _aliases, ips = socket.gethostbyname_ex(domain)
            a_records.extend(ips)
        except socket.gaierror:
            pass

        a_out = self._run_nslookup(domain, "A")
        ns_out = self._run_nslookup(domain, "NS")
        mx_out = self._run_nslookup(domain, "MX")

        a_records.extend(self._parse_a_records(a_out))

        return {
            "A": self._dedupe(a_records),
            "NS": self._parse_ns_records(ns_out),
            "MX": self._parse_mx_records(mx_out),
        }


class DNSClient:
    """Client performing recursive lookup with query/reply message simulation."""

    QUERY_FLAG = 0x0000
    REPLY_FLAG = 0x8000

    def __init__(self, root_server: RootServer):
        self.root_server = root_server
        self.cache = DNSCache(max_size=5, ttl_seconds=120)
        self.auth_server = AuthoritativeServer()

    @staticmethod
    def _new_id() -> int:
        return random.randint(0, 0xFFFF)

    def _build_query(self, domain: str, rtype: str) -> DNSMessage:
        return DNSMessage(
            identification=self._new_id(),
            flags=self.QUERY_FLAG,
            qname=domain,
            qtype=rtype,
        )

    def _build_reply(self, request_msg: DNSMessage, answers: list[str]) -> DNSMessage:
        return DNSMessage(
            identification=request_msg.identification,
            flags=self.REPLY_FLAG,
            qname=request_msg.qname,
            qtype=request_msg.qtype,
            answers=answers,
        )

    def _show_wire_message(self, msg: DNSMessage, label: str):
        raw = msg.to_bytes()
        parsed = DNSMessage.from_bytes(raw)
        print(f"\n[{label}]")
        print(
            f"ID(16-bit)={parsed.identification}, FLAGS(16-bit)=0x{parsed.flags:04X}, "
            f"QNAME={parsed.qname}, QTYPE={parsed.qtype}, ANSWER_COUNT={len(parsed.answers or [])}"
        )

    def resolve_recursive(self, domain: str):
        domain = domain.lower().rstrip(".")

        # Cache check for full DNS info bundle.
        cached = self.cache.get(domain, "ALL")
        if cached is not None:
            return cached, True

        query = self._build_query(domain, "ALL")
        self._show_wire_message(query, "CLIENT -> ROOT (QUERY)")

        tld_ref = self.root_server.handle_query(query)
        if not tld_ref:
            raise ValueError(f"Unsupported TLD for domain: {domain}")
        print(f"[Root] referral -> {tld_ref}")

        tld = domain.split(".")[-1]
        tld_server = TLDServer(tld)
        tld_ref_2 = tld_server.handle_query(query)
        if not tld_ref_2:
            raise ValueError(f"TLD server could not resolve referral for: {domain}")
        print(f"[TLD .{tld}] referral -> {tld_ref_2}")

        records = self.auth_server.query_records(domain)

        # Reply contains all A records as answer list for wire demonstration.
        reply_answers = records["A"] if records["A"] else ["NO_A_RECORD"]
        reply = self._build_reply(query, reply_answers)
        self._show_wire_message(reply, "AUTHORITATIVE -> CLIENT (REPLY)")

        self.cache.put(domain, "ALL", records)
        return records, False


class DNSApplication:
    """End-to-end assignment driver."""

    def __init__(self):
        self.client = DNSClient(RootServer())

    @staticmethod
    def _print_dns_info(domain: str, records: dict):
        a_records = records.get("A", [])
        ns_records = records.get("NS", [])
        mx_records = records.get("MX", [])

        if a_records:
            print(f"{domain}/{a_records[0]}")
        else:
            print(f"{domain}/NO_A_RECORD")

        print("-- DNS INFORMATION --")
        print("A: " + (", ".join(a_records) if a_records else "N/A"))
        print("NS: " + (", ".join(ns_records) if ns_records else "N/A"))
        print("MX: " + (", ".join(mx_records) if mx_records else "N/A"))

    def run(self):
        print("=" * 70)
        print("DNS Server Simulation (Root -> TLD -> Authoritative)")
        print("Includes 16-bit ID and 16-bit flags in query/reply message format")
        print("=" * 70)

        demo_domains = [
            "google.com",
            "facebook.com",
            "amazon.com",
            "github.com",
        ]

        print("\n[Demo 1] Recursive lookup (first pass, expected cache misses)")
        for domain in demo_domains:
            print("\n" + "-" * 70)
            start = time.perf_counter()
            records, from_cache = self.client.resolve_recursive(domain)
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._print_dns_info(domain, records)
            print(f"resolved_in={elapsed_ms:.2f}ms, source={'CACHE' if from_cache else 'NETWORK'}")

        print("\n[Demo 2] Re-query google.com to show cache benefit")
        start = time.perf_counter()
        records, from_cache = self.client.resolve_recursive("google.com")
        elapsed_ms = (time.perf_counter() - start) * 1000
        self._print_dns_info("google.com", records)
        print(f"resolved_in={elapsed_ms:.2f}ms, source={'CACHE' if from_cache else 'NETWORK'}")

        print("\n[Demo 3] Auto-flush when local cache gets full")
        # max_size=5 in client cache. Insert extra unique entries to force oldest eviction.
        self.client.resolve_recursive("yahoo.com")
        self.client.resolve_recursive("wikipedia.org")
        self.client.cache.show()


def main():
    try:
        app = DNSApplication()
        app.run()
    except subprocess.TimeoutExpired:
        print("DNS query timed out. Check network connectivity and try again.")
    except FileNotFoundError:
        print("'nslookup' command not found on this host. Install/enable DNS tools and retry.")
    except Exception as exc:
        print(f"Error: {exc}")


if __name__ == "__main__":
    main()

