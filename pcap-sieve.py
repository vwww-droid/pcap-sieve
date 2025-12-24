#!/usr/bin/env python3
"""
pcap-sieve: Extract IPs and domains from pcap payload.
Designed for r0capture decrypted traffic.
"""

import argparse
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Set, List, Optional

import pyshark

# Regex patterns
# IPv4: standard dotted decimal, will validate later
IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# IPv6: simplified, use ipaddress module to validate
IPV6_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'  # full
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'  # trailing ::
    r'\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|'  # leading ::
    r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|'  # :: in middle
    r'\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|'
    r'\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|'
    r'\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b|'
    r'\b::1\b|::'
)

# Domain: label.label.tld format, includes internal hostnames
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' 
    r'[a-zA-Z]{2,}\b'
)


@dataclass
class Match:
    """Single match record"""
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    protocol: str
    match_type: str  # 'ipv4', 'ipv6', 'domain'
    value: str
    field_name: str  # which field it was found in


@dataclass
class Result:
    """Aggregated result"""
    ipv4: Set[str] = field(default_factory=set)
    ipv6: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    sensitive: dict = field(default_factory=lambda: defaultdict(set))
    matches: List[Match] = field(default_factory=list)


class PayloadExtractor:
    """Extract payload from various protocol layers"""

    # Fields to check for payload, ordered by priority
    PAYLOAD_FIELDS = [
        # HTTP
        ('http', 'file_data'),
        ('http', 'request_uri'),
        ('http', 'host'),
        ('http', 'user_agent'),
        ('http', 'referer'),
        ('http', 'cookie'),
        ('http', 'set_cookie'),
        ('http', 'location'),
        ('http', 'request_line'),
        ('http', 'response_line'),
        # WebSocket
        ('websocket', 'payload'),
        ('websocket', 'text'),
        # FTP
        ('ftp', 'request_arg'),
        ('ftp', 'response_arg'),
        ('ftp', 'request_command'),
        # XMPP (jabber)
        ('xmpp', 'attribute_value'),
        ('jabber', 'attribute_value'),
        # IMAP
        ('imap', 'request'),
        ('imap', 'response'),
        # SMTP
        ('smtp', 'req_parameter'),
        ('smtp', 'data_fragment'),
        ('smtp', 'command_line'),
        ('smtp', 'response'),
        # DNS (for domain extraction)
        ('dns', 'qry_name'),
        ('dns', 'resp_name'),
        # Generic data
        ('data', 'data'),
        ('data_text_lines', 'text'),
    ]

    @staticmethod
    def get_payload_from_packet(packet) -> List[tuple]:
        """
        Extract all available payload fields from packet.
        Returns list of (field_name, content) tuples.
        """
        payloads = []

        for layer_name, field_name in PayloadExtractor.PAYLOAD_FIELDS:
            try:
                if not hasattr(packet, layer_name):
                    continue
                layer = getattr(packet, layer_name)
                if not hasattr(layer, 'field_names'):
                    continue
                if field_name not in layer.field_names:
                    continue

                value = getattr(layer, field_name)
                if value:
                    # Handle hex-encoded data
                    content = PayloadExtractor._decode_value(value)
                    if content:
                        payloads.append((f"{layer_name}.{field_name}", content))
            except Exception:
                continue

        # Fallback: try raw tcp/udp payload
        for transport in ['tcp', 'udp']:
            try:
                if hasattr(packet, transport):
                    layer = getattr(packet, transport)
                    if hasattr(layer, 'payload'):
                        raw = layer.payload
                        content = PayloadExtractor._decode_value(raw)
                        if content:
                            payloads.append((f"{transport}.payload", content))
            except Exception:
                continue

        return payloads

    @staticmethod
    def _decode_value(value) -> Optional[str]:
        """Decode hex or return as-is"""
        if not value:
            return None

        # If it's a pyshark field with raw_value
        if hasattr(value, 'raw_value'):
            try:
                hex_str = value.raw_value.replace(':', '')
                return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
            except Exception:
                pass

        # If it's a hex string (colon-separated)
        if isinstance(value, str) and re.match(r'^[0-9a-fA-F:]+$', value):
            try:
                hex_str = value.replace(':', '')
                if len(hex_str) % 2 == 0:
                    return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
            except Exception:
                pass

        # Return as string
        return str(value)


class Sieve:
    """Main extractor class"""

    def __init__(self, print_output: bool = False, regex_file: str = 'regexes.json'):
        self.result = Result()
        self.print_output = print_output
        self.extractor = PayloadExtractor()
        self.custom_regexes = self._load_regexes(regex_file)

    def _load_regexes(self, filepath: str) -> dict:
        """Load custom regex patterns from JSON file"""
        if not os.path.exists(filepath):
            if self.print_output:
                print(f"[!] Regex file not found: {filepath}", file=sys.stderr)
            return {}
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                raw_patterns = json.load(f)
            
            compiled = {}
            for name, pattern in raw_patterns.items():
                try:
                    if isinstance(pattern, list):
                        compiled[name] = [re.compile(p, re.IGNORECASE) for p in pattern]
                    else:
                        compiled[name] = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    if self.print_output:
                        print(f"[!] Invalid regex for {name}: {e}", file=sys.stderr)
            
            return compiled
        except Exception as e:
            if self.print_output:
                print(f"[!] Error loading regexes: {e}", file=sys.stderr)
            return {}

    def process_packet(self, packet):
        """Process single packet"""
        try:
            # Get packet metadata
            timestamp = packet.sniff_time.isoformat()
            src_ip = self._get_ip(packet, 'src')
            dst_ip = self._get_ip(packet, 'dst')
            src_port = self._get_port(packet, 'srcport')
            dst_port = self._get_port(packet, 'dstport')
            protocol = packet.highest_layer

            # Add remote dst IP to results (server IP)
            if dst_ip and self._is_remote_ip(dst_ip):
                self._add_ip_to_result(dst_ip, timestamp, src_ip, dst_ip,
                                       src_port, dst_port, protocol, 'packet.dst')

            # Extract remote domain from DNS/HTTP
            self._extract_remote_domain(packet, timestamp, src_ip, dst_ip,
                                       src_port, dst_port, protocol)

            # Extract payloads
            payloads = self.extractor.get_payload_from_packet(packet)

            for field_name, content in payloads:
                self._extract_matches(
                    content, timestamp, src_ip, dst_ip,
                    src_port, dst_port, protocol, field_name
                )

        except Exception as e:
            if self.print_output:
                print(f"[!] Error processing packet: {e}", file=sys.stderr)

    def _get_ip(self, packet, direction: str) -> str:
        """Get source or destination IP"""
        if hasattr(packet, 'ipv6'):
            return getattr(packet.ipv6, direction, '')
        if hasattr(packet, 'ip'):
            return getattr(packet.ip, direction, '')
        return ''

    def _get_port(self, packet, attr: str) -> str:
        """Get source or destination port"""
        for transport in ['tcp', 'udp']:
            if hasattr(packet, transport):
                layer = getattr(packet, transport)
                if hasattr(layer, attr):
                    return getattr(layer, attr)
        return ''

    def _clean_match_value(self, value: str) -> str:
        """Clean and normalize matched value"""
        # Strip whitespace
        value = value.strip()
        # Remove surrounding quotes
        if len(value) >= 2 and value[0] in ('"', "'") and value[-1] in ('"', "'"):
            value = value[1:-1]
        return value

    def _is_valid_match(self, value: str) -> bool:
        """Check if matched value is valid (not binary garbage)"""
        if not value or len(value) < 3:
            return False
        
        # Count control characters
        control_count = 0
        for char in value:
            code = ord(char)
            # Control chars: 0-31 (except tab/newline/cr) and 127 (DEL)
            if (code < 32 and char not in ('\t', '\n', '\r')) or code == 127:
                control_count += 1
        
        # Reject if ANY control characters found (too strict for binary data)
        if control_count > 0:
            return False
        
        return True

    def _extract_remote_domain(self, packet, timestamp: str, src_ip: str,
                               dst_ip: str, src_port: str, dst_port: str,
                               protocol: str):
        """Extract domain from DNS query or HTTP Host"""
        try:
            # DNS query
            if hasattr(packet, 'dns'):
                dns_layer = packet.dns
                if hasattr(dns_layer, 'qry_name'):
                    domain = str(dns_layer.qry_name).lower().rstrip('.')
                    if domain and self._is_valid_domain(domain):
                        self.result.domains.add(domain)
                        m = Match(timestamp, src_ip, dst_ip, src_port, dst_port,
                                  protocol, 'domain', domain, 'dns.qry_name')
                        self.result.matches.append(m)
                        if self.print_output:
                            print(f"[Domain] {domain} <- dns.qry_name")
            
            # HTTP Host
            if hasattr(packet, 'http'):
                http_layer = packet.http
                if hasattr(http_layer, 'host'):
                    host = str(http_layer.host).lower().rstrip('.')
                    if host and self._is_valid_domain(host):
                        self.result.domains.add(host)
                        m = Match(timestamp, src_ip, dst_ip, src_port, dst_port,
                                  protocol, 'domain', host, 'http.host')
                        self.result.matches.append(m)
                        if self.print_output:
                            print(f"[Domain] {host} <- http.host")
        except Exception:
            pass

    def _extract_matches(self, content: str, timestamp: str, src_ip: str,
                         dst_ip: str, src_port: str, dst_port: str,
                         protocol: str, field_name: str):
        """Extract IPs and domains from content"""
        # IPv4
        for match in IPV4_PATTERN.finditer(content):
            ip = match.group()
            if self._is_valid_ipv4(ip):
                self.result.ipv4.add(ip)
                m = Match(timestamp, src_ip, dst_ip, src_port, dst_port,
                          protocol, 'ipv4', ip, field_name)
                self.result.matches.append(m)
                if self.print_output:
                    print(f"[IPv4] {ip} <- {field_name}")

        # IPv6
        for match in IPV6_PATTERN.finditer(content):
            ip = match.group()
            if self._is_valid_ipv6(ip):
                self.result.ipv6.add(ip)
                m = Match(timestamp, src_ip, dst_ip, src_port, dst_port,
                          protocol, 'ipv6', ip, field_name)
                self.result.matches.append(m)
                if self.print_output:
                    print(f"[IPv6] {ip} <- {field_name}")

        # Domain
        for match in DOMAIN_PATTERN.finditer(content):
            domain = match.group().lower().rstrip('.')
            if self._is_valid_domain(domain):
                self.result.domains.add(domain)
                m = Match(timestamp, src_ip, dst_ip, src_port, dst_port,
                          protocol, 'domain', domain, field_name)
                self.result.matches.append(m)
                if self.print_output:
                    print(f"[Domain] {domain} <- {field_name}")

        # Custom regex patterns
        for pattern_name, pattern in self.custom_regexes.items():
            if isinstance(pattern, list):
                for p in pattern:
                    for match in p.finditer(content):
                        # Use group(1) if available (captures without quotes), else group()
                        try:
                            value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group()
                        except IndexError:
                            value = match.group()
                        
                        value = self._clean_match_value(value)
                        if value and self._is_valid_match(value):
                            self.result.sensitive[pattern_name].add(value)
                            m = Match(timestamp, src_ip, dst_ip, src_port, dst_port,
                                      protocol, pattern_name, value, field_name)
                            self.result.matches.append(m)
                            if self.print_output:
                                print(f"[{pattern_name}] {value} <- {field_name}")
            else:
                for match in pattern.finditer(content):
                    try:
                        value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group()
                    except IndexError:
                        value = match.group()
                    
                    value = self._clean_match_value(value)
                    if value and self._is_valid_match(value):
                        self.result.sensitive[pattern_name].add(value)
                        m = Match(timestamp, src_ip, dst_ip, src_port, dst_port,
                                  protocol, pattern_name, value, field_name)
                        self.result.matches.append(m)
                        if self.print_output:
                            print(f"[{pattern_name}] {value} <- {field_name}")

    def _is_valid_ipv4(self, ip: str) -> bool:
        """Validate IPv4 address"""
        try:
            addr = ipaddress.IPv4Address(ip)
            # Skip special addresses
            if addr.is_unspecified or addr.is_loopback:
                return False
            return True
        except Exception:
            return False

    def _is_valid_ipv6(self, ip: str) -> bool:
        """Validate IPv6 address"""
        try:
            # Skip if too short (likely false positive like "1::" or "d::")
            if len(ip) < 5:
                return False
            
            addr = ipaddress.IPv6Address(ip)
            if addr.is_unspecified or addr.is_loopback:
                return False
            
            # Skip link-local and multicast (usually not interesting)
            if addr.is_link_local or addr.is_multicast:
                return False
            
            return True
        except Exception:
            return False

    def _is_valid_domain(self, domain: str) -> bool:
        """Basic domain validation"""
        # Skip common file extensions
        if re.match(r'^[^.]+\.(png|jpg|jpeg|gif|webp|css|js|html|ico|svg|woff|ttf|'
                    r'xml|json|apk|so|zip|rar|pdf|doc|xls|ppt|mp4|mp3|avi|mov)$', 
                    domain, re.I):
            return False
        
        # Skip UUID-like patterns (8-4-4-4-12 hex format)
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\..+$',
                    domain, re.I):
            return False
        
        # Skip pure hex strings with extensions
        if re.match(r'^[0-9a-f]{16,}\..+$', domain, re.I):
            return False
        
        # Skip version numbers
        if re.match(r'^[\d.]+$', domain):
            return False
        
        # Minimum 2 labels
        if domain.count('.') < 1:
            return False
        
        # Check each label
        labels = domain.split('.')
        for label in labels:
            # Label too short (single char)
            if len(label) < 2:
                return False
            # Label too long (>63 chars per DNS spec)
            if len(label) > 63:
                return False
        
        # TLD (last label) should be at least 2 chars and alpha
        tld = labels[-1]
        if len(tld) < 2 or not tld.isalpha():
            return False
        
        # Skip if looks like random gibberish (too many consonants)
        # This is heuristic: if >80% consonants in non-TLD labels, likely random
        for label in labels[:-1]:
            consonants = sum(1 for c in label.lower() 
                           if c in 'bcdfghjklmnpqrstvwxyz')
            if len(label) > 3 and consonants / len(label) > 0.8:
                return False
        
        return True

    def _is_remote_ip(self, ip: str) -> bool:
        """Check if IP is remote (not local/private)"""
        try:
            addr = ipaddress.ip_address(ip)
            # Skip private, loopback, link-local, multicast
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return False
            if addr.is_multicast or addr.is_unspecified:
                return False
            return True
        except Exception:
            return False

    def _add_ip_to_result(self, ip: str, timestamp: str, src_ip: str,
                          dst_ip: str, src_port: str, dst_port: str,
                          protocol: str, field_name: str):
        """Add IP to result set based on its type"""
        try:
            addr = ipaddress.ip_address(ip)
            if isinstance(addr, ipaddress.IPv4Address):
                self.result.ipv4.add(ip)
                m = Match(timestamp, src_ip, dst_ip, src_port, dst_port,
                          protocol, 'ipv4', ip, field_name)
                self.result.matches.append(m)
                if self.print_output:
                    print(f"[IPv4] {ip} <- {field_name}")
            else:  # IPv6
                self.result.ipv6.add(ip)
                m = Match(timestamp, src_ip, dst_ip, src_port, dst_port,
                          protocol, 'ipv6', ip, field_name)
                self.result.matches.append(m)
                if self.print_output:
                    print(f"[IPv6] {ip} <- {field_name}")
        except Exception:
            pass

    def save(self, output_path: str):
        """Save results to files"""
        # Convert sensitive data to sorted lists
        sensitive_data = {}
        for pattern_name, values in self.result.sensitive.items():
            sensitive_data[pattern_name] = sorted(values)
        
        # Summary JSON
        summary = {
            'ipv4': sorted(self.result.ipv4),
            'ipv6': sorted(self.result.ipv6),
            'domains': sorted(self.result.domains),
            **sensitive_data,
            'stats': {
                'ipv4_count': len(self.result.ipv4),
                'ipv6_count': len(self.result.ipv6),
                'domain_count': len(self.result.domains),
                'sensitive_patterns': len(self.result.sensitive),
                'match_count': len(self.result.matches)
            }
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        print(f"[+] Summary saved to {output_path}")

        # Detail JSONL
        jsonl_path = output_path.rsplit('.', 1)[0] + '.jsonl'
        with open(jsonl_path, 'w', encoding='utf-8') as f:
            for m in self.result.matches:
                f.write(json.dumps(asdict(m), ensure_ascii=False) + '\n')
        print(f"[+] Details saved to {jsonl_path}")

        # Print stats
        print(f"\n=== Stats ===")
        print(f"IPv4:    {len(self.result.ipv4)}")
        print(f"IPv6:    {len(self.result.ipv6)}")
        print(f"Domains: {len(self.result.domains)}")
        for pattern_name, values in sorted(self.result.sensitive.items()):
            if values:
                print(f"{pattern_name}: {len(values)}")
        print(f"Total Matches: {len(self.result.matches)}")


def process_pcap(filepath: str, sieve: Sieve):
    """Process single pcap file"""
    print(f"[*] Processing: {filepath}")
    try:
        cap = pyshark.FileCapture(filepath, keep_packets=False)
        for packet in cap:
            sieve.process_packet(packet)
        cap.close()
    except Exception as e:
        print(f"[!] Error processing {filepath}: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='Extract IPs, domains and sensitive data from pcap payload'
    )
    parser.add_argument('-r', '--read', type=str, help='pcap file to process')
    parser.add_argument('-d', '--directory', type=str, 
                        help='directory of pcap files')
    parser.add_argument('-o', '--output', type=str, default='sieve_result.json',
                        help='output file path (default: sieve_result.json)')
    parser.add_argument('-p', '--print', action='store_true', dest='print_out',
                        help='print matches to stdout')
    parser.add_argument('--regex', type=str, default='regexes.json',
                        help='custom regex patterns file (default: regexes.json)')
    args = parser.parse_args()

    if not args.read and not args.directory:
        parser.print_help()
        sys.exit(1)

    sieve = Sieve(print_output=args.print_out, regex_file=args.regex)

    if args.read:
        process_pcap(args.read, sieve)
    elif args.directory:
        for f in os.scandir(args.directory):
            if f.is_file() and f.name.endswith(('.pcap', '.pcapng', '.cap')):
                process_pcap(f.path, sieve)

    sieve.save(args.output)


if __name__ == '__main__':
    main()

