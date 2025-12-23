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

    def __init__(self, print_output: bool = False):
        self.result = Result()
        self.print_output = print_output
        self.extractor = PayloadExtractor()

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

    def save(self, output_path: str):
        """Save results to files"""
        # Summary JSON
        summary = {
            'ipv4': sorted(self.result.ipv4),
            'ipv6': sorted(self.result.ipv6),
            'domains': sorted(self.result.domains),
            'stats': {
                'ipv4_count': len(self.result.ipv4),
                'ipv6_count': len(self.result.ipv6),
                'domain_count': len(self.result.domains),
                'match_count': len(self.result.matches)
            }
        }
        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"[+] Summary saved to {output_path}")

        # Detail JSONL
        jsonl_path = output_path.rsplit('.', 1)[0] + '.jsonl'
        with open(jsonl_path, 'w') as f:
            for m in self.result.matches:
                f.write(json.dumps(asdict(m)) + '\n')
        print(f"[+] Details saved to {jsonl_path}")

        # Print stats
        print(f"\n=== Stats ===")
        print(f"IPv4:    {len(self.result.ipv4)}")
        print(f"IPv6:    {len(self.result.ipv6)}")
        print(f"Domains: {len(self.result.domains)}")
        print(f"Matches: {len(self.result.matches)}")


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
        description='Extract IPs and domains from pcap payload'
    )
    parser.add_argument('-r', '--read', type=str, help='pcap file to process')
    parser.add_argument('-d', '--directory', type=str, 
                        help='directory of pcap files')
    parser.add_argument('-o', '--output', type=str, default='sieve_result.json',
                        help='output file path (default: sieve_result.json)')
    parser.add_argument('-p', '--print', action='store_true', dest='print_out',
                        help='print matches to stdout')
    args = parser.parse_args()

    if not args.read and not args.directory:
        parser.print_help()
        sys.exit(1)

    sieve = Sieve(print_output=args.print_out)

    if args.read:
        process_pcap(args.read, sieve)
    elif args.directory:
        for f in os.scandir(args.directory):
            if f.is_file() and f.name.endswith(('.pcap', '.pcapng', '.cap')):
                process_pcap(f.path, sieve)

    sieve.save(args.output)


if __name__ == '__main__':
    main()

