import enum
import socket
import struct
from pathlib import Path
from typing import Any, BinaryIO, NamedTuple

import dpkt
from pcap.errors import PcapParseError
from pcap.models import FlowKey, FlowRecord, ParsedCapture

from utils.logging_setup import get_logger

logger = get_logger(__name__)

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
SEQUENCE_SPACE = 1 << 32


class DatalinkType(enum.IntEnum):
    """DLT (datalink type) stored in the libpcap file header: it says what precedes the IP packet in each record.

    ETHERNET (1): a 14-byte Ethernet header precedes the IP packet — captures made on a physical network card.
    RAW_IP (101): the IP packet starts at byte zero — captures made on tun/VPN interfaces. The pcap file
        format always stores 101 for raw IP; 12/14 are BSD-era values that never appear in capture files.
    LINUX_SLL (113): a 16-byte Linux cooked header precedes the IP packet — captures made with `tcpdump -i any`.
    """

    ETHERNET = 1
    RAW_IP = 101
    LINUX_SLL = 113


class _Transport(NamedTuple):
    """One dissected TCP or UDP packet: its protocol, both endpoints and the dpkt transport object."""

    protocol: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    segment: Any


class _FlowAccumulator:
    """Mutable per-flow bookkeeping the parser folds into one FlowRecord: byte counters plus the TCP-only
    retransmission, zero-window and handshake state."""

    def __init__(self, flow_key: FlowKey) -> None:
        """Start with empty counters, no recorded handshake and no sent byte ranges."""
        self.flow_key = flow_key
        self.total_frame_bytes = 0
        self.payload_bytes = 0
        self.retransmission_count = 0
        self.zero_window_event_count = 0
        self.reset_count = 0
        self.handshake_rtt: float | None = None
        self._syn_timestamp: float | None = None
        self._syn_sequence: int | None = None
        self._syn_retransmitted = False
        self._sequence_base: dict[str, int] = {}
        self._sent_ranges: dict[str, list[tuple[int, int]]] = {}

    def add_tcp_segment(self, timestamp: float, segment: dpkt.tcp.TCP, frame_length: int, source_ip: str) -> None:
        """Fold one TCP segment into the flow's byte counters and TCP analysis state.

        - payload: the TCP data bytes of every segment (retransmitted copies included);
        - reset: every segment carrying the RST flag;
        - zero window: every segment advertising a zero receive window, except SYN/FIN/RST segments;
        - retransmission: a segment that consumes sequence space (payload, SYN or FIN) whose whole
          range was already seen in the same direction;
        - handshake RTT: first SYN to its matching SYN-ACK, skipped when the SYN itself was retransmitted.
        """
        self.total_frame_bytes += frame_length
        payload_length = len(segment.data)
        self.payload_bytes += payload_length

        is_syn = bool(segment.flags & dpkt.tcp.TH_SYN)
        is_fin = bool(segment.flags & dpkt.tcp.TH_FIN)
        is_rst = bool(segment.flags & dpkt.tcp.TH_RST)
        is_ack = bool(segment.flags & dpkt.tcp.TH_ACK)

        if is_rst:
            self.reset_count += 1
        if segment.win == 0 and not (is_syn or is_fin or is_rst):
            self.zero_window_event_count += 1

        self._track_handshake(timestamp, segment, is_syn, is_ack)

        sequence_length = payload_length + int(is_syn) + int(is_fin)
        if sequence_length and self._is_retransmission(source_ip, segment.seq, sequence_length):
            self.retransmission_count += 1

    def add_udp_datagram(self, datagram: dpkt.udp.UDP, frame_length: int) -> None:
        """Fold one UDP datagram into the flow's byte counters; UDP has no TCP analysis state."""
        self.total_frame_bytes += frame_length
        self.payload_bytes += len(datagram.data)

    def record(self) -> FlowRecord:
        """Freeze the bookkeeping into the flow's immutable record."""
        return FlowRecord(
            flow_key=self.flow_key,
            total_frame_bytes=self.total_frame_bytes,
            payload_bytes=self.payload_bytes,
            retransmission_count=self.retransmission_count,
            zero_window_event_count=self.zero_window_event_count,
            reset_count=self.reset_count,
            handshake_rtt=self.handshake_rtt,
        )

    def _track_handshake(self, timestamp: float, segment: dpkt.tcp.TCP, is_syn: bool, is_ack: bool) -> None:
        """Record the first SYN, then measure its RTT when the matching SYN-ACK arrives."""
        if is_syn and not is_ack:
            if self._syn_timestamp is None:
                self._syn_timestamp = timestamp
                self._syn_sequence = segment.seq
            elif segment.seq == self._syn_sequence:
                self._syn_retransmitted = True
        elif is_syn and is_ack and self.handshake_rtt is None and self._syn_timestamp is not None:
            matches_syn = segment.ack == (self._syn_sequence + 1) % SEQUENCE_SPACE
            rtt = timestamp - self._syn_timestamp
            if matches_syn and not self._syn_retransmitted and rtt >= 0:
                self.handshake_rtt = rtt

    def _is_retransmission(self, source_ip: str, sequence_number: int, length: int) -> bool:
        """True when this sequence range was already fully sent in this direction; remember it either way.

        Sequence numbers are made relative to the first one seen per direction (wrap-safe), so an
        out-of-order first arrival of a new range is not mistaken for a retransmission.
        """
        base = self._sequence_base.setdefault(source_ip, sequence_number)
        start = ((sequence_number - base + (SEQUENCE_SPACE >> 1)) % SEQUENCE_SPACE) - (SEQUENCE_SPACE >> 1)
        end = start + length
        ranges = self._sent_ranges.setdefault(source_ip, [])
        already_sent = any(range_start <= start and end <= range_end for range_start, range_end in ranges)
        _remember_range(ranges, start, end)
        return already_sent


def _remember_range(ranges: list[tuple[int, int]], start: int, end: int) -> None:
    """Add [start, end) to a list of disjoint sorted ranges, merging overlapping and adjacent ones."""
    if ranges and ranges[-1][1] == start:
        ranges[-1] = (ranges[-1][0], end)
        return
    merged: list[tuple[int, int]] = []
    for range_start, range_end in sorted([*ranges, (start, end)]):
        if merged and range_start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], range_end))
        else:
            merged.append((range_start, range_end))
    ranges[:] = merged


class PcapParser:
    """Parses pcap/pcapng captures into per-flow records using dpkt (no external tools)."""

    DISSECTION_ERRORS: tuple[type[Exception], ...] = (dpkt.UnpackError, struct.error, IndexError)
    FILE_ERRORS: tuple[type[Exception], ...] = (dpkt.UnpackError, struct.error, ValueError, EOFError)

    def parse(self, pcap_path: Path) -> ParsedCapture:
        """Dissect a capture into one record per TCP/UDP flow, plus the non-flow byte total.

        Flows are keyed by their canonical five-tuple, so both directions of a flow and both
        protocols on the same four-tuple are handled. Non-flow traffic (ARP, ICMP, ...) only
        counts its frame bytes. Individually malformed packets are skipped and counted; an
        unreadable file raises PcapParseError.
        """
        try:
            capture = self._parse(pcap_path)
        except OSError as error:
            raise PcapParseError(f"cannot read {pcap_path}: {error}") from error
        if capture.malformed_packet_count:
            logger.warning("%s: skipped %d malformed packet(s).", pcap_path.name, capture.malformed_packet_count)
        return capture

    def _parse(self, pcap_path: Path) -> ParsedCapture:
        """Read every record of one capture file and fold it into flows."""
        accumulators: dict[FlowKey, _FlowAccumulator] = {}
        other_frame_bytes = 0
        malformed_packet_count = 0

        with pcap_path.open("rb") as handle:
            try:
                reader = self._open_reader(handle)
                datalink = self._datalink_of(reader)
                for timestamp, frame in reader:
                    try:
                        transport = self._dissect(frame, datalink)
                    except self.DISSECTION_ERRORS:
                        malformed_packet_count += 1
                        continue

                    if transport is None:
                        other_frame_bytes += len(frame)
                        continue

                    flow_key = FlowKey.from_packet(
                        transport.protocol,
                        transport.source_ip,
                        transport.source_port,
                        transport.destination_ip,
                        transport.destination_port,
                    )
                    accumulator = accumulators.get(flow_key)
                    if accumulator is None:
                        accumulator = accumulators[flow_key] = _FlowAccumulator(flow_key)
                    if transport.protocol == "TCP":
                        accumulator.add_tcp_segment(timestamp, transport.segment, len(frame), transport.source_ip)
                    else:
                        accumulator.add_udp_datagram(transport.segment, len(frame))
            except PcapParseError:
                raise
            except self.FILE_ERRORS as error:
                raise PcapParseError(f"{pcap_path.name} is not a readable capture: {error}") from error

        return ParsedCapture(
            flows=tuple(accumulator.record() for accumulator in accumulators.values()),
            other_frame_bytes=other_frame_bytes,
            malformed_packet_count=malformed_packet_count,
        )

    @staticmethod
    def _open_reader(handle: BinaryIO) -> Any:
        """Pick the pcapng or classic pcap reader from the file's first four bytes."""
        magic = handle.read(4)
        handle.seek(0)
        if magic == PCAPNG_MAGIC:
            return dpkt.pcapng.Reader(handle)
        return dpkt.pcap.Reader(handle)

    @staticmethod
    def _datalink_of(reader: Any) -> DatalinkType:
        """The capture's datalink type, or PcapParseError when this parser cannot dissect it."""
        raw_datalink = reader.datalink()
        try:
            return DatalinkType(raw_datalink)
        except ValueError as error:
            raise PcapParseError(f"unsupported datalink type {raw_datalink}") from error

    def _dissect(self, frame: bytes, datalink: DatalinkType) -> _Transport | None:
        """Dissect one frame into a TCP/UDP packet, or None for traffic that is not part of a flow."""
        network = self._network_layer(frame, datalink)

        if isinstance(network, dpkt.ip.IP):
            if self._is_fragment(network):
                return None
            source_ip, destination_ip = socket.inet_ntoa(network.src), socket.inet_ntoa(network.dst)
        elif isinstance(network, dpkt.ip6.IP6):
            source_ip = socket.inet_ntop(socket.AF_INET6, network.src)
            destination_ip = socket.inet_ntop(socket.AF_INET6, network.dst)
        else:
            return None

        if network.p == dpkt.ip.IP_PROTO_TCP:
            protocol, expected_type = "TCP", dpkt.tcp.TCP
        elif network.p == dpkt.ip.IP_PROTO_UDP:
            protocol, expected_type = "UDP", dpkt.udp.UDP
        else:
            return None

        if not isinstance(network.data, expected_type):
            raise dpkt.UnpackError(f"truncated {protocol} header")
        segment = network.data
        return _Transport(protocol, source_ip, segment.sport, destination_ip, segment.dport, segment)

    @staticmethod
    def _is_fragment(packet: dpkt.ip.IP) -> bool:
        """True for IPv4 fragments: they carry no complete transport header, so they are not flow traffic."""
        try:
            return bool(packet.mf or packet.offset)
        except AttributeError:  # older dpkt versions only expose the combined flags/offset field
            return bool(packet.off & (dpkt.ip.IP_MF | dpkt.ip.IP_OFFMASK))

    @staticmethod
    def _network_layer(frame: bytes, datalink: DatalinkType) -> Any:
        """Strip the link-layer header and return the dpkt network-layer object (IP, IP6, ARP, bytes, ...)."""
        if datalink is DatalinkType.ETHERNET:
            return dpkt.ethernet.Ethernet(frame).data
        if datalink is DatalinkType.RAW_IP:
            version = frame[0] >> 4
            if version == 4:
                return dpkt.ip.IP(frame)
            if version == 6:
                return dpkt.ip6.IP6(frame)
            return None
        return dpkt.sll.SLL(frame).data