import dpkt
import pytest
from pcap.errors import PcapParseError
from pcap.parser import PcapParser

from tests.builders import (
    CLIENT_IP,
    CLIENT_PORT,
    SERVER_IP,
    SERVER_PORT,
    arp_packet,
    handshake_packets,
    malformed_packet_bytes,
    pcapng_enhanced_packet_block,
    pcapng_interface_description_block,
    pcapng_section_header_block,
    tcp_packet,
    truncated_record_pcap_bytes,
    udp_packet,
    write_pcap,
)

RAW_IP_LINKTYPE = 101  # the value libpcap files store for raw IP (dpkt.pcap.DLT_RAW is the BSD value 12)
ACK = dpkt.tcp.TH_ACK
SYN = dpkt.tcp.TH_SYN


def _data(sequence_number: int, payload: bytes = b"x" * 100, *, source="client", timestamp=2.0, window_size=65535):
    """One data segment from the client (or an ACK-only segment from the server)."""
    if source == "client":
        packet = tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, flags=ACK, sequence_number=sequence_number,
                            acknowledgment_number=301, payload=payload, window_size=window_size)
    else:
        packet = tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, flags=ACK, sequence_number=sequence_number,
                            acknowledgment_number=sequence_number, payload=payload, window_size=window_size)
    return timestamp, packet


def _parse(tmp_path, packets, **kwargs):
    path = tmp_path / "capture.pcap"
    write_pcap(path, packets, **kwargs)
    return PcapParser().parse(path)


def test_handshake_measures_rtt_payload_and_frame_bytes(tmp_path):
    capture = _parse(tmp_path, handshake_packets())

    (flow,) = capture.flows
    assert flow.handshake_rtt == pytest.approx(0.05)
    assert flow.payload_bytes == 100
    assert flow.total_frame_bytes == 54 + 54 + 154
    assert (flow.retransmission_count, flow.zero_window_event_count, flow.reset_count) == (0, 0, 0)
    assert capture.other_frame_bytes == 0
    assert capture.malformed_packet_count == 0


def test_both_directions_form_one_flow(tmp_path):
    capture = _parse(tmp_path, handshake_packets())

    assert len(capture.flows) == 1


def test_resent_range_counts_as_a_retransmission_but_new_ranges_do_not(tmp_path):
    packets = handshake_packets() + [_data(201), _data(101), _data(201)]

    (flow,) = _parse(tmp_path, packets).flows

    assert flow.retransmission_count == 2


def test_out_of_order_first_arrival_is_not_a_retransmission(tmp_path):
    packets = handshake_packets()[:2] + [_data(201), _data(101)]

    (flow,) = _parse(tmp_path, packets).flows

    assert flow.retransmission_count == 0


def test_retransmission_detection_survives_sequence_number_wraparound(tmp_path):
    near_wrap = 2**32 - 50
    syn = (1.0, tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, flags=SYN, sequence_number=near_wrap - 1))
    packets = [syn, _data(near_wrap), _data(near_wrap + 100 - 2**32), _data(near_wrap)]

    (flow,) = _parse(tmp_path, packets).flows

    assert flow.retransmission_count == 1


def test_pure_acks_are_never_retransmissions(tmp_path):
    packets = handshake_packets() + [_data(201, b"", timestamp=2.0), _data(201, b"", timestamp=2.1)]

    (flow,) = _parse(tmp_path, packets).flows

    assert flow.retransmission_count == 0


def test_retransmitted_syn_is_counted_and_its_rtt_is_not_measured(tmp_path):
    syn = tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, flags=SYN, sequence_number=100)
    syn_ack = tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, flags=SYN | ACK, sequence_number=300,
                         acknowledgment_number=101)

    (flow,) = _parse(tmp_path, [(1.0, syn), (2.0, syn), (2.05, syn_ack)]).flows

    assert flow.retransmission_count == 1
    assert flow.handshake_rtt is None


def test_syn_ack_that_does_not_acknowledge_the_syn_is_ignored(tmp_path):
    syn = tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, flags=SYN, sequence_number=100)
    wrong_ack = tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, flags=SYN | ACK, sequence_number=300,
                           acknowledgment_number=999)

    (flow,) = _parse(tmp_path, [(1.0, syn), (1.05, wrong_ack)]).flows

    assert flow.handshake_rtt is None


def test_zero_window_advertisements_are_counted_except_on_syn_fin_and_rst(tmp_path):
    zero_ack = _data(301, b"", source="server", window_size=0)
    zero_rst = (3.0, tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, flags=ACK | dpkt.tcp.TH_RST,
                                window_size=0))
    packets = handshake_packets() + [zero_ack, (2.5, zero_ack[1]), zero_rst]

    (flow,) = _parse(tmp_path, packets).flows

    assert flow.zero_window_event_count == 2
    assert flow.reset_count == 1


def test_rst_packets_are_counted(tmp_path):
    rst = tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, flags=dpkt.tcp.TH_RST)

    (flow,) = _parse(tmp_path, handshake_packets() + [(2.0, rst), (2.1, rst)]).flows

    assert flow.reset_count == 2


def test_udp_datagrams_form_their_own_flow(tmp_path):
    udp = udp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, b"y" * 40)

    capture = _parse(tmp_path, handshake_packets() + [(2.0, udp)])

    protocols = sorted(flow.flow_key.protocol for flow in capture.flows)
    udp_flow = next(flow for flow in capture.flows if flow.flow_key.protocol == "UDP")
    assert protocols == ["TCP", "UDP"]
    assert udp_flow.payload_bytes == 40
    assert udp_flow.total_frame_bytes == 14 + 20 + 8 + 40


def test_non_flow_traffic_only_counts_its_frame_bytes(tmp_path):
    arp = arp_packet()

    capture = _parse(tmp_path, [(1.0, arp)])

    assert capture.flows == ()
    assert capture.other_frame_bytes == len(arp)


def test_malformed_packets_are_skipped_and_counted(tmp_path):
    capture = _parse(tmp_path, handshake_packets() + [(2.0, malformed_packet_bytes())])

    assert capture.malformed_packet_count == 1
    assert len(capture.flows) == 1
    assert capture.other_frame_bytes == 0


def test_raw_ip_captures_are_supported(tmp_path):
    raw_packets = [(timestamp, frame[14:]) for timestamp, frame in handshake_packets()]

    (flow,) = _parse(tmp_path, raw_packets, linktype=RAW_IP_LINKTYPE).flows

    assert flow.handshake_rtt == pytest.approx(0.05)
    assert flow.total_frame_bytes == 40 + 40 + 140


def test_ipv6_tcp_is_parsed(tmp_path):
    tcp = dpkt.tcp.TCP(sport=40000, dport=443, seq=1, flags=ACK, data=b"z" * 30)
    ip6 = dpkt.ip6.IP6(src=b"\x20\x01" + b"\x00" * 13 + b"\x01", dst=b"\x20\x01" + b"\x00" * 13 + b"\x02",
                       nxt=dpkt.ip.IP_PROTO_TCP, hlim=64, plen=len(bytes(tcp)), data=tcp)

    (flow,) = _parse(tmp_path, [(1.0, bytes(ip6))], linktype=RAW_IP_LINKTYPE).flows

    assert flow.payload_bytes == 30
    assert flow.flow_key.protocol == "TCP"


def test_unsupported_datalink_raises_a_parse_error(tmp_path):
    path = tmp_path / "capture.pcap"
    write_pcap(path, handshake_packets(), linktype=147)

    with pytest.raises(PcapParseError, match="unsupported datalink"):
        PcapParser().parse(path)


def test_truncated_record_header_raises_a_parse_error(tmp_path):
    path = tmp_path / "broken.pcap"
    path.write_bytes(truncated_record_pcap_bytes())

    with pytest.raises(PcapParseError):
        PcapParser().parse(path)


@pytest.mark.parametrize("content", [b"", b"not a capture at all"])
def test_non_capture_files_raise_a_parse_error(tmp_path, content):
    path = tmp_path / "garbage.pcap"
    path.write_bytes(content)

    with pytest.raises(PcapParseError):
        PcapParser().parse(path)


def test_missing_file_raises_a_parse_error(tmp_path):
    with pytest.raises(PcapParseError, match="cannot read"):
        PcapParser().parse(tmp_path / "missing.pcap")


def test_pcapng_captures_are_supported(tmp_path):
    blocks = [pcapng_section_header_block(), pcapng_interface_description_block(dpkt.pcap.DLT_EN10MB)]
    blocks += [pcapng_enhanced_packet_block(timestamp, frame) for timestamp, frame in handshake_packets()]
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"".join(blocks))

    (flow,) = PcapParser().parse(path).flows

    assert flow.handshake_rtt == pytest.approx(0.05)
    assert flow.payload_bytes == 100