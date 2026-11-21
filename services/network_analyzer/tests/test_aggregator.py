import pytest
from metrics.aggregator import PcapMetricsAggregator
from pcap.models import FlowKey, FlowRecord, ParsedCapture


def _flow(client_port: int, server_port: int, **counters) -> FlowRecord:
    key = FlowKey.from_packet("TCP", "10.0.0.2", client_port, "93.184.216.34", server_port)
    return FlowRecord(flow_key=key, **counters)


def _capture(*flows: FlowRecord, other_frame_bytes: int = 0) -> ParsedCapture:
    return ParsedCapture(flows=tuple(flows), other_frame_bytes=other_frame_bytes, malformed_packet_count=0)


def test_sums_counters_and_derives_the_overhead_ratio():
    capture = _capture(
        _flow(50000, 443, total_frame_bytes=1000, payload_bytes=600, retransmission_count=2,
              zero_window_event_count=1, reset_count=1, handshake_rtt=0.04),
        _flow(50001, 443, total_frame_bytes=500, payload_bytes=300, retransmission_count=1,
              zero_window_event_count=0, reset_count=2, handshake_rtt=0.06),
        other_frame_bytes=100,
    )

    metrics = PcapMetricsAggregator().aggregate(capture)

    assert metrics.total_transferred_bytes == 1600
    assert metrics.total_payload_bytes == 900
    assert metrics.overhead_ratio == pytest.approx(700 / 1600)
    assert (metrics.retransmission_count, metrics.zero_window_event_count, metrics.tcp_reset_drops) == (3, 1, 3)
    assert metrics.handshake_rtt_avg == pytest.approx(0.05)


def test_handshake_rtt_averages_only_measurable_flows():
    capture = _capture(
        _flow(50000, 443, total_frame_bytes=100, handshake_rtt=0.1),
        _flow(50001, 443, total_frame_bytes=100, handshake_rtt=None),
    )

    assert PcapMetricsAggregator().aggregate(capture).handshake_rtt_avg == pytest.approx(0.1)


def test_empty_capture_has_no_ratio_rtt_or_port():
    metrics = PcapMetricsAggregator().aggregate(_capture())

    assert metrics.total_transferred_bytes == 0
    assert metrics.overhead_ratio is None
    assert metrics.handshake_rtt_avg is None
    assert metrics.dominant_server_port is None


def test_overhead_ratio_stays_between_zero_and_one():
    metrics = PcapMetricsAggregator().aggregate(_capture(_flow(50000, 443, total_frame_bytes=100, payload_bytes=100)))

    assert metrics.overhead_ratio == 0.0


def test_dominant_port_is_the_well_known_port_with_the_most_bytes():
    capture = _capture(
        _flow(50000, 443, total_frame_bytes=500),
        _flow(50001, 80, total_frame_bytes=300),
        _flow(50002, 80, total_frame_bytes=300),
    )

    assert PcapMetricsAggregator().aggregate(capture).dominant_server_port == 80


def test_unknown_ports_fall_back_to_the_lower_endpoint_port():
    capture = _capture(_flow(51000, 5222, total_frame_bytes=500))

    assert PcapMetricsAggregator().aggregate(capture).dominant_server_port == 5222


def test_port_ties_go_to_the_lower_port():
    capture = _capture(_flow(50000, 443, total_frame_bytes=100), _flow(50001, 80, total_frame_bytes=100))

    assert PcapMetricsAggregator().aggregate(capture).dominant_server_port == 80