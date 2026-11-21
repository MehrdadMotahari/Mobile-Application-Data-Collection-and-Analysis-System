from collections import Counter

from configs import WELL_KNOWN_PORTS
from metrics.models import PcapMetrics
from pcap.models import FlowKey, FlowRecord, ParsedCapture


class PcapMetricsAggregator:
    """Reduces a parsed capture's flows into the aggregate metrics stored in the network_metrics table."""

    def aggregate(self, capture: ParsedCapture) -> PcapMetrics:
        """Sum the per-flow counters, derive the ratios and pick the dominant server port.

        - total transferred bytes: frame bytes of every flow plus non-flow traffic (ARP, ICMP, ...);
          the pcap file's own headers are never counted;
        - overhead ratio: (total - payload) / total, None when nothing was transferred;
        - handshake RTT: mean over the flows whose handshake could be measured, None when none could.
        """
        flows = capture.flows
        total_bytes = sum(flow.total_frame_bytes for flow in flows) + capture.other_frame_bytes
        payload_bytes = sum(flow.payload_bytes for flow in flows)
        handshake_rtts = [flow.handshake_rtt for flow in flows if flow.handshake_rtt is not None]

        return PcapMetrics(
            handshake_rtt_avg=sum(handshake_rtts) / len(handshake_rtts) if handshake_rtts else None,
            retransmission_count=sum(flow.retransmission_count for flow in flows),
            zero_window_event_count=sum(flow.zero_window_event_count for flow in flows),
            tcp_reset_drops=sum(flow.reset_count for flow in flows),
            total_transferred_bytes=total_bytes,
            total_payload_bytes=payload_bytes,
            overhead_ratio=(total_bytes - payload_bytes) / total_bytes if total_bytes else None,
            dominant_server_port=self._dominant_server_port(flows),
        )

    @staticmethod
    def _server_port(flow_key: FlowKey) -> int:
        """The flow's server-side port: the well-known endpoint port when there is one, else the lower port."""
        ports = (flow_key.first_endpoint.port, flow_key.second_endpoint.port)
        well_known_ports = [port for port in ports if port in WELL_KNOWN_PORTS]
        return min(well_known_ports or ports)

    def _dominant_server_port(self, flows: tuple[FlowRecord, ...]) -> int | None:
        """The server port that carried the most frame bytes; the lower port wins a tie."""
        bytes_by_port: Counter[int] = Counter()
        for flow in flows:
            bytes_by_port[self._server_port(flow.flow_key)] += flow.total_frame_bytes
        if not bytes_by_port:
            return None
        return min(bytes_by_port, key=lambda port: (-bytes_by_port[port], port))