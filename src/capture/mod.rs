use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedPacket {
    pub timestamp: u64,
    pub direction: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub payload_hex: String,
    pub packet_size: usize,
    pub parsed_info: Option<JsonValue>,
}

#[derive(Debug, Clone)]
pub struct PacketCapture {
    packets: Arc<Mutex<VecDeque<CapturedPacket>>>,
    max_packets: usize,
    server_port: u16,
    shutdown_flag: Arc<AtomicBool>,
}

impl PacketCapture {
    pub fn new(max_packets: usize, server_port: u16) -> Self {
        Self {
            packets: Arc::new(Mutex::new(VecDeque::new())),
            max_packets,
            server_port,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start_capture(
        &self,
        interface: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let packets = self.packets.clone();
        let max_packets = self.max_packets;
        let server_port = self.server_port;
        let shutdown_flag = self.shutdown_flag.clone();

        tracing::info!("Attempting to start packet capture on port {}", server_port);

        // Test basic pcap functionality first
        match self.test_pcap_basic(interface.clone()) {
            Ok(device_name) => {
                tracing::info!("Packet capture test passed, using device: {}", device_name);

                // Spawn the actual capture task
                let _capture_handle = tokio::task::spawn_blocking(move || {
                    if let Err(e) = Self::run_capture_blocking(
                        packets,
                        max_packets,
                        server_port,
                        interface,
                        shutdown_flag,
                    ) {
                        tracing::error!("Packet capture task error: {}", e);
                    }
                });

                // Give the capture task a moment to initialize before returning
                std::thread::sleep(std::time::Duration::from_millis(500));
                tracing::info!("Packet capture background task started");

                Ok(())
            }
            Err(e) => {
                tracing::error!("Packet capture initialization failed: {}", e);
                Err(e)
            }
        }
    }

    fn test_pcap_basic(
        &self,
        interface: Option<String>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        use pcap::{Capture, Device};

        let devices = Device::list()?;
        tracing::info!("Available network devices:");
        for (i, device) in devices.iter().enumerate() {
            tracing::info!(
                "  {}: {} ({})",
                i,
                device.name,
                device
                    .desc
                    .as_ref()
                    .unwrap_or(&"No description".to_string())
            );
        }

        let device = if let Some(iface) = interface {
            devices
                .into_iter()
                .find(|d| d.name == iface)
                .ok_or(format!("Interface {} not found", iface))?
        } else {
            // For localhost testing, prefer loopback interface over 'any'
            devices
                .iter()
                .find(|d| d.name == "lo")
                .cloned()
                .or_else(|| devices.iter().find(|d| d.name == "any").cloned())
                .unwrap_or_else(|| devices.into_iter().next().unwrap())
        };

        let use_promisc = device.name != "any";
        let _test_cap = Capture::from_device(device.clone())?
            .promisc(use_promisc)
            .snaplen(1500)
            .timeout(100)
            .open()?;

        Ok(device.name)
    }

    fn run_capture_blocking(
        packets: Arc<Mutex<VecDeque<CapturedPacket>>>,
        max_packets: usize,
        server_port: u16,
        interface: Option<String>,
        shutdown_flag: Arc<AtomicBool>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use pcap::{Capture, Device};

        let devices = Device::list()?;
        let device = if let Some(iface) = interface {
            devices
                .into_iter()
                .find(|d| d.name == iface)
                .ok_or(format!("Interface {} not found", iface))?
        } else {
            devices
                .iter()
                .find(|d| d.name == "lo")
                .cloned()
                .or_else(|| devices.iter().find(|d| d.name == "any").cloned())
                .unwrap_or_else(|| devices.into_iter().next().unwrap())
        };

        tracing::info!("Starting packet capture on interface: {}", device.name);

        let use_promisc = device.name != "any";
        let mut cap = Capture::from_device(device)?
            .promisc(use_promisc)
            .snaplen(65535)
            .timeout(100)
            .open()?;

        let filter = format!("tcp and dst port {}", server_port);
        tracing::info!("Setting packet filter: {}", filter);
        cap.filter(&filter, true)?;

        tracing::info!("Packet capture loop started, waiting for packets...");
        let mut packet_count = 0;

        loop {
            if shutdown_flag.load(Ordering::SeqCst) {
                tracing::info!("Shutdown flag is set, terminating packet capture loop");
                break;
            }

            match cap.next_packet() {
                Ok(packet) => {
                    packet_count += 1;
                    tracing::info!(
                        "Raw packet #{} captured, size: {} bytes",
                        packet_count,
                        packet.data.len()
                    );

                    if let Some(captured_packet) = Self::parse_packet(&packet.data, server_port) {
                        let mut packets_guard = packets.lock().unwrap();

                        if packets_guard.len() >= max_packets {
                            packets_guard.pop_front();
                        }

                        packets_guard.push_back(captured_packet.clone());
                        tracing::info!(
                            "Captured packet #{}: {} -> {} ({})",
                            packet_count,
                            captured_packet.src_ip,
                            captured_packet.dst_ip,
                            captured_packet.direction
                        );
                    } else {
                        let parsed_info = Self::parse_packet_with_pktparse(&packet.data);
                        let raw_packet = CapturedPacket {
                            timestamp: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as u64,
                            direction: "unknown".to_string(),
                            src_ip: "unknown".to_string(),
                            dst_ip: "unknown".to_string(),
                            src_port: 0,
                            dst_port: server_port,
                            protocol: "RAW".to_string(),
                            payload_hex: hex::encode(&packet.data),
                            packet_size: packet.data.len(),
                            parsed_info,
                        };

                        let mut packets_guard = packets.lock().unwrap();
                        if packets_guard.len() >= max_packets {
                            packets_guard.pop_front();
                        }
                        packets_guard.push_back(raw_packet);

                        tracing::warn!("Stored raw packet #{} (parsing failed)", packet_count);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Timeout is normal, continue
                    continue;
                }
                Err(e) => {
                    tracing::error!("Packet capture error: {}", e);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }

        tracing::info!(
            "Packet capture thread exiting, processed {} packets",
            packet_count
        );
        Ok(())
    }

    fn parse_packet(data: &[u8], server_port: u16) -> Option<CapturedPacket> {
        use pnet::packet::{
            ethernet::{EtherTypes, EthernetPacket},
            ip::IpNextHeaderProtocols,
            ipv4::Ipv4Packet,
            ipv6::Ipv6Packet,
            tcp::TcpPacket,
            Packet,
        };

        let ethernet = EthernetPacket::new(data)?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let parsed_info = Self::parse_packet_with_pktparse(data);

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4 = Ipv4Packet::new(ethernet.payload())?;

                if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                    let tcp = TcpPacket::new(ipv4.payload())?;
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();

                    if dst_port == server_port {
                        return Some(CapturedPacket {
                            timestamp,
                            direction: "inbound".to_string(),
                            src_ip: ipv4.get_source().to_string(),
                            dst_ip: ipv4.get_destination().to_string(),
                            src_port,
                            dst_port,
                            protocol: "TCP".to_string(),
                            payload_hex: hex::encode(data),
                            packet_size: data.len(),
                            parsed_info,
                        });
                    }
                }
            }
            EtherTypes::Ipv6 => {
                let ipv6 = Ipv6Packet::new(ethernet.payload())?;

                if ipv6.get_next_header() == IpNextHeaderProtocols::Tcp {
                    let tcp = TcpPacket::new(ipv6.payload())?;
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();

                    if dst_port == server_port {
                        return Some(CapturedPacket {
                            timestamp,
                            direction: "inbound".to_string(),
                            src_ip: ipv6.get_source().to_string(),
                            dst_ip: ipv6.get_destination().to_string(),
                            src_port,
                            dst_port,
                            protocol: "TCP".to_string(),
                            payload_hex: hex::encode(data),
                            packet_size: data.len(),
                            parsed_info,
                        });
                    }
                }
            }
            _ => {}
        }

        None
    }

    fn parse_packet_with_pktparse(data: &[u8]) -> Option<JsonValue> {
        use pktparse::{ethernet, ip::IPProtocol, ipv4, ipv6, tcp};
        use serde_json::{json, to_value};

        // Try to parse the ethernet frame
        match ethernet::parse_ethernet_frame(data) {
            Ok((remaining, eth_frame)) => {
                let mut parsed = json!({
                    "ethernet": {
                        "ethertype": to_value(&eth_frame.ethertype).unwrap_or_else(|_| json!("unknown"))
                    }
                });

                // Parse IP layer
                match eth_frame.ethertype {
                    ethernet::EtherType::IPv4 => {
                        if let Ok((tcp_udp_data, ipv4_hdr)) = ipv4::parse_ipv4_header(remaining) {
                            parsed["ipv4"] = to_value(&ipv4_hdr).unwrap_or_else(
                                |_| json!({"error": "Failed to serialize IPv4 header"}),
                            );

                            // Parse transport layer
                            match ipv4_hdr.protocol {
                                IPProtocol::TCP => {
                                    if let Ok((payload, tcp_hdr)) =
                                        tcp::parse_tcp_header(tcp_udp_data)
                                    {
                                        parsed["tcp"] = to_value(&tcp_hdr).unwrap_or_else(
                                            |_| json!({"error": "Failed to serialize TCP header"}),
                                        );

                                        // If there's application data, include a preview
                                        if !payload.is_empty() {
                                            let preview_len = std::cmp::min(payload.len(), 64);
                                            parsed["application_data"] = json!({
                                                "length": payload.len(),
                                                "preview_hex": hex::encode(&payload[..preview_len]),
                                                "preview_ascii": payload[..preview_len].iter()
                                                    .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                                                    .collect::<String>()
                                            });
                                        }
                                    }
                                }
                                _ => {
                                    parsed["unknown_transport"] = json!({
                                        "protocol": to_value(&ipv4_hdr.protocol).unwrap_or_else(|_| json!("unknown")),
                                        "data_length": tcp_udp_data.len()
                                    });
                                }
                            }
                        }
                    }
                    ethernet::EtherType::IPv6 => {
                        if let Ok((tcp_udp_data, ipv6_hdr)) = ipv6::parse_ipv6_header(remaining) {
                            parsed["ipv6"] = to_value(&ipv6_hdr).unwrap_or_else(
                                |_| json!({"error": "Failed to serialize IPv6 header"}),
                            );

                            // Parse transport layer for IPv6
                            match ipv6_hdr.next_header {
                                IPProtocol::TCP => {
                                    if let Ok((payload, tcp_hdr)) =
                                        tcp::parse_tcp_header(tcp_udp_data)
                                    {
                                        parsed["tcp"] = to_value(&tcp_hdr).unwrap_or_else(
                                            |_| json!({"error": "Failed to serialize TCP header"}),
                                        );

                                        // If there's application data, include a preview
                                        if !payload.is_empty() {
                                            let preview_len = std::cmp::min(payload.len(), 64);
                                            parsed["application_data"] = json!({
                                                "length": payload.len(),
                                                "preview_hex": hex::encode(&payload[..preview_len]),
                                                "preview_ascii": payload[..preview_len].iter()
                                                    .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                                                    .collect::<String>()
                                            });
                                        }
                                    }
                                }
                                _ => {
                                    parsed["unknown_transport"] = json!({
                                        "protocol": to_value(&ipv6_hdr.next_header).unwrap_or_else(|_| json!("unknown")),
                                        "data_length": tcp_udp_data.len()
                                    });
                                }
                            }
                        }
                    }
                    _ => {
                        parsed["unknown_protocol"] = json!({
                            "ethertype": to_value(&eth_frame.ethertype).unwrap_or_else(|_| json!("unknown")),
                            "data_length": remaining.len()
                        });
                    }
                }

                Some(parsed)
            }
            Err(_) => Some(json!({
                "parse_error": "Failed to parse ethernet frame",
                "raw_data_length": data.len(),
                "raw_data_preview": hex::encode(&data[..std::cmp::min(data.len(), 32)])
            })),
        }
    }

    pub fn get_packets_for_client(&self, client_ip: &str, client_port: u16) -> Vec<CapturedPacket> {
        let packets_guard = self.packets.lock().unwrap();
        packets_guard
            .iter()
            .filter(|packet| packet.src_ip == client_ip && packet.src_port == client_port)
            .cloned()
            .collect()
    }

    pub fn clear_packets_for_client(&self, client_ip: &str, client_port: u16) {
        let mut packets_guard = self.packets.lock().unwrap();
        packets_guard
            .retain(|packet| !(packet.src_ip == client_ip && packet.src_port == client_port));
    }

    pub fn shutdown(&self) {
        tracing::info!("Signaling packet capture to shutdown");
        self.shutdown_flag.store(true, Ordering::SeqCst);
    }
}
