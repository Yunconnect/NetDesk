#[cfg(not(target_os = "ios"))]
use hbb_common::whoami;
use hbb_common::{
    allow_err,
    anyhow::bail,
    config::Config,
    config::{self},
    log,
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{
        self,
        sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    },
    ResultType,
};

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    time::Instant,
};

const LAN_DISCOVERY_PORT: u16 = 21_119;
pub(crate) const LAN_DEVICE_NAME_OPTION: &str = "lan-device-name";

type Message = RendezvousMessage;

pub(crate) fn sanitize_lan_device_name(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(64)
        .collect()
}

fn select_device_display_name(custom_name: &str, system_hostname: &str) -> String {
    let custom_name = sanitize_lan_device_name(custom_name);
    if !custom_name.is_empty() {
        return custom_name;
    }
    let system_hostname = sanitize_lan_device_name(system_hostname);
    if system_hostname.is_empty() {
        "SubnetDesk".to_owned()
    } else {
        system_hostname
    }
}

pub(crate) fn device_display_name() -> String {
    select_device_display_name(
        &Config::get_option(LAN_DEVICE_NAME_OPTION),
        &crate::hostname(),
    )
}

#[cfg(not(target_os = "ios"))]
pub(super) fn start_listening() -> ResultType<()> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    std::thread::spawn(|| {
        if let Err(err) = crate::lan_mdns::start_publisher() {
            log::warn!("mDNS publisher stopped: {err}");
        }
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], get_broadcast_port()));
    let socket = std::net::UdpSocket::bind(addr)?;
    socket.set_read_timeout(Some(std::time::Duration::from_millis(1000)))?;
    log::info!("lan discovery listener started");
    loop {
        let mut buf = [0; 2048];
        if let Ok((len, addr)) = socket.recv_from(&mut buf) {
            if let Ok(msg_in) = Message::parse_from_bytes(&buf[0..len]) {
                match msg_in.union {
                    Some(rendezvous_message::Union::PeerDiscovery(p)) => {
                        if p.cmd == "ping"
                            && Config::get_option("lan-discovery-enabled") != "N"
                            && Config::lan_credentials_configured()
                            && !config::option2bool(
                                "stop-service",
                                &Config::get_option("stop-service"),
                            )
                            && crate::lan_server::source_allowed(addr.ip())
                        {
                            let fingerprint =
                                crate::lan_protocol::fingerprint(&Config::get_key_pair().1);
                            if p.id == fingerprint {
                                continue;
                            }
                            if let Some(self_addr) = get_ipaddr_by_peer(&addr) {
                                let mut msg_out = Message::new();
                                let peer = PeerDiscovery {
                                    cmd: "pong".to_owned(),
                                    mac: get_mac(&self_addr),
                                    id: fingerprint.clone(),
                                    hostname: device_display_name(),
                                    username: String::new(),
                                    platform: whoami::platform().to_string(),
                                    misc: serde_json::json!({
                                        "protocol_version": hbb_common::lan::PROTOCOL_VERSION,
                                        "port": Config::get_option("lan-listen-port")
                                            .parse::<u16>()
                                            .ok()
                                            .filter(|port| *port > 0)
                                            .unwrap_or(hbb_common::lan::DEFAULT_PORT),
                                        "fingerprint": fingerprint,
                                    })
                                    .to_string(),
                                    ..Default::default()
                                };
                                msg_out.set_peer_discovery(peer);
                                socket.send_to(&msg_out.write_to_bytes()?, addr).ok();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

pub(crate) async fn discover_async() -> ResultType<()> {
    let (tx, rx) = unbounded_channel::<_>();
    let mut worker_started = false;
    match send_query() {
        Ok(sockets) => {
            spawn_wait_responses(sockets, tx.clone());
            worker_started = true;
        }
        Err(err) => log::warn!("UDP LAN discovery unavailable: {err}"),
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    match crate::lan_mdns::spawn_browse(tx.clone()) {
        Ok(()) => worker_started = true,
        Err(err) => log::warn!("mDNS discovery unavailable: {err}"),
    }
    drop(tx);
    if !worker_started {
        bail!("No LAN discovery transport is available");
    }
    handle_received_peers(rx).await?;

    log::info!("discover ping done");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
pub async fn discover() -> ResultType<()> {
    discover_async().await
}

pub(crate) fn connection_candidates(endpoint: &str) -> (Option<String>, Vec<String>) {
    let recent = config::LocalConfig::get_recent_lan_endpoints();
    let peers = config::LanPeers::load().peers;
    connection_candidates_from(endpoint, &recent, &peers)
}

fn connection_candidates_from(
    endpoint: &str,
    recent: &[config::RecentLanEndpoint],
    peers: &[config::DiscoveryPeer],
) -> (Option<String>, Vec<String>) {
    let Ok(requested) = hbb_common::lan::Endpoint::parse(endpoint) else {
        return (None, vec![endpoint.to_owned()]);
    };
    let requested = requested.authority().to_owned();
    let mut fingerprint = recent
        .iter()
        .find(|recent| recent.endpoint == requested)
        .map(|recent| recent.fingerprint.to_ascii_lowercase());

    if fingerprint.is_none() {
        fingerprint = peers.iter().find_map(|peer| {
            if peer.endpoint == requested {
                return Some(peer.fingerprint.to_ascii_lowercase());
            }
            let requested_endpoint = hbb_common::lan::Endpoint::parse(&requested).ok()?;
            if peer.ip_mac.contains_key(requested_endpoint.host()) {
                Some(peer.fingerprint.to_ascii_lowercase())
            } else {
                None
            }
        });
    }
    let fingerprint = fingerprint
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let mut candidates = Vec::new();
    push_unique(&mut candidates, requested);
    if let Some(fingerprint) = fingerprint.as_ref() {
        for recent in recent
            .iter()
            .filter(|recent| recent.fingerprint.eq_ignore_ascii_case(fingerprint))
        {
            push_unique(&mut candidates, recent.endpoint.clone());
        }
        for peer in peers
            .iter()
            .filter(|peer| peer.fingerprint.eq_ignore_ascii_case(fingerprint))
        {
            push_unique(&mut candidates, peer.endpoint.clone());
            let port = hbb_common::lan::Endpoint::parse(&peer.endpoint)
                .map(|endpoint| endpoint.port())
                .unwrap_or(hbb_common::lan::DEFAULT_PORT);
            let mut addresses = peer.ip_mac.keys().collect::<Vec<_>>();
            addresses.sort();
            for address in addresses {
                if let Ok(address) = address.parse::<IpAddr>() {
                    let endpoint = match address {
                        IpAddr::V4(address) => format!("{address}:{port}"),
                        IpAddr::V6(address) => format!("[{address}]:{port}"),
                    };
                    push_unique(&mut candidates, endpoint);
                }
            }
        }
    }
    (fingerprint, candidates)
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !value.is_empty() && !values.contains(&value) {
        values.push(value);
    }
}

pub fn send_wol(id: String) {
    let interfaces = default_net::get_interfaces();
    for peer in &config::LanPeers::load().peers {
        if peer.id == id {
            for (_, mac) in peer.ip_mac.iter() {
                if let Ok(mac_addr) = mac.parse() {
                    for interface in &interfaces {
                        for ipv4 in &interface.ipv4 {
                            // remove below mask check to avoid unexpected bug
                            // if (u32::from(ipv4.addr) & u32::from(ipv4.netmask)) == (u32::from(peer_ip) & u32::from(ipv4.netmask))
                            log::info!("Send wol to {mac_addr} of {}", ipv4.addr);
                            allow_err!(wol::send_wol(mac_addr, None, Some(IpAddr::V4(ipv4.addr))));
                        }
                    }
                }
            }
            break;
        }
    }
}

#[inline]
fn get_broadcast_port() -> u16 {
    LAN_DISCOVERY_PORT
}

fn get_mac(_ip: &IpAddr) -> String {
    #[cfg(not(target_os = "ios"))]
    if let Ok(mac) = get_mac_by_ip(_ip) {
        mac.to_string()
    } else {
        "".to_owned()
    }
    #[cfg(target_os = "ios")]
    "".to_owned()
}

#[cfg(not(target_os = "ios"))]
fn get_mac_by_ip(ip: &IpAddr) -> ResultType<String> {
    for interface in default_net::get_interfaces() {
        match ip {
            IpAddr::V4(local_ipv4) => {
                if interface.ipv4.iter().any(|x| x.addr == *local_ipv4) {
                    if let Some(mac_addr) = interface.mac_addr {
                        return Ok(mac_addr.address());
                    }
                }
            }
            IpAddr::V6(local_ipv6) => {
                if interface.ipv6.iter().any(|x| x.addr == *local_ipv6) {
                    if let Some(mac_addr) = interface.mac_addr {
                        return Ok(mac_addr.address());
                    }
                }
            }
        }
    }
    bail!("No interface found for ip: {:?}", ip);
}

// Mainly from https://github.com/shellrow/default-net/blob/cf7ca24e7e6e8e566ed32346c9cfddab3f47e2d6/src/interface/shared.rs#L4
fn get_ipaddr_by_peer<A: ToSocketAddrs>(peer: A) -> Option<IpAddr> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return None,
    };

    match socket.connect(peer) {
        Ok(()) => (),
        Err(_) => return None,
    };

    match socket.local_addr() {
        Ok(addr) => return Some(addr.ip()),
        Err(_) => return None,
    };
}

fn create_broadcast_sockets() -> Vec<UdpSocket> {
    let mut ipv4s = Vec::new();
    // TODO: maybe we should use a better way to get ipv4 addresses.
    // But currently, it's ok to use `[Ipv4Addr::UNSPECIFIED]` for discovery.
    // `default_net::get_interfaces()` causes undefined symbols error when `flutter build` on iOS simulator x86_64
    #[cfg(not(any(target_os = "ios")))]
    for interface in default_net::get_interfaces() {
        for ipv4 in &interface.ipv4 {
            ipv4s.push(ipv4.addr.clone());
        }
    }
    ipv4s.push(Ipv4Addr::UNSPECIFIED); // for robustness
    let mut sockets = Vec::new();
    for v4_addr in ipv4s {
        // removing v4_addr.is_private() check, https://github.com/rustdesk/rustdesk/issues/4663
        if let Ok(s) = UdpSocket::bind(SocketAddr::from((v4_addr, 0))) {
            if s.set_broadcast(true).is_ok() {
                sockets.push(s);
            }
        }
    }
    sockets
}

fn send_query() -> ResultType<Vec<UdpSocket>> {
    let sockets = create_broadcast_sockets();
    if sockets.is_empty() {
        bail!("Found no bindable ipv4 addresses");
    }

    let mut msg_out = Message::new();
    let id = crate::lan_protocol::fingerprint(&Config::get_key_pair().1);
    let peer = PeerDiscovery {
        cmd: "ping".to_owned(),
        id,
        ..Default::default()
    };
    msg_out.set_peer_discovery(peer);
    let out = msg_out.write_to_bytes()?;
    let maddr = SocketAddr::from(([255, 255, 255, 255], get_broadcast_port()));
    for socket in &sockets {
        allow_err!(socket.send_to(&out, maddr));
    }
    log::info!("discover ping sent");
    Ok(sockets)
}

fn wait_response(
    socket: UdpSocket,
    timeout: Option<std::time::Duration>,
    tx: UnboundedSender<config::DiscoveryPeer>,
) -> ResultType<()> {
    let mut last_recv_time = Instant::now();

    let local_addr = socket.local_addr();
    let try_get_ip_by_peer = match local_addr.as_ref() {
        Err(..) => true,
        Ok(addr) => addr.ip().is_unspecified(),
    };
    let mut mac: Option<String> = None;

    socket.set_read_timeout(timeout)?;
    loop {
        let mut buf = [0; 2048];
        if let Ok((len, addr)) = socket.recv_from(&mut buf) {
            if let Ok(msg_in) = Message::parse_from_bytes(&buf[0..len]) {
                match msg_in.union {
                    Some(rendezvous_message::Union::PeerDiscovery(p)) => {
                        last_recv_time = Instant::now();
                        if p.cmd == "pong" {
                            if p.id.len() != 64
                                || !p.id.bytes().all(|value| value.is_ascii_hexdigit())
                            {
                                log::warn!(
                                    "Ignoring LAN discovery response from {} with invalid fingerprint",
                                    addr
                                );
                                continue;
                            }

                            let misc = serde_json::from_str::<serde_json::Value>(&p.misc)
                                .unwrap_or_default();
                            let port = misc
                                .get("port")
                                .and_then(|value| value.as_u64())
                                .and_then(|value| u16::try_from(value).ok())
                                .filter(|value| *value > 0)
                                .unwrap_or(hbb_common::lan::DEFAULT_PORT);
                            let endpoint = if addr.ip().is_ipv6() {
                                format!("[{}]:{}", addr.ip(), port)
                            } else {
                                format!("{}:{}", addr.ip(), port)
                            };

                            let local_mac = if try_get_ip_by_peer {
                                if let Some(self_addr) = get_ipaddr_by_peer(&addr) {
                                    get_mac(&self_addr)
                                } else {
                                    "".to_owned()
                                }
                            } else {
                                match mac.as_ref() {
                                    Some(m) => m.clone(),
                                    None => {
                                        let m = if let Ok(local_addr) = local_addr {
                                            get_mac(&local_addr.ip())
                                        } else {
                                            "".to_owned()
                                        };
                                        mac = Some(m.clone());
                                        m
                                    }
                                }
                            };

                            if local_mac.is_empty() && p.mac.is_empty() || local_mac != p.mac {
                                allow_err!(tx.send(config::DiscoveryPeer {
                                    id: endpoint.clone(),
                                    endpoint,
                                    fingerprint: p.id.clone(),
                                    ip_mac: HashMap::from([
                                        (addr.ip().to_string(), p.mac.clone(),)
                                    ]),
                                    username: p.username.clone(),
                                    hostname: p.hostname.clone(),
                                    platform: p.platform.clone(),
                                    online: true,
                                }));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if last_recv_time.elapsed().as_millis() > 3_000 {
            break;
        }
    }
    Ok(())
}

fn spawn_wait_responses(
    sockets: Vec<UdpSocket>,
    tx: UnboundedSender<config::DiscoveryPeer>,
) {
    for socket in sockets {
        let tx_clone = tx.clone();
        std::thread::spawn(move || {
            allow_err!(wait_response(
                socket,
                Some(std::time::Duration::from_millis(10)),
                tx_clone
            ));
        });
    }
}

async fn handle_received_peers(mut rx: UnboundedReceiver<config::DiscoveryPeer>) -> ResultType<()> {
    let mut peers = config::LanPeers::load().peers;
    peers.iter_mut().for_each(|peer| {
        peer.online = false;
    });

    let mut last_write_time: Option<Instant> = None;
    loop {
        tokio::select! {
            data = rx.recv() => match data {
                Some(mut peer) => {
                    if let Some(pos) = peers.iter().position(|x| x.is_same_peer(&peer) ) {
                        let peer1 = peers.remove(pos);
                        if let Ok(endpoint) = hbb_common::lan::Endpoint::parse(&peer1.endpoint) {
                            if endpoint.host().parse::<IpAddr>().is_ok() {
                                peer.ip_mac
                                    .entry(endpoint.host().to_owned())
                                    .or_default();
                            }
                        }
                        peer.ip_mac.extend(peer1.ip_mac);
                    }
                    peers.insert(0, peer);
                    if last_write_time.map(|t| t.elapsed().as_millis() > 300).unwrap_or(true)  {
                        config::LanPeers::store(&peers);
                        #[cfg(feature = "flutter")]
                        crate::flutter_ffi::main_load_lan_peers();
                        last_write_time = Some(Instant::now());
                    }
                }
                None => {
                    break
                }
            }
        }
    }

    config::LanPeers::store(&peers);
    #[cfg(feature = "flutter")]
    crate::flutter_ffi::main_load_lan_peers();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_device_name_is_trimmed_filtered_and_bounded() {
        assert_eq!(sanitize_lan_device_name("  Meeting Room  "), "Meeting Room");
        assert_eq!(sanitize_lan_device_name("会议\n室"), "会议室");
        assert_eq!(sanitize_lan_device_name(&"a".repeat(80)).len(), 64);
    }

    #[test]
    fn custom_device_name_overrides_hostname_and_empty_value_restores_it() {
        assert_eq!(
            select_device_display_name("Studio Mac", "host.local"),
            "Studio Mac"
        );
        assert_eq!(select_device_display_name("", "host.local"), "host.local");
        assert_eq!(select_device_display_name("", "\n"), "SubnetDesk");
    }

    #[test]
    fn connection_candidates_keep_vpn_endpoint_and_add_discovered_addresses() {
        let fingerprint = "a".repeat(64);
        let recent = config::RecentLanEndpoint {
            endpoint: "10.8.0.15:21118".to_owned(),
            fingerprint: fingerprint.clone(),
            ..Default::default()
        };
        let peers = vec![config::DiscoveryPeer {
            endpoint: "192.168.1.99:21118".to_owned(),
            fingerprint: fingerprint.clone(),
            ip_mac: HashMap::from([
                ("192.168.1.99".to_owned(), String::new()),
                ("10.8.0.15".to_owned(), String::new()),
            ]),
            ..Default::default()
        }];

        let (resolved_fingerprint, candidates) =
            connection_candidates_from(&recent.endpoint, &[recent.clone()], &peers);

        assert_eq!(resolved_fingerprint, Some(fingerprint));
        assert_eq!(candidates[0], "10.8.0.15:21118");
        assert!(candidates.contains(&"192.168.1.99:21118".to_owned()));
        assert_eq!(
            candidates
                .iter()
                .filter(|endpoint| endpoint.as_str() == "10.8.0.15:21118")
                .count(),
            1
        );
    }

    #[test]
    fn connection_candidates_can_identify_device_from_discovery_cache() {
        let fingerprint = "b".repeat(64);
        let peers = vec![config::DiscoveryPeer {
            endpoint: "192.168.1.20:21118".to_owned(),
            fingerprint: fingerprint.clone(),
            ip_mac: HashMap::from([("10.9.0.20".to_owned(), String::new())]),
            ..Default::default()
        }];

        let (resolved_fingerprint, candidates) =
            connection_candidates_from("10.9.0.20:21118", &[], &peers);

        assert_eq!(resolved_fingerprint, Some(fingerprint));
        assert_eq!(candidates[0], "10.9.0.20:21118");
        assert!(candidates.contains(&"192.168.1.20:21118".to_owned()));
    }
}
