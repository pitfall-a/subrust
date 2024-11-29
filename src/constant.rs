pub mod clash_constant {
    pub const PORT: u32 = 7890;
    pub const SOCKS_PORT: u32 = 7891;
    pub const ALLOW_LAN: bool = true;
    pub const MODE: &str = "Rule";
    pub const LOG_LEVEL: &str = "info";
    pub const EXTERNAL_CONTROLLER: &str = ":9090";
    pub const DNS_ENABLED: bool = true;
    pub const DNS_NAMESERVER: [&str; 2] = ["119.29.29.29", "223.5.5.5"];
    pub const DNS_FALLBACK: [&str; 4] = [
        "8.8.8.8",
        "8.8.4.4",
        "tls://1.0.0.1:853",
        "tls://dns.google:853",
    ];

    pub const FORMAT_RULE_TYPE: [&str;9] = ["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "GEOIP", "GEOIP-CIDR", "PROCESS-NAME", "MATCH"];
}
