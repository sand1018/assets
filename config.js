// Sub-Store 覆写配置（稳定最终版）
// 特点：
// - 国内域名/IP 直连
// - 国外域名/IP 代理
// - Fake-IP + TUN 全接管
// - Cloudflare DNS 优先
// - 严格防 DNS 泄露
// - 不使用 fallback
// - 使用 jsDelivr ruleset CDN
// - 兼容 Mihomo / Clash Meta / FlClash
// - 偏长期稳定使用

function main(config) {
  config = config || {};

  const proxies = Array.isArray(config.proxies) ? config.proxies : [];
  const nodeNames = proxies.map((p) => p.name).filter(Boolean);
  const usableNodes = nodeNames.length ? nodeNames : ["REJECT"];

  const URL_TEST = "http://www.gstatic.com/generate_204";

  // 地区识别
  const regionDefs = [
    { name: "香港", re: /香港|🇭🇰|Hong\s?Kong|(^|[^a-z])hk([^a-z]|$)/i },
    { name: "台湾", re: /台湾|台灣|🇹🇼|Taiwan|(^|[^a-z])tw([^a-z]|$)/i },
    { name: "日本", re: /日本|东京|大阪|🇯🇵|Japan|(^|[^a-z])jp([^a-z]|$)/i },
    { name: "新加坡", re: /新加坡|狮城|獅城|🇸🇬|Singapore|(^|[^a-z])sg([^a-z]|$)/i },
    { name: "美国", re: /美国|美國|🇺🇸|United\s?States|America|(^|[^a-z])(us|usa)([^a-z]|$)/i },
    { name: "韩国", re: /韩国|韓國|首尔|🇰🇷|Korea|(^|[^a-z])kr([^a-z]|$)/i },
  ];

  const regionGroups = regionDefs
    .map((d) => ({
      name: d.name,
      nodes: nodeNames.filter((n) => d.re.test(n)),
    }))
    .filter((r) => r.nodes.length);

  const regionNames = regionGroups.map((r) => r.name);

  // Ruleset CDN
  const RS_PREFIX =
    "https://fastly.jsdelivr.net/gh/DustinWin/ruleset_geodata@mihomo-ruleset";

  const mrs = (name, behavior) => ({
    type: "http",
    behavior,
    format: "mrs",
    interval: 86400,
    path: `./ruleset/${name}.mrs`,
    url: `${RS_PREFIX}/${name}.mrs`,
  });

  Object.assign(config, {
    ipv6: false,

    "tcp-concurrent": true,

    mode: "rule",

    "log-level": "info",

    profile: {
      "store-selected": true,
      "store-fake-ip": true,
    },

    // TUN
    tun: {
      enable: true,

      stack: "system",

      "dns-hijack": [
        "any:53",
        "tcp://any:53",
        "tcp://any:853",
        "udp://any:853",
      ],

      "auto-route": true,

      "auto-detect-interface": true,
    },

    // DNS
    dns: {
      enable: true,

      ipv6: false,

      "prefer-h3": false,

      "enhanced-mode": "fake-ip",

      "fake-ip-range": "198.18.0.1/16",

      "respect-rules": true,

      "use-hosts": false,

      // 本地 DNS（仅用于启动）
      "default-nameserver": [
        "223.5.5.5",
        "119.29.29.29",
      ],

      // 节点域名解析
      "proxy-server-nameserver": [
        "https://dns.alidns.com/dns-query#DIRECT",
        "https://doh.pub/dns-query#DIRECT",
      ],

      // 国内 DNS
      "direct-nameserver": [
        "https://dns.alidns.com/dns-query#DIRECT",
        "https://doh.pub/dns-query#DIRECT",
      ],

      "direct-nameserver-follow-policy": true,

      // 国外 DNS（Cloudflare 优先）
      // 不使用 fallback，避免 DNS 泄露
      nameserver: [
        "tls://1.1.1.1#Proxy",
        "tls://1.0.0.1#Proxy",
        "tls://8.8.8.8#Proxy",
      ],

      // DNS 分流
      "nameserver-policy": {
        "geosite:private": [
          "223.5.5.5",
          "119.29.29.29",
        ],

        "geosite:cn": [
          "https://dns.alidns.com/dns-query#DIRECT",
          "https://doh.pub/dns-query#DIRECT",
        ],

        "geosite:geolocation-cn": [
          "https://dns.alidns.com/dns-query#DIRECT",
          "https://doh.pub/dns-query#DIRECT",
        ],

        "geosite:category-games@cn": [
          "https://dns.alidns.com/dns-query#DIRECT",
          "https://doh.pub/dns-query#DIRECT",
        ],

        "+.cn": [
          "https://dns.alidns.com/dns-query#DIRECT",
          "https://doh.pub/dns-query#DIRECT",
        ],
      },

      // Fake-IP 排除
      "fake-ip-filter": [
        "*.lan",
        "*.local",
        "*.localdomain",
        "*.home.arpa",

        "localhost.ptlogin2.qq.com",

        "*.msftconnecttest.com",
        "*.msftncsi.com",

        "time.*.com",
        "time.*.gov",
        "ntp.*.com",
        "+.ntp.org",

        "+.srv.nintendo.net",
        "+.stun.playstation.net",

        "xbox.*.*.microsoft.com",

        "connect.rom.miui.com",

        "network-test.debian.org",
      ],
    },

    // Rule Providers
    "rule-providers": {
      private: mrs("private", "domain"),

      privateip: mrs("privateip", "ipcidr"),

      ai: mrs("ai", "domain"),

      media: mrs("media", "domain"),

      proxy: mrs("proxy", "domain"),

      cn: mrs("cn", "domain"),

      cnip: mrs("cnip", "ipcidr"),

      telegramip: mrs("telegramip", "ipcidr"),
    },

    // Proxy Groups
    "proxy-groups": [
      {
        name: "Proxy",
        type: "select",
        proxies: [
          "Auto",
          ...regionNames,
          "DIRECT",
          ...usableNodes,
        ],
      },

      {
        name: "Auto",
        type: "url-test",
        proxies: usableNodes,
        url: URL_TEST,
        interval: 300,
        tolerance: 50,
        lazy: true,
      },

      {
        name: "流媒体",
        type: "select",
        proxies: [
          "Proxy",
          "Auto",
          ...regionNames,
    
