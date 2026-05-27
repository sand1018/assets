// 配置入口：保留 SubStore 生成的节点，只覆写 DNS、TUN、策略组和规则。
function main(config) {
  config = config || {};

  const proxies = Array.isArray(config.proxies) ? config.proxies : [];
  const nodeNames = proxies.map((proxy) => proxy.name).filter(Boolean);
  const usableNodes = nodeNames.length ? nodeNames : ["REJECT"];

  Object.assign(config, {
    ipv6: false,
    mode: "rule",
    "log-level": "info",

    profile: {
      "store-selected": true,
      "store-fake-ip": true,
    },

    tun: {
      enable: true,
      stack: "system",
      "dns-hijack": ["any:53", "tcp://any:53"],
      "auto-route": true,
      "auto-detect-interface": true,
    },

    dns: {
      enable: true,
      ipv6: false,
      "enhanced-mode": "fake-ip",
      "fake-ip-range": "198.18.0.1/16",
      "use-hosts": false,
      "respect-rules": true,

      "default-nameserver": ["223.5.5.5", "119.29.29.29"],

      "proxy-server-nameserver": [
        "https://dns.alidns.com/dns-query#DIRECT",
        "https://doh.pub/dns-query#DIRECT",
      ],

      "direct-nameserver": [
        "https://dns.alidns.com/dns-query#DIRECT",
        "https://doh.pub/dns-query#DIRECT",
      ],
      "direct-nameserver-follow-policy": true,

      nameserver: [
        "https://cloudflare-dns.com/dns-query#Proxy",
        "https://dns.google/dns-query#Proxy",
      ],

      "nameserver-policy": {
        "geosite:private": ["223.5.5.5", "119.29.29.29"],
        "geosite:cn": [
          "https://dns.alidns.com/dns-query#DIRECT",
          "https://doh.pub/dns-query#DIRECT",
        ],
        "geosite:geolocation-cn": [
          "https://dns.alidns.com/dns-query#DIRECT",
          "https://doh.pub/dns-query#DIRECT",
        ],
        "+.cn": [
          "https://dns.alidns.com/dns-query#DIRECT",
          "https://doh.pub/dns-query#DIRECT",
        ],
      },

      // 排除以下域名走 fake-ip：本地域、NTP 对时、Windows 联网检测，避免对时失败/误报“无 Internet”。
      "fake-ip-filter": [
        "*.lan",
        "*.local",
        "*.localdomain",
        "*.home.arpa",
        "localhost.ptlogin2.qq.com",
        "time.*.com",
        "time.*.gov",
        "ntp.*.com",
        "*.ntp.org",
        "*.msftconnecttest.com",
        "*.msftncsi.com",
      ],
    },

    "proxy-groups": [
      {
        name: "Proxy",
        type: "select",
        proxies: ["Auto", "DIRECT", ...usableNodes],
      },
      {
        name: "Auto",
        type: "url-test",
        proxies: usableNodes,
        url: "http://www.gstatic.com/generate_204",
        interval: 300,
        tolerance: 50,
        lazy: true,
      },
    ],

    rules: [
      "DOMAIN,clash.razord.top,DIRECT",
      "DOMAIN,yacd.metacubex.one,DIRECT",

      "DOMAIN-KEYWORD,httpdns,REJECT",
      "DOMAIN-SUFFIX,dnspod.cn,REJECT",

      "GEOSITE,private,DIRECT",
      "GEOIP,private,DIRECT,no-resolve",

      "GEOSITE,geolocation-!cn,Proxy",

      "GEOSITE,cn,DIRECT",
      "GEOSITE,geolocation-cn,DIRECT",
      "GEOIP,CN,DIRECT,no-resolve",

      "MATCH,Proxy",
    ],
  });

  delete config["proxy-providers"];

  return config;
}
