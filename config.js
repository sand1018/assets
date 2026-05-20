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

      "fake-ip-filter": [
        "*.lan",
        "*.local",
        "localhost.ptlogin2.qq.com",
      ],
    },

    "proxy-groups": [
      {
        name: "Proxy",
        type: "select",
        proxies: ["Auto", "Fallback", "DIRECT", ...usableNodes],
      },
      {
        name: "Auto",
        type: "url-test",
        proxies: usableNodes,
        url: "http://www.gstatic.com/generate_204",
        interval: 300,
        tolerance: 50,
      },
      {
        name: "Fallback",
        type: "fallback",
        proxies: usableNodes,
        url: "http://www.gstatic.com/generate_204",
        interval: 300,
      },
    ],

    rules: [
      "DOMAIN,clash.razord.top,DIRECT",
      "DOMAIN,yacd.metacubex.one,DIRECT",

      "DOMAIN-KEYWORD,httpdns,REJECT",
      "DOMAIN-SUFFIX,dnspod.cn,REJECT",
      "DOMAIN-SUFFIX,httpdns.alicdn.com,REJECT",
      "DOMAIN-SUFFIX,httpdns.aliyuncs.com,REJECT",
      "DOMAIN-SUFFIX,httpdns.baidu.com,REJECT",
      "DOMAIN-SUFFIX,httpdns.qq.com,REJECT",
      "DOMAIN-SUFFIX,httpdns.weixin.qq.com,REJECT",

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
