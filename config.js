// 配置入口：保留 SubStore 生成的节点，只覆写 DNS、TUN、策略组和规则。
function main(config) {
  config = config || {};

  const proxies = Array.isArray(config.proxies) ? config.proxies : [];
  const nodeNames = proxies.map((proxy) => proxy.name).filter(Boolean);
  const usableNodes = nodeNames.length ? nodeNames : ["REJECT"];

  // 测速地址，所有 url-test 组共用。
  const URL_TEST = "http://www.gstatic.com/generate_204";

  // 按节点名关键字归类地区；匹配不到节点的地区组自动剔除，避免空组报错。
  const regionDefs = [
    { name: "香港", re: /香港|HK|Hong\s?Kong|🇭🇰/i },
    { name: "台湾", re: /台湾|台灣|TW|Taiwan|🇹🇼/i },
    { name: "日本", re: /日本|东京|大阪|JP|Japan|🇯🇵/i },
    { name: "新加坡", re: /新加坡|狮城|獅城|SG|Singapore|🇸🇬/i },
    { name: "美国", re: /美国|美國|US|United\s?States|America|🇺🇸/i },
    { name: "韩国", re: /韩国|韓國|首尔|KR|Korea|🇰🇷/i },
  ];
  const regionGroups = regionDefs
    .map((d) => ({ name: d.name, nodes: nodeNames.filter((n) => d.re.test(n)) }))
    .filter((r) => r.nodes.length);
  const regionNames = regionGroups.map((r) => r.name);

  // DustinWin/ruleset_geodata 规则集下载前缀（国内镜像 ghfast.top）。
  const RS_PREFIX =
    "https://ghfast.top/https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset";
  // 生成单个 rule-provider 配置。
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
    mode: "rule",
    "log-level": "info",

    profile: {
      "store-selected": true,
      "store-fake-ip": true,
    },

    tun: {
      enable: true,
      stack: "system",
      "dns-hijack": ["any:53", "tcp://any:53", "tcp://any:853", "udp://any:853"],
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

    // DustinWin 规则集：域名类 behavior=domain，IP 类 behavior=ipcidr。
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

    "proxy-groups": [
      // 总开关，默认 Auto，可手选地区组或具体节点。
      {
        name: "Proxy",
        type: "select",
        proxies: ["Auto", ...regionNames, "DIRECT", ...usableNodes],
      },
      // 全部节点测速选最快，未被使用时暂停测速。
      {
        name: "Auto",
        type: "url-test",
        proxies: usableNodes,
        url: URL_TEST,
        interval: 300,
        tolerance: 50,
        lazy: true,
      },
      // 分场景组，默认跟随 Proxy，可手动切到指定地区。
      {
        name: "流媒体",
        type: "select",
        proxies: ["Proxy", "Auto", ...regionNames, "DIRECT"],
      },
      {
        name: "AI",
        type: "select",
        proxies: ["Proxy", ...regionNames, "Auto", "DIRECT"],
      },
      {
        name: "Telegram",
        type: "select",
        proxies: ["Proxy", ...regionNames, "Auto", "DIRECT"],
      },
      // 各地区组（仅生成有节点的地区）。
      ...regionGroups.map((r) => ({
        name: r.name,
        type: "url-test",
        proxies: r.nodes,
        url: URL_TEST,
        interval: 300,
        tolerance: 50,
        lazy: true,
      })),
    ],

    rules: [
      "DOMAIN,clash.razord.top,DIRECT",
      "DOMAIN,yacd.metacubex.one,DIRECT",

      "DOMAIN-KEYWORD,httpdns,REJECT",
      "DOMAIN-SUFFIX,dnspod.cn,REJECT",

      "RULE-SET,private,DIRECT",
      "RULE-SET,privateip,DIRECT,no-resolve",

      "RULE-SET,ai,AI",
      "RULE-SET,media,流媒体",
      "RULE-SET,telegramip,Telegram,no-resolve",

      "RULE-SET,proxy,Proxy",

      "RULE-SET,cn,DIRECT",
      "GEOSITE,cn,DIRECT",
      "RULE-SET,cnip,DIRECT,no-resolve",
      "GEOIP,CN,DIRECT,no-resolve",

      "MATCH,Proxy",
    ],
  });

  delete config["proxy-providers"];

  return config;
}
