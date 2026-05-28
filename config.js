// 配置入口：保留 SubStore 生成的节点，只覆写 DNS、TUN、策略组和规则。
function main(config) {
  config = config || {};

  const proxies = Array.isArray(config.proxies) ? config.proxies : [];
  const nodeNames = proxies.map((proxy) => proxy.name).filter(Boolean);
  const hasNodes = nodeNames.length > 0;
  const usableNodes = hasNodes ? nodeNames : [];

  // 测速地址，所有 url-test 组共用。
  const URL_TEST = "http://www.gstatic.com/generate_204";

  // 国内 DoH：国内域名和直连流量使用，强制走 DIRECT。
  // 223.5.5.5 是 IP 字面量，doh.pub 由 default-nameserver bootstrap。
  const CN_DOH = [
    "https://223.5.5.5/dns-query#DIRECT", // 阿里，IP 字面量（零 bootstrap）
    "https://doh.pub/dns-query#DIRECT", // 腾讯，域名（其 IP 证书不确定，用域名稳妥）
  ];

  // 国外 DoH：默认解析器使用，强制走不含 DIRECT 的 Final（Final 默认 Auto，等价行为；
  // 且节点为空时 Final 退化为 REJECT 仍存在，避免引用不存在的 Auto 组导致启动校验失败）。
  // 首项是 IP 字面量 DoH，无需 bootstrap，作为冷启动应急，打破 FOREIGN_DOH 自身的域名解析依赖。
  const FOREIGN_DOH = [
    "https://1.1.1.1/dns-query#Final",
    "https://cloudflare-dns.com/dns-query#Final",
    "https://dns.google/dns-query#Final",
  ];

  // bootstrap 只解析 DoH 服务器域名，必须是纯 IP（mihomo 限制：不接受 DoH/DoT 格式）。
  const BOOTSTRAP_DNS = ["223.5.5.5", "119.29.29.29"];

  // 按节点名关键字归类地区；匹配不到节点的地区组自动剔除，避免空组报错。
  // 2 字母代码用“非字母边界”包裹，避免 Plus/Cluster/Network 等英文词被误匹配（不用 lookbehind，兼容各 JS 引擎）。
  const regionDefs = [
    { name: "香港", re: /香港|🇭🇰|Hong\s?Kong|(^|[^a-z])hk([^a-z]|$)/i },
    { name: "台湾", re: /台湾|台灣|🇹🇼|Taiwan|(^|[^a-z])tw([^a-z]|$)/i },
    { name: "日本", re: /日本|东京|大阪|🇯🇵|Japan|(^|[^a-z])jp([^a-z]|$)/i },
    { name: "新加坡", re: /新加坡|狮城|獅城|🇸🇬|Singapore|(^|[^a-z])sg([^a-z]|$)/i },
    { name: "美国", re: /美国|美國|🇺🇸|United\s?States|America|(^|[^a-z])(us|usa)([^a-z]|$)/i },
    { name: "韩国", re: /韩国|韓國|首尔|🇰🇷|Korea|(^|[^a-z])kr([^a-z]|$)/i },
  ];
  const regionGroups = regionDefs
    .map((d) => ({ name: d.name, nodes: nodeNames.filter((n) => d.re.test(n)) }))
    .filter((r) => r.nodes.length);
  const regionNames = regionGroups.map((r) => r.name);

  // DustinWin/ruleset_geodata 规则集下载前缀（国内镜像 ghfast.top）。
  // 注意：这是单一镜像，挂了会导致首次加载失败/规则缺失（进而 MATCH 兜底），如遇问题可换备用前缀。
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

    // 域名嗅探：fake-ip 下兜底——对“直接拿 IP 发起、不查 DNS”的连接，从 TLS SNI / HTTP Host 还原域名，
    // 否则这类流量只能落到 GEOIP/cnip 兜底，命中不了域名规则。
    sniffer: {
      enable: true,
      "force-dns-mapping": true,
      "parse-pure-ip": true,
      "override-destination": false,
      sniff: {
        HTTP: { ports: [80, "8080-8880"], "override-destination": true },
        TLS: { ports: [443, 8443] },
      },
      // 仅排除"嗅探后会出问题的少数服务"，其余 Apple/Microsoft 域名仍允许嗅探还原，
      // 以便准确命中下方新增的 Apple/Microsoft 分组。
      "skip-domain": ["+.push.apple.com", "+.teams.microsoft.com"],
    },

    tun: {
      enable: true,
      stack: "system",
      "dns-hijack": ["any:53", "tcp://any:853", "udp://any:853"],
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

      // bootstrap 只解析 DoH 服务器域名，不承载普通域名查询。
      "default-nameserver": BOOTSTRAP_DNS,

      // 解析代理节点域名（DIRECT，打破 respect-rules 的循环依赖）。
      "proxy-server-nameserver": CN_DOH,

      // 直连流量解析：国内 DoH。
      "direct-nameserver": CN_DOH,
      "direct-nameserver-follow-policy": false,

      // 默认解析器：国外 DoH 经 Auto 代理，国内域名由 nameserver-policy 指回 CN_DOH。
      nameserver: FOREIGN_DOH,

      // policy 与规则体系统一用 rule-set 引用（不依赖内置 GeoSite 数据库）。
      "nameserver-policy": {
        "rule-set:private": ["223.5.5.5#DIRECT", "119.29.29.29#DIRECT"],
        "rule-set:cn": CN_DOH,
        "+.cn": CN_DOH,
      },

      // 排除以下域名走 fake-ip：本地域、对时、联网检测、STUN/推送/游戏（需真实 IP），
      // 避免对时失败/误报“无 Internet”/打洞与推送异常。
      "fake-ip-filter": [
        "*.lan",
        "*.local",
        "*.localdomain",
        "*.home.arpa",
        "localhost.ptlogin2.qq.com",
        "time.*.com",
        "time.*.gov",
        "time.*.apple.com",
        "ntp.*.com",
        "+.ntp.org",
        "*.msftconnecttest.com",
        "*.msftncsi.com",
        "+.ocsp.*",
        "+.crl.*",
        "+.stun.*",
        "*.stun.playstation.net",
        "*.srv.nintendo.net",
        "+.push.apple.com",
        "*.battle.net",
        "*.battlenet.com.cn",
      ],
    },

    // DustinWin 规则集：域名类 behavior=domain，IP 类 behavior=ipcidr。
    "rule-providers": {
      private: mrs("private", "domain"),
      privateip: mrs("privateip", "ipcidr"),
      ai: mrs("ai", "domain"),
      media: mrs("media", "domain"),
      apple: mrs("apple", "domain"),
      microsoft: mrs("microsoft", "domain"),
      proxy: mrs("proxy", "domain"),
      cn: mrs("cn", "domain"),
      cnip: mrs("cnip", "ipcidr"),
      telegramip: mrs("telegramip", "ipcidr"),
    },

    // 节点订阅为空时，所有策略组退化为 REJECT，避免 url-test 在 REJECT 上反复测速报错，
    // 同时保证 fail-closed：没有节点时绝不直连，宁可断网也不泄露隐私。
    "proxy-groups": hasNodes ? [
      // 总开关，默认 Auto，可手选地区组或具体节点。含 DIRECT 方便整体切直连，国外 DNS 不跟随此组。
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
      {
        name: "Apple",
        type: "select",
        proxies: ["Proxy", ...regionNames, "Auto", "DIRECT"],
      },
      {
        name: "Microsoft",
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
      // 严格兜底组放在最后：专供 MATCH 与 GEOIP 等"不确定"规则使用，永不含 DIRECT/REJECT。
      // 目的：即便 Proxy 被误切到 DIRECT，或 GeoIP/规则集出现误判，兜底流量也不会落到直连导致隐私泄露。
      {
        name: "Final",
        type: "select",
        proxies: ["Auto", ...regionNames, ...usableNodes],
      },
    ] : [
      { name: "Proxy", type: "select", proxies: ["REJECT"] },
      { name: "流媒体", type: "select", proxies: ["REJECT"] },
      { name: "AI", type: "select", proxies: ["REJECT"] },
      { name: "Telegram", type: "select", proxies: ["REJECT"] },
      { name: "Apple", type: "select", proxies: ["REJECT"] },
      { name: "Microsoft", type: "select", proxies: ["REJECT"] },
      { name: "Final", type: "select", proxies: ["REJECT"] },
    ],

    rules: [
      "DOMAIN,clash.razord.top,DIRECT",
      "DOMAIN,yacd.metacubex.one,DIRECT",

      "DOMAIN-KEYWORD,httpdns,REJECT",
      "DOMAIN-SUFFIX,dnspod.cn,REJECT",

      // 拦截第三方公共 DoH，防止浏览器/系统内置 DoH 绕过本地分流与 DNS。
      // 注：仅对“按域名解析”的 DoH 生效；对硬编码 IP 的浏览器 DoH 需配合下方 QUIC 拦截。可按需增删。
      "DOMAIN-SUFFIX,dns.google,REJECT",
      "DOMAIN-SUFFIX,cloudflare-dns.com,REJECT",
      "DOMAIN-SUFFIX,dns.quad9.net,REJECT",
      "DOMAIN-SUFFIX,doh.opendns.com,REJECT",
      "DOMAIN-SUFFIX,dns.adguard-dns.com,REJECT",
      "DOMAIN-SUFFIX,dns.nextdns.io,REJECT",

      "RULE-SET,private,DIRECT",
      "RULE-SET,privateip,DIRECT,no-resolve",

      // 拦截 QUIC(UDP/443)：封 DoH3，并迫使 YouTube/Google 等回落 TCP，分流更准、代理更稳。
      // 如需保留 QUIC 性能可删除此条。
      "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",

      "RULE-SET,ai,AI",
      "RULE-SET,media,流媒体",
      "RULE-SET,telegramip,Telegram,no-resolve",
      "RULE-SET,apple,Apple",
      "RULE-SET,microsoft,Microsoft",

      // 手动特例：强制直连（按需保留/删除）。
      "DOMAIN-SUFFIX,lggafw.com,DIRECT",

      "RULE-SET,proxy,Proxy",

      // 规则集首次下载失败时，保证 .cn 域名仍然直连。
      "DOMAIN-SUFFIX,cn,DIRECT",
      "RULE-SET,cn,DIRECT",
      "RULE-SET,cnip,DIRECT,no-resolve",
      // GeoIP 数据库存在边界段误判（CDN/Anycast/HK 段误标 CN 等），
      // 命中即直连有隐私泄露风险，故改走 Final 严格兜底而非 DIRECT。
      "GEOIP,CN,Final,no-resolve",

      // 兜底改 Final 而非 Proxy：即便 Proxy 被误切到 DIRECT，
      // 未明确归类的流量也不会泄露。
      "MATCH,Final",
    ],
  });

  delete config["proxy-providers"];

  return config;
}
