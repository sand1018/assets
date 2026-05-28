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

  // 国外 DoH：默认解析器使用，走 Final 兜底组（Final 跟随 Proxy 的选择，逻辑统一；
  // 节点为空时 Final 退化为 REJECT 仍存在，避免引用不存在的组导致启动校验失败）。
  // 已知权衡：Proxy 一旦被切到 DIRECT，国外 DoH 也会跟随直连——这是上层"Final 默认 Proxy"的代价。
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

  // MetaCubeX/meta-rules-dat 的 meta 分支：mihomo 官方维护，每日更新，
  // 覆盖 v2fly geosite/geoip 全量（geosite 1800+，含 apple/microsoft 等 DustinWin 缺失项）。
  // 经 jsdelivr CDN 分发（Cloudflare/Fastly 底座，比免费公共 GitHub 镜像更稳）；
  // 国内偶发被屏蔽，备选可换 https://ghfast.top/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo
  const RS_PREFIX =
    "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo";
  // site(): geosite/<name>.mrs (domain)；ip(): geoip/<name>.mrs (ipcidr)。
  const site = (name) => ({
    type: "http",
    behavior: "domain",
    format: "mrs",
    interval: 86400,
    path: `./ruleset/geosite-${name}.mrs`,
    url: `${RS_PREFIX}/geosite/${name}.mrs`,
  });
  const ip = (name) => ({
    type: "http",
    behavior: "ipcidr",
    format: "mrs",
    interval: 86400,
    path: `./ruleset/geoip-${name}.mrs`,
    url: `${RS_PREFIX}/geoip/${name}.mrs`,
  });

  Object.assign(config, {
    ipv6: false,
    mode: "rule",
    "log-level": "info",
    // 并发尝试 IPv4/IPv6 与多候选解析结果，首包更快（mihomo 默认 false）。
    "tcp-concurrent": true,

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
      // private 集里的 *.lan/*.local/*.home.arpa 等公网 DNS 必返 NXDOMAIN，
      // 交给系统/路由器 DNS 处理，避免一轮无用的 DoH 往返。
      "nameserver-policy": {
        "rule-set:private": ["system"],
        "rule-set:cn": CN_DOH,
        "+.cn": CN_DOH,
      },

      // 排除以下域名走 fake-ip：本地域、对时、联网检测、STUN/推送/游戏（需真实 IP），
      // 避免对时失败/误报“无 Internet”/打洞与推送异常。
      "fake-ip-filter": [
        "+.lan",
        "+.local",
        "+.localdomain",
        "+.home.arpa",
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

    // MetaCubeX rule-providers。语义平移要点：
    //   ai    → category-ai-!cn（境外 AI 全集，比单一 ai 更广）
    //   media → 无聚合，拆为 netflix/disney/youtube/spotify；其他境外流媒体由 proxy(geolocation-!cn) 兜住
    //   proxy → geolocation-!cn（境外域名全集，替代 DustinWin 的 proxy）
    "rule-providers": {
      private: site("private"),
      privateip: ip("private"),
      ai: site("category-ai-!cn"),
      apple: site("apple"),
      microsoft: site("microsoft"),
      netflix: site("netflix"),
      disney: site("disney"),
      youtube: site("youtube"),
      spotify: site("spotify"),
      proxy: site("geolocation-!cn"),
      cn: site("cn"),
      cnip: ip("cn"),
      telegramip: ip("telegram"),
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
        proxies: ["Proxy", "Auto", ...regionNames, "DIRECT", ...usableNodes],
      },
      {
        name: "AI",
        type: "select",
        proxies: ["Proxy", ...regionNames, "Auto", "DIRECT", ...usableNodes],
      },
      {
        name: "Telegram",
        type: "select",
        proxies: ["Proxy", ...regionNames, "Auto", "DIRECT", ...usableNodes],
      },
      {
        name: "Apple",
        type: "select",
        proxies: ["Proxy", ...regionNames, "Auto", "DIRECT", ...usableNodes],
      },
      {
        name: "Microsoft",
        type: "select",
        proxies: ["Proxy", ...regionNames, "Auto", "DIRECT", ...usableNodes],
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
      // 兜底组放在最后：专供 MATCH 与 GEOIP 等"不确定"规则使用，本身不含 DIRECT/REJECT。
      // 默认跟随 Proxy，便于"一个开关切所有"；已知权衡：Proxy 被切到 DIRECT 时 Final 也会跟着直连。
      {
        name: "Final",
        type: "select",
        proxies: ["Proxy", "Auto", ...regionNames, ...usableNodes],
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
      // 流媒体细分（MetaCubeX 无聚合 media 集）；其他境外流媒体由下方 RULE-SET,proxy 兜住。
      "RULE-SET,netflix,流媒体",
      "RULE-SET,disney,流媒体",
      "RULE-SET,youtube,流媒体",
      "RULE-SET,spotify,流媒体",
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
