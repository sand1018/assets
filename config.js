// 生成 mihomo 配置：保留 SubStore 订阅节点，只覆写 DNS、TUN、策略组和规则。
function main(config) {
  config = config || {};

  const proxies = Array.isArray(config.proxies) ? config.proxies : [];
  const nodeNames = collectNodeNames(proxies);
  const hasNodes = nodeNames.length > 0;
  const usableNodes = hasNodes ? nodeNames : [];

  // 测速地址，所有 url-test 组共用。
  const URL_TEST = "http://www.gstatic.com/generate_204";

  // 国内 DoH：国内域名和直连流量使用，强制走 DIRECT。
  const CN_DOH = [
    "https://223.5.5.5/dns-query#DIRECT",
    "https://doh.pub/dns-query#DIRECT",
  ];

  // 国外 DoH：默认解析器使用，走 Final 兜底组。
  // 全部用纯 IP 形式，从源头避开下方对 dns.google / cloudflare-dns.com 的 REJECT 规则，
  // 不再依赖 "#Final" 策略标签的隐式绕过行为来救场（1.1.1.1 / 8.8.8.8 证书 SAN 含对应 IP，TLS 校验正常）。
  const FOREIGN_DOH = [
    "https://1.1.1.1/dns-query#Final",
    "https://1.0.0.1/dns-query#Final",
    "https://8.8.8.8/dns-query#Final",
  ];

  // bootstrap 只解析 DoH 服务器域名，必须是纯 IP。
  const BOOTSTRAP_DNS = ["223.5.5.5", "119.29.29.29"];

  // 手动直连特例：集中管理，避免散落在 rules 中段难维护。
  const MANUAL_DIRECT = [
    "DOMAIN-SUFFIX,lggafw.com,DIRECT",
    "DOMAIN-SUFFIX,tyhmobile.com,DIRECT",
    "DOMAIN-SUFFIX,plexins.com,DIRECT",
    "DOMAIN-SUFFIX,lanhuapp.com,DIRECT",
    "PROCESS-NAME-REGEX,(?i)(uuremote|gameviewer|uuyc|todesk|sunlogin),DIRECT",
  ];

  // 可信 P2P 应用白名单：明确信任、需要真实 IP 打洞的应用，特批直连。
  // ⚠️ 隐私权衡：这会让对应应用的 STUN/打洞流量暴露真实公网 IP，与全局「STUN 强制走代理」的
  //    防泄露设计是有意冲突的特例——仅对这里列出的应用生效，不影响其它 STUN 流量。
  const TRUSTED_P2P = {
    // 进程名：进程规则能兜住发往动态 peer 裸 IP 的 P2P 数据，是覆盖动态 IP 的主要办法。
    //   parsecd.exe — Windows 负责联网的主进程（已核实，C:\Program Files\Parsec\parsecd.exe）。
    //   Parsec      — macOS 上 Parsec.app 的进程名（首字母大写）。⚠️ 切勿用小写 "parsecd"：
    //                 那是 Apple Siri/位置框架的系统守护进程（/usr/libexec/parsecd），与 Parsec 无关，
    //                 误用会放行 Siri 流量且抓不到真正的 Parsec。Mac 上若仍匹配不到，
    //                 请用活动监视器或 mihomo 连接面板确认实际进程名后替换。
    //                 注：跨平台名互不干扰——Windows 上 "Parsec" 匹配不到，macOS 上 "parsecd.exe" 匹配不到。
    processes: ["parsecd.exe", "Parsec"],
    // 域名兜底（平台无关）：进程规则在 UDP 上可能失效时，至少保住信令/STUN 域名（stun.parsec.app、kessel-*）。
    domains: ["parsec.app"],
    // 端口兜底（平台无关，不依赖进程匹配）：strict 模式下进程规则可能漏匹配，端口规则是关键安全网。
    // ⚠️ 生效前提：必须在 Parsec 两端把端口固定下来（Network 标签 → Host Start Port=8000、Client Port=9000，
    //    需重启 Parsec）。若不固定，Parsec 用随机端口，这两行将匹配不到任何流量（无害但失效）。
    udpPorts: ["8000-8009", "9000-9009"],
  };

  // 按节点名关键字归类地区；匹配不到节点的地区组自动剔除，避免空组报错。
  const regionDefs = [
    { name: "香港", re: /香港|🇭🇰|Hong\s?Kong|(^|[^a-z])hk([^a-z]|$)/i },
    { name: "台湾", re: /台湾|台灣|🇹🇼|Taiwan|(^|[^a-z])tw([^a-z]|$)/i },
    { name: "日本", re: /日本|东京|大阪|🇯🇵|Japan|(^|[^a-z])jp([^a-z]|$)/i },
    { name: "新加坡", re: /新加坡|狮城|獅城|🇸🇬|Singapore|(^|[^a-z])sg([^a-z]|$)/i },
    { name: "美国", re: /美国|美國|🇺🇸|United\s?States|America|(^|[^a-z])(us|usa)([^a-z]|$)/i },
    { name: "韩国", re: /韩国|韓國|首尔|🇰🇷|Korea|(^|[^a-z])kr([^a-z]|$)/i },
  ];
  const regionGroups = buildRegionGroups(regionDefs, nodeNames);
  const regionNames = collectRegionNames(regionGroups);

  // MetaCubeX/meta-rules-dat 的 meta 分支：mihomo 官方维护，每日更新。
  const RS_PREFIX =
    "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo";

  Object.assign(config, {
    ipv6: false,
    mode: "rule",
    "log-level": "info",
    "tcp-concurrent": true,

    // 统一延迟：剔除握手开销，url-test 测出的延迟更接近真实体感，Auto 组选节点更准。
    "unified-delay": true,

    // 进程匹配模式：strict 仅在判断可能用到进程规则时才查进程，开销略低；
    // 代价是部分连接会被判定"用不到进程规则"而跳过查找，导致 MANUAL_DIRECT 的 todesk/向日葵
    // 与 TRUSTED_P2P 的 Parsec 进程规则可能间歇漏匹配。若需进程规则稳定生效请改回 "always"；
    // 若坚持 strict，建议 Parsec 改用 TRUSTED_P2P.udpPorts 端口兜底（不依赖进程匹配）。
    "find-process-mode": "strict",

    profile: {
      "store-selected": true,
      // 缓存 fake-ip 映射以加速启动；注意：改动下方 fake-ip-filter 后需手动清一次 fake-ip 缓存，
      // 否则新加入 filter 的域名仍可能命中旧映射、走错路径。
      "store-fake-ip": true,
    },

    // 域名嗅探：fake-ip 下兜底，从 TLS SNI / HTTP Host 还原域名。
    sniffer: {
      enable: true,
      "force-dns-mapping": true,
      "parse-pure-ip": true,
      "override-destination": false,
      sniff: {
        HTTP: { ports: [80, "8080-8880"], "override-destination": true },
        TLS: { ports: [443, 8443] },
      },
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

      // 解析代理节点域名，打破 respect-rules 的循环依赖。
      "proxy-server-nameserver": CN_DOH,

      // 直连流量解析：国内 DoH。
      "direct-nameserver": CN_DOH,
      "direct-nameserver-follow-policy": false,

      // 默认解析器：国外 DoH 经 Final，国内域名由 nameserver-policy 指回 CN_DOH。
      nameserver: FOREIGN_DOH,

      "nameserver-policy": {
        "rule-set:private": ["system"],
        "rule-set:cn": CN_DOH,
        "+.cn": CN_DOH,
      },

      // 不再放通用 +.stun.*，避免浏览器 WebRTC/STUN 丢失 fake-ip 域名上下文。
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
        "*.stun.playstation.net",
        "*.srv.nintendo.net",
        "+.push.apple.com",
        "*.battle.net",
        "*.battlenet.com.cn",
      ],
    },

    "rule-providers": {
      private: buildSiteProvider(RS_PREFIX, "private"),
      privateip: buildIpProvider(RS_PREFIX, "private"),
      stun: buildSiteProvider(RS_PREFIX, "category-stun"),
      ai: buildSiteProvider(RS_PREFIX, "category-ai-!cn"),
      apple: buildSiteProvider(RS_PREFIX, "apple"),
      microsoft: buildSiteProvider(RS_PREFIX, "microsoft"),
      netflix: buildSiteProvider(RS_PREFIX, "netflix"),
      disney: buildSiteProvider(RS_PREFIX, "disney"),
      youtube: buildSiteProvider(RS_PREFIX, "youtube"),
      spotify: buildSiteProvider(RS_PREFIX, "spotify"),
      proxy: buildSiteProvider(RS_PREFIX, "geolocation-!cn"),
      cn: buildSiteProvider(RS_PREFIX, "cn"),
      cnip: buildIpProvider(RS_PREFIX, "cn"),
      telegramip: buildIpProvider(RS_PREFIX, "telegram"),
    },

    "proxy-groups": hasNodes
      ? buildProxyGroups(URL_TEST, usableNodes, regionGroups, regionNames)
      : buildRejectGroups(),

    rules: [
      "DOMAIN,clash.razord.top,DIRECT",
      "DOMAIN,yacd.metacubex.one,DIRECT",

      "DOMAIN-KEYWORD,httpdns,REJECT",
      "DOMAIN-SUFFIX,dnspod.cn,REJECT",

      // 拦截第三方公共 DoH，防止浏览器/系统内置 DoH 绕过本地分流与 DNS。
      "DOMAIN-SUFFIX,dns.google,REJECT",
      "DOMAIN-SUFFIX,cloudflare-dns.com,REJECT",
      "DOMAIN-SUFFIX,dns.quad9.net,REJECT",
      "DOMAIN-SUFFIX,doh.opendns.com,REJECT",
      "DOMAIN-SUFFIX,dns.adguard-dns.com,REJECT",
      "DOMAIN-SUFFIX,dns.nextdns.io,REJECT",

      "RULE-SET,private,DIRECT",
      "RULE-SET,privateip,DIRECT,no-resolve",

      // 可信 P2P 应用特批直连：必须位于下方 STUN 代理规则与 UDP/443 REJECT 之前，
      // 否则 Parsec 等应用的打洞流量会被全局规则截走。
      ...buildTrustedP2PRules(TRUSTED_P2P),

      // WebRTC/STUN/TURN 前置，避免先命中国内 IP 直连规则导致真实公网 IP 暴露。
      // 已移除 DOMAIN-KEYWORD,stun（子串匹配会误伤 stunning-* 等无关域名），RULE-SET,stun 已覆盖真实 STUN 域名。
      "RULE-SET,stun,Proxy",
      "AND,((NETWORK,UDP),(DST-PORT,3478)),Proxy",
      "AND,((NETWORK,UDP),(DST-PORT,19302)),Proxy",
      "AND,((NETWORK,UDP),(DST-PORT,5349)),Proxy",

      // 拦截 QUIC(UDP/443)：封 DoH3，并迫使 YouTube/Google 等回落 TCP。
      "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",

      "RULE-SET,ai,AI",
      "RULE-SET,netflix,流媒体",
      "RULE-SET,disney,流媒体",
      "RULE-SET,youtube,流媒体",
      "RULE-SET,spotify,流媒体",
      "RULE-SET,telegramip,Telegram,no-resolve",
      "RULE-SET,apple,Apple",
      "RULE-SET,microsoft,Microsoft",

      // 手动特例：强制直连（集中维护于顶部 MANUAL_DIRECT）。
      ...MANUAL_DIRECT,

      "RULE-SET,proxy,Proxy",

      // 规则集首次下载失败时，保证 .cn 域名仍然直连。
      "DOMAIN-SUFFIX,cn,DIRECT",
      "RULE-SET,cn,DIRECT",
      "RULE-SET,cnip,DIRECT,no-resolve",

      // GeoIP 中国段改走 Final，避免边界段误判时直接泄露。
      "GEOIP,CN,Final,no-resolve",

      "MATCH,Final",
    ],
  });

  delete config["proxy-providers"];

  return config;
}

// 收集订阅节点名称：只保留有 name 的代理节点。
function collectNodeNames(proxies) {
  const names = [];
  for (const proxy of proxies) {
    if (proxy && proxy.name) {
      names.push(proxy.name);
    }
  }
  return names;
}

// 构建可信 P2P 应用的直连规则：进程名 + 域名 + 可选端口，三类分别展开为 DIRECT 规则。
function buildTrustedP2PRules(p2p) {
  const rules = [];
  for (const proc of p2p.processes) {
    rules.push(`PROCESS-NAME,${proc},DIRECT`);
  }
  for (const domain of p2p.domains) {
    rules.push(`DOMAIN-SUFFIX,${domain},DIRECT`);
  }
  // 端口兜底用 AND 组合 UDP + 目标端口，绕过 PROCESS-NAME 对 UDP 可能失效的已知问题。
  for (const portRange of p2p.udpPorts) {
    rules.push(`AND,((NETWORK,UDP),(DST-PORT,${portRange})),DIRECT`);
  }
  return rules;
}

// 构建地区分组：仅返回至少匹配到一个节点的地区。
function buildRegionGroups(regionDefs, nodeNames) {
  const groups = [];
  for (const region of regionDefs) {
    const nodes = [];
    for (const nodeName of nodeNames) {
      if (region.re.test(nodeName)) {
        nodes.push(nodeName);
      }
    }
    if (nodes.length > 0) {
      groups.push({ name: region.name, nodes });
    }
  }
  return groups;
}

// 收集地区组名称：用于策略组引用。
function collectRegionNames(regionGroups) {
  const names = [];
  for (const region of regionGroups) {
    names.push(region.name);
  }
  return names;
}

// 生成 domain 类型的 rule-provider 配置。
function buildSiteProvider(prefix, name) {
  return {
    type: "http",
    behavior: "domain",
    format: "mrs",
    interval: 86400,
    path: `./ruleset/geosite-${name}.mrs`,
    url: `${prefix}/geosite/${name}.mrs`,
  };
}

// 生成 ipcidr 类型的 rule-provider 配置。
function buildIpProvider(prefix, name) {
  return {
    type: "http",
    behavior: "ipcidr",
    format: "mrs",
    interval: 86400,
    path: `./ruleset/geoip-${name}.mrs`,
    url: `${prefix}/geoip/${name}.mrs`,
  };
}

// 构建有节点时的策略组：主代理组保留 DIRECT，便于手动切换。
function buildProxyGroups(urlTest, usableNodes, regionGroups, regionNames) {
  const groups = [
    {
      name: "Proxy",
      type: "select",
      proxies: ["Auto", ...regionNames, "DIRECT", ...usableNodes],
    },
    {
      name: "Auto",
      type: "url-test",
      proxies: usableNodes,
      url: urlTest,
      interval: 300,
      tolerance: 50,
      lazy: true,
    },
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
  ];

  for (const region of regionGroups) {
    groups.push({
      name: region.name,
      type: "url-test",
      proxies: region.nodes,
      url: urlTest,
      interval: 300,
      tolerance: 50,
      lazy: true,
    });
  }

  groups.push({
    name: "Final",
    type: "select",
    proxies: ["Proxy", "Auto", ...regionNames, ...usableNodes],
  });

  return groups;
}

// 构建无节点时的策略组：全部 fail-closed 到 REJECT。
function buildRejectGroups() {
  return [
    { name: "Proxy", type: "select", proxies: ["REJECT"] },
    { name: "流媒体", type: "select", proxies: ["REJECT"] },
    { name: "AI", type: "select", proxies: ["REJECT"] },
    { name: "Telegram", type: "select", proxies: ["REJECT"] },
    { name: "Apple", type: "select", proxies: ["REJECT"] },
    { name: "Microsoft", type: "select", proxies: ["REJECT"] },
    { name: "Final", type: "select", proxies: ["REJECT"] },
  ];
}
