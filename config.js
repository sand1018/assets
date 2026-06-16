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
  const FOREIGN_DOH = [
    "https://1.1.1.1/dns-query#Final",
    "https://cloudflare-dns.com/dns-query#Final",
    "https://dns.google/dns-query#Final",
  ];

  // bootstrap 只解析 DoH 服务器域名，必须是纯 IP。
  const BOOTSTRAP_DNS = ["223.5.5.5", "119.29.29.29"];

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

    profile: {
      "store-selected": true,
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

      // WebRTC/STUN/TURN 前置，避免先命中国内 IP 直连规则导致真实公网 IP 暴露。
      "RULE-SET,stun,Proxy",
      "DOMAIN-KEYWORD,stun,Proxy",
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

      // 手动特例：强制直连。
      "DOMAIN-SUFFIX,lggafw.com,DIRECT",
      "DOMAIN-SUFFIX,tyhmobile.com,DIRECT",
      "DOMAIN-SUFFIX,plexins.com,DIRECT",
      "DOMAIN-SUFFIX,lanhuapp.com,DIRECT",
      "PROCESS-NAME-REGEX,(?i)(uuremote|gameviewer|uuyc|todesk|sunlogin),DIRECT",

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
