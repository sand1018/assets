// 生成 mihomo 配置：保留 SubStore 订阅节点，只覆写 DNS、TUN、策略组和规则。
function main(config) {
  config = config || {};

  const rawProxies = Array.isArray(config.proxies) ? config.proxies : [];
  // 去掉官网/流量/到期等说明项，避免污染 url-test 与策略组。
  const proxies = rawProxies.filter(
    (proxy) => proxy && proxy.name && !isNonNodeName(proxy.name),
  );
  config.proxies = proxies;
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

  // 策略组名：纯文字；图标由 proxy-groups 的 icon 字段提供（面板需支持，如 metacubexd/Verge）。
  const G = {
    select: "节点选择",
    auto: "自动选择",
    stream: "流媒体",
    ai: "AI",
    telegram: "Telegram",
    apple: "Apple",
    microsoft: "Microsoft",
    // 仅国外个人网盘；国内盘走下方 cn 直连，不进本组。
    cloud: "网盘",
    bilibili: "哔哩哔哩",
    game: "游戏",
    final: "漏网之鱼",
  };

  // 游戏平台域名集（MetaCubeX geosite）；挂到 G.game，默认 DIRECT。
  const GAME_SITES = [
    "steam",
    "epicgames",
    "ea",
    "origin",
    "nintendo",
    "playstation",
  ];

  // blackmatrix7 Clash classical 规则：国外网盘域名/进程，挂到 G.cloud。
  // 不含 Baidu/115 等国内盘；不含 Yandex 全站（过宽会把搜索等一并卷进网盘组）。
  const BM_CLASH =
    "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash";
  const CLOUD_RULES = [
    "PikPak",
    "GoogleDrive",
    "MEGA",
    "Dropbox",
    "OneDrive",
    "TeraBox",
    "Dubox",
  ];

  // 国外 DoH：默认解析器使用，跟随「节点选择」总闸。
  // 选节点/自动/地区时经代理出站（无 DNS 真 IP 直出）；选 DIRECT 时与关代理一致，DNS 也直连。
  // 全部用纯 IP 形式，从源头避开下方对 dns.google / cloudflare-dns.com 的 REJECT 规则，
  // 不再依赖策略标签的隐式绕过行为来救场（1.1.1.1 / 8.8.8.8 证书 SAN 含对应 IP，TLS 校验正常）。
  const FOREIGN_DOH = [
    `https://1.1.1.1/dns-query#${G.select}`,
    `https://1.0.0.1/dns-query#${G.select}`,
    `https://8.8.8.8/dns-query#${G.select}`,
  ];

  // bootstrap 只解析 DoH 服务器域名，必须是纯 IP。
  const BOOTSTRAP_DNS = ["223.5.5.5", "119.29.29.29"];

  // 第三方公共 DNS / DoH / DoT 拦截（尽量彻底）：防浏览器/系统 Secure DNS 绕过 fake-ip 分流。
  // 不含 223.5.5.5、119.29.29.29、doh.pub —— 本配置 CN_DOH / bootstrap 自用。
  // 纯 DNS anycast 用 IP 全端口 REJECT；普通网站 HTTP/3 不走这些 IP，可正常分流。
  // 无法穷尽所有自建/商业 DoH；系统侧仍建议关闭 Secure DNS。
  const DOH_BLOCK_SUFFIXES = [
    // Google
    "dns.google",
    "dns.google.com",
    // Cloudflare（含 mozilla/chrome/family/security 等子域）
    "cloudflare-dns.com",
    "one.one.one.one",
    "dns.cloudflare.com",
    // Quad9
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    "dns12.quad9.net",
    "dns13.quad9.net",
    // OpenDNS / Cisco
    "doh.opendns.com",
    "doh.familyshield.opendns.com",
    "doh.sandbox.opendns.com",
    "cisco-udns.com",
    // AdGuard
    "adguard-dns.com",
    "adguard-dns.ru",
    "dns.adguard.com",
    "dns-family.adguard.com",
    "dns-unfiltered.adguard.com",
    // NextDNS / Control D
    "dns.nextdns.io",
    "dns.controld.com",
    // Apple Private Relay / 系统 DoH
    "doh.dns.apple.com",
    "mask.icloud.com",
    "mask-h2.icloud.com",
    "mask.apple-dns.net",
    // 其它常见公共 DoH
    "doh.cleanbrowsing.org",
    "security.cleanbrowsing.org",
    "family.cleanbrowsing.org",
    "adult.cleanbrowsing.org",
    "dns.sb",
    "doh.sb",
    "doh.dns.sb",
    "dns.switch.ch",
    "dns.mullvad.net",
    "adblock.dns.mullvad.net",
    "base.dns.mullvad.net",
    "extended.dns.mullvad.net",
    "family.dns.mullvad.net",
    "all.dns.mullvad.net",
    "wikimedia-dns.org",
    "dns.oszx.co",
    "doh.appliedprivacy.net",
    "doh.libredns.gr",
    "dnsforge.de",
    "ordns.he.net",
    "dns.twnic.tw",
    "doh.360.cn",
    "dns.alidns.com",
    "dns.rubyfish.cn",
    "i.233py.com",
    "dns.aa.net.uk",
    "doh.ffmuc.net",
    "dns.digitale-gesellschaft.ch",
    "odvr.nic.cz",
    "doh.pi-dns.com",
    "dns.pi-dns.com",
    // 故意不拦 doh.pub / 223.5.5.5 / 119.29.29.29：本配置 CN_DOH 与 bootstrap 依赖它们。
  ];

  // 公共递归 DNS 的 anycast IP（专用解析器，非整站 CDN）。全端口 REJECT 以覆盖 DoH2/DoH3/DoT/非常规端口。
  const DOH_BLOCK_IPS = [
    // Cloudflare DNS / 家庭与安全变体
    "1.1.1.1",
    "1.0.0.1",
    "1.1.1.2",
    "1.0.0.2",
    "1.1.1.3",
    "1.0.0.3",
    // Google Public DNS
    "8.8.8.8",
    "8.8.4.4",
    // Quad9
    "9.9.9.9",
    "149.112.112.112",
    "9.9.9.10",
    "149.112.112.10",
    "9.9.9.11",
    "149.112.112.11",
    "9.9.9.12",
    "149.112.112.12",
    "9.9.9.13",
    "149.112.112.13",
    // OpenDNS
    "208.67.222.222",
    "208.67.220.220",
    "208.67.222.123",
    "208.67.220.123",
    "208.67.222.2",
    "208.67.220.2",
    // AdGuard DNS
    "94.140.14.14",
    "94.140.15.15",
    "94.140.14.15",
    "94.140.15.16",
    "94.140.14.140",
    "94.140.14.141",
    // CleanBrowsing
    "185.228.168.9",
    "185.228.169.9",
    "185.228.168.10",
    "185.228.169.11",
    "185.228.168.168",
    "185.228.169.168",
    // Control D
    "76.76.2.0",
    "76.76.10.0",
    "76.76.2.1",
    "76.76.10.1",
    "76.76.2.2",
    "76.76.10.2",
    "76.76.2.3",
    "76.76.10.3",
    "76.76.2.4",
    "76.76.10.4",
    "76.76.2.5",
    "76.76.10.5",
    // Comodo Secure DNS
    "8.26.56.26",
    "8.20.247.20",
    // Yandex DNS
    "77.88.8.8",
    "77.88.8.1",
    "77.88.8.2",
    "77.88.8.3",
    "77.88.8.88",
    "77.88.8.7",
    // DNS.SB
    "185.222.222.222",
    "185.184.222.222",
    // LibreDNS
    "116.202.176.26",
    "116.203.70.27",
    // Mullvad DNS
    "194.242.2.2",
    "194.242.2.3",
    "194.242.2.4",
    "194.242.2.5",
    "194.242.2.6",
    "194.242.2.9",
    // NextDNS 公共 anycast（账号专用 IP 无法穷尽，靠域名规则）
    "45.90.28.0",
    "45.90.30.0",
    "45.90.28.167",
    "45.90.30.167",
    // Level3 / CenturyLink
    "209.244.0.3",
    "209.244.0.4",
    // Verisign Public DNS
    "64.6.64.6",
    "64.6.65.6",
    // Neustar / UltraDNS
    "156.154.70.1",
    "156.154.71.1",
    "156.154.70.2",
    "156.154.71.2",
    "156.154.70.3",
    "156.154.71.3",
    "156.154.70.4",
    "156.154.71.4",
    "156.154.70.5",
    "156.154.71.5",
    // Quad101 (TWNIC)
    "101.101.101.101",
    "101.102.103.104",
    // OpenNIC 常用
    "192.71.245.208",
    "94.247.43.254",
    // Switch.ch
    "130.59.31.248",
    "130.59.31.251",
  ];

  // 手动直连特例：集中管理，避免散落在 rules 中段难维护。
  const MANUAL_DIRECT = [
    "DOMAIN-SUFFIX,lggafw.com,DIRECT",
    "DOMAIN-SUFFIX,tyhmobile.com,DIRECT",
    "DOMAIN-SUFFIX,plexins.com,DIRECT",
    "DOMAIN-SUFFIX,lanhuapp.com,DIRECT",
  ];

  // 远程桌面 / 远控软件优先直连：必须放在 STUN 代理规则前面。
  const REMOTE_DESKTOP_DIRECT = [
    "PROCESS-NAME-REGEX,(?i)(uuremote|gameviewer|uuyc|todesk|sunlogin|anydesk|teamviewer|rustdesk|mstsc),DIRECT",
    "DOMAIN-SUFFIX,todesk.com,DIRECT",
    "DOMAIN-SUFFIX,todesk.cn,DIRECT",
    "DOMAIN-SUFFIX,oray.com,DIRECT",
    "DOMAIN-SUFFIX,sunlogin.oray.com,DIRECT",
    "DOMAIN-SUFFIX,anydesk.com,DIRECT",
    "DOMAIN-SUFFIX,teamviewer.com,DIRECT",
    "DOMAIN-SUFFIX,rustdesk.com,DIRECT",
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
    // 端口兜底默认关闭：全局 UDP 端口直连不限进程，会扩大真实 IP 暴露面。
    // 若进程规则在 UDP 上失效且已在 Parsec 两端固定端口（Host Start Port=8000、Client Port=9000），
    // 可显式改为 ["8000-8009", "9000-9009"] 作为安全网。
    udpPorts: [],
  };

  // 按节点名关键字归类地区；匹配不到节点的地区组自动剔除，避免空组报错。
  // name 为纯地区名（展示名）；正则里的国旗 emoji 仅用于识别节点名，不写进策略组名。
  const regionDefs = [
    {
      name: "香港",
      re: /香港|Hong\s?Kong|🇭🇰|(^|[^a-z])hk([^a-z]|$)/i,
    },
    {
      name: "台湾",
      re: /台湾|台灣|Taiwan|🇹🇼|(^|[^a-z])tw([^a-z]|$)/i,
    },
    {
      name: "日本",
      re: /日本|东京|大阪|Japan|🇯🇵|(^|[^a-z])jp([^a-z]|$)/i,
    },
    {
      name: "新加坡",
      re: /新加坡|狮城|獅城|Singapore|🇸🇬|(^|[^a-z])sg([^a-z]|$)/i,
    },
    {
      // 不用裸 America：会误收 South America / American Samoa 等。
      name: "美国",
      re: /美国|美國|United\s?States|🇺🇸|(^|[^a-z])(us|usa)([^a-z]|$)/i,
    },
    {
      name: "韩国",
      re: /韩国|韓國|首尔|Korea|🇰🇷|(^|[^a-z])kr([^a-z]|$)/i,
    },
    {
      // 只用 uk 代码：gb 会误伤「剩余100GB」等流量标签，故不启用。
      // 不用裸 London：会把 Frankfurt-London / DE-London 等多地拼接名误收进英国。
      // 保留中文「伦敦」（机场节点几乎总是英区）；英文请靠 UK / Britain / 英国。
      name: "英国",
      re: /英国|英國|United\s?Kingdom|Britain|伦敦|🇬🇧|(^|[^a-z])uk([^a-z]|$)/i,
    },
    {
      name: "德国",
      re: /德国|德國|Germany|🇩🇪|(^|[^a-z])de([^a-z]|$)/i,
    },
    {
      name: "法国",
      re: /法国|法國|France|🇫🇷|(^|[^a-z])fr([^a-z]|$)/i,
    },
    {
      name: "荷兰",
      re: /荷兰|荷蘭|Netherlands|Holland|🇳🇱|(^|[^a-z])nl([^a-z]|$)/i,
    },
    {
      // 不用裸 ca：会误收 US-CA（加州）。改用 can / 全称 / 城市 / Emoji；配合下方首命中分配。
      name: "加拿大",
      re: /加拿大|Canada|🇨🇦|Toronto|Vancouver|Montreal|Ottawa|Calgary|Edmonton|多伦多|温哥华|蒙特利尔|渥太华|卡加利|埃德蒙顿|(^|[^a-z])can([^a-z]|$)/i,
    },
    {
      // 用「澳洲/澳大利亚」而非裸「澳」，避开澳门。
      name: "澳大利亚",
      re: /澳大利亚|澳洲|Australia|🇦🇺|(^|[^a-z])au([^a-z]|$)/i,
    },
    {
      name: "泰国",
      re: /泰国|泰國|Thailand|🇹🇭|(^|[^a-z])th([^a-z]|$)/i,
    },
    // 省略 my 代码：撞英文 "my"，仅靠名称/Emoji 匹配。
    { name: "马来西亚", re: /马来西亚|马来|Malaysia|🇲🇾/i },
    {
      name: "越南",
      re: /越南|Vietnam|🇻🇳|(^|[^a-z])vn([^a-z]|$)/i,
    },
    {
      name: "菲律宾",
      re: /菲律宾|菲律賓|Philippines|🇵🇭|(^|[^a-z])ph([^a-z]|$)/i,
    },
    {
      name: "俄罗斯",
      re: /俄罗斯|俄羅斯|俄国|Russia|🇷🇺|(^|[^a-z])ru([^a-z]|$)/i,
    },
    {
      name: "土耳其",
      re: /土耳其|Turkey|🇹🇷|(^|[^a-z])tr([^a-z]|$)/i,
    },
    // 省略 in 代码：撞英文 "in"，仅靠名称/Emoji 匹配。
    { name: "印度", re: /印度|India|🇮🇳/i },
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

    // 进程匹配模式：strict 由内核按需查找，省掉 always 对每条连接的强制进程查找。
    // ⚠️ 若远控/Parsec 的进程直连规则失效（尤其 UDP 打洞流量），改回 "always"。
    "find-process-mode": "strict",

    profile: {
      "store-selected": true,
      // 缓存 fake-ip 映射以加速启动；注意：改动下方 fake-ip-filter 后需手动清一次 fake-ip 缓存，
      // 否则新加入 filter 的域名仍可能命中旧映射、走错路径。
      "store-fake-ip": true,
    },

    // 域名嗅探：fake-ip 丢映射或应用直连 IP 时，从载荷还原域名再走规则。
    // - HTTP/TLS：TCP Host / SNI
    // - QUIC：UDP/443 等 ClientHello 里的 SNI（HTTP/3）；不配 ports 时内核默认也只嗅 443
    // - STUN/TURN 明文无 SNI，嗅探无能为力 → 仍靠 stun 规则集 + UDP 3478/19302/5349
    sniffer: {
      enable: true,
      "force-dns-mapping": true,
      "parse-pure-ip": true,
      // 全局 false：嗅探只用于匹配规则，不改真实目标 IP（避免部分 UDP/CDN 异常）。
      // HTTP 单独 override-destination:true，便于按 Host 分流反代/多站点同 IP。
      "override-destination": false,
      sniff: {
        HTTP: { ports: [80, "8080-8880"], "override-destination": true },
        TLS: { ports: [443, 8443] },
        // 补上 QUIC：否则 HTTP/3 走裸 IP 时只能靠 IP 规则，geosite 全失效。
        QUIC: { ports: [443, 8443] },
      },
      "skip-domain": ["+.push.apple.com", "+.teams.microsoft.com"],
    },

    tun: {
      enable: true,
      // mixed：DNS 劫持比 system 更稳；若某应用异常再退回 system。
      stack: "mixed",
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

      // 默认解析器：国外 DoH 经节点选择（与总闸一致；DIRECT 时 DNS 也直连），国内域名由 nameserver-policy 指回 CN_DOH。
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
      // VPSDance/ai-proxy-rules 聚合集：补齐 category-ai-!cn 缺失的二线 AI
      // （Suno/Runway/Luma/Character.AI 等），多源合并、每日更新；
      // classical 行为（混合 DOMAIN/IP 规则），IP 条目自带 no-resolve。
      aiextra: {
        type: "http",
        behavior: "classical",
        format: "yaml",
        interval: 86400,
        path: "./ruleset/ai-extra.yaml",
        url: "https://cdn.jsdelivr.net/gh/VPSDance/ai-proxy-rules@main/rules/clash/all.yaml",
      },
      applecn: buildSiteProvider(RS_PREFIX, "apple-cn"),
      apple: buildSiteProvider(RS_PREFIX, "apple"),
      // MetaCubeX geosite 使用 microsoft@cn / azure@cn（不是 *-cn 文件名）
      microsoftcn: buildSiteProvider(RS_PREFIX, "microsoft@cn"),
      azurecn: buildSiteProvider(RS_PREFIX, "azure@cn"),
      microsoft: buildSiteProvider(RS_PREFIX, "microsoft"),
      netflix: buildSiteProvider(RS_PREFIX, "netflix"),
      disney: buildSiteProvider(RS_PREFIX, "disney"),
      youtube: buildSiteProvider(RS_PREFIX, "youtube"),
      spotify: buildSiteProvider(RS_PREFIX, "spotify"),
      // 推送 / B 站 / 游戏（借鉴 ACL4SSR 粒度，规则源仍用 MetaCubeX）。
      googlefcm: buildSiteProvider(RS_PREFIX, "googlefcm"),
      bilibili: buildSiteProvider(RS_PREFIX, "bilibili"),
      ...Object.fromEntries(
        GAME_SITES.map((name) => [name, buildSiteProvider(RS_PREFIX, name)]),
      ),
      // 国外网盘：blackmatrix7 classical；provider 名小写，与下方 RULE-SET 对应。
      ...Object.fromEntries(
        CLOUD_RULES.map((name) => [
          name.toLowerCase(),
          buildBmClassicalProvider(BM_CLASH, name),
        ]),
      ),
      proxy: buildSiteProvider(RS_PREFIX, "geolocation-!cn"),
      cn: buildSiteProvider(RS_PREFIX, "cn"),
      cnip: buildIpProvider(RS_PREFIX, "cn"),
      telegram: buildSiteProvider(RS_PREFIX, "telegram"),
      telegramip: buildIpProvider(RS_PREFIX, "telegram"),
    },

    "proxy-groups": hasNodes
      ? buildProxyGroups(G, URL_TEST, usableNodes, regionGroups, regionNames)
      : buildRejectGroups(G),

    rules: [
      "DOMAIN,clash.razord.top,DIRECT",
      "DOMAIN,yacd.metacubex.one,DIRECT",

      "DOMAIN-KEYWORD,httpdns,REJECT",
      // App HTTP DNS / 部分内置安全 DNS 域名关键字（子串；过宽误伤时再收窄）。
      "DOMAIN-KEYWORD,-httpdns-,REJECT",
      "DOMAIN-KEYWORD,dns-query,REJECT",

      // 第三方公共 DoH/DoT/DNS IP：名单尽量全；普通站 HTTP/3 仍走后续规则分流。
      ...buildDohRejectRules(DOH_BLOCK_SUFFIXES, DOH_BLOCK_IPS),

      "RULE-SET,private,DIRECT",
      "RULE-SET,privateip,DIRECT,no-resolve",

      // 谷歌 FCM 推送直连，降低代理解析导致的通知延迟/失败。
      "RULE-SET,googlefcm,DIRECT",

      // 远控软件优先直连：必须位于下方 STUN 代理规则之前，
      // 否则打洞流量会被全局规则截走。
      ...REMOTE_DESKTOP_DIRECT,

      // 可信 P2P 应用特批直连：必须位于下方 STUN 代理规则之前，
      // 否则 Parsec 等应用的打洞流量会被全局规则截走。
      ...buildTrustedP2PRules(TRUSTED_P2P),

      // WebRTC/STUN/TURN 前置，避免先命中国内 IP 直连规则导致真实公网 IP 暴露。
      // 已移除 DOMAIN-KEYWORD,stun（子串匹配会误伤 stunning-* 等无关域名），RULE-SET,stun 已覆盖真实 STUN 域名。
      `RULE-SET,stun,${G.select}`,
      `AND,((NETWORK,UDP),(DST-PORT,3478)),${G.select}`,
      `AND,((NETWORK,UDP),(DST-PORT,19302)),${G.select}`,
      `AND,((NETWORK,UDP),(DST-PORT,5349)),${G.select}`,

      `RULE-SET,ai,${G.ai}`,
      `RULE-SET,netflix,${G.stream}`,
      `RULE-SET,disney,${G.stream}`,
      `RULE-SET,youtube,${G.stream}`,
      `RULE-SET,spotify,${G.stream}`,
      `RULE-SET,telegram,${G.telegram}`,
      `RULE-SET,telegramip,${G.telegram},no-resolve`,
      // aiextra 是 classical 行为（逐条线性匹配），置于流媒体/Telegram 之后，
      // 让高频流量免扫线性集；置于 Apple/Microsoft 之前，防止 microsoft 集的
      // +.azure.com 等抢走 Copilot / Azure OpenAI（与下方国区直连集已验证零交集）。
      `RULE-SET,aiextra,${G.ai}`,

      // B 站：默认直连；港台限定可在「哔哩哔哩」组选手动/地区节点（须在 proxy/cn 之前）。
      `RULE-SET,bilibili,${G.bilibili}`,

      // 游戏平台：默认直连；须在 geolocation-!cn 之前，避免 Steam 等被送进节点选择。
      ...GAME_SITES.map((name) => `RULE-SET,${name},${G.game}`),

      // 国区 Apple / Microsoft 直连，避免全球规则集抢在 cn 前把国区流量送进策略组→节点选择。
      "RULE-SET,applecn,DIRECT",
      `RULE-SET,apple,${G.apple}`,
      "RULE-SET,microsoftcn,DIRECT",
      "RULE-SET,azurecn,DIRECT",
      // OneDrive 须在 microsoft 全球集之前，否则 sharepoint/onedrive 会被 Microsoft 组抢走。
      // 其余国外网盘亦置于 proxy 之前，便于单独选高速节点。
      ...CLOUD_RULES.map((name) => `RULE-SET,${name.toLowerCase()},${G.cloud}`),
      `RULE-SET,microsoft,${G.microsoft}`,

      // 手动特例：强制直连（集中维护于顶部 MANUAL_DIRECT）。
      ...MANUAL_DIRECT,

      `RULE-SET,proxy,${G.select}`,

      // cn 规则集内容缺漏或缓存过期时，保证 .cn 域名仍然直连。
      // 注：兜不住「首次下载失败」——无缓存且下载失败时 mihomo 直接启动失败。
      "DOMAIN-SUFFIX,cn,DIRECT",
      "RULE-SET,cn,DIRECT",
      "RULE-SET,cnip,DIRECT,no-resolve",

      // GeoIP 中国段改走 漏网之鱼，避免边界段误判时直接泄露。
      `GEOIP,CN,${G.final},no-resolve`,

      `MATCH,${G.final}`,
    ],
  });

  // 已有展开节点时去掉动态源，避免与 proxies 双轨；无节点时保留，供上游 provider 继续供数。
  if (proxies.length > 0) {
    delete config["proxy-providers"];
  }

  return config;
}

// 判断是否为订阅里的说明/营销项（非真实节点）。
// 刻意收窄：避免「非官方」「Unofficial」「流量优化」「Telegram中继」「Channel Islands」等被误杀。
function isNonNodeName(name) {
  const n = String(name).trim();
  if (!n) return true;
  if (/https?:\/\//i.test(n)) return true;

  // 官方 / official：先剥掉否定前缀，再匹配（对称处理中英文）。
  const nForOfficial = n.replace(/非官方/g, "").replace(/unofficial/gi, "");
  if (/官网|官方/.test(nForOfficial)) return true;
  if (/\bofficial\b/i.test(nForOfficial)) return true;

  // 社群入口：Telegram/TG 仅在「群/频道/客服」等语境下剔除，保留「Telegram中继」类节点。
  if (
    /t\.me|(?:加入)?\s*Telegram\s*(?:群|频道|频道组|客服|通知)|(?:加入)?\s*TG\s*(?:群|频道|客服)|电报群|微信|公众号|discord/i.test(
      n,
    )
  ) {
    return true;
  }

  // 英文 channel：不用裸 channel（会误伤 Channel Islands 等地名）；仅社群/订阅语境。
  if (
    /(?:telegram|tg|discord|join|subscribe|official)\s*channels?\b|\bchannels?\s*(?:invite|link|group)\b/i.test(
      n,
    )
  ) {
    return true;
  }

  // 英文 support：不用裸 support（会误伤节点名里的 Support）；仅客服/工单语境。
  if (
    /(?:customer|tech|technical|contact|help|online)\s*support\b|\bsupport\s*(?:group|channel|ticket|team)\b/i.test(
      n,
    )
  ) {
    return true;
  }

  // 流量/账单/营销说明：不用裸「流量」；中文「频道」仍剔（机场说明项），英文 channel 见上。
  return /网站|网址|地址|订阅|到期|过期|剩余|套餐|重置|距离|链接|机场|频道|群组|客服|通知|说明|教程|签到|邀请|返利|优惠|测试中|维护|离线|用完|耗尽|刷新|账号|密码|无法使用|流量重置|剩余流量|已用流量|可用流量|已用|可用|总量|加入|expire|traffic|surplus|quota|invite|website/i.test(
    n,
  );
}

// 收集订阅节点名称：只保留有 name 的真实节点。
function collectNodeNames(proxies) {
  const names = [];
  for (const proxy of proxies) {
    if (proxy && proxy.name && !isNonNodeName(proxy.name)) {
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

// 构建地区分组：每个节点只归入第一个命中的地区，避免 US-CA 等多重归属污染 url-test。
function buildRegionGroups(regionDefs, nodeNames) {
  const assigned = new Set();
  const groups = [];
  for (const region of regionDefs) {
    const nodes = [];
    for (const nodeName of nodeNames) {
      if (assigned.has(nodeName)) continue;
      if (region.re.test(nodeName)) {
        nodes.push(nodeName);
        assigned.add(nodeName);
      }
    }
    if (nodes.length > 0) {
      groups.push({ name: region.name, nodes });
    }
  }
  return groups;
}

// 地区外层 select 展示名：纯地区名（图标由 icon 字段提供）。
function regionSelectLabel(region) {
  return region.name;
}

// 地区内层 url-test 名：地区 + 自动；hidden，仅在地区组内可选。
function regionAutoLabel(region) {
  return region.name + "自动";
}

// 收集地区组名称：用于策略组引用。
function collectRegionNames(regionGroups) {
  const names = [];
  for (const region of regionGroups) {
    names.push(regionSelectLabel(region));
  }
  return names;
}

// 公共 DNS/DoH 拦截规则：域名后缀 + 纯解析器 IP 全端口 REJECT。
function buildDohRejectRules(suffixes, ips) {
  const rules = [];
  const seen = new Set();
  for (const suffix of suffixes) {
    const rule = `DOMAIN-SUFFIX,${suffix},REJECT`;
    if (seen.has(rule)) continue;
    seen.add(rule);
    rules.push(rule);
  }
  for (const ip of ips) {
    const rule = `IP-CIDR,${ip}/32,REJECT,no-resolve`;
    if (seen.has(rule)) continue;
    seen.add(rule);
    rules.push(rule);
  }
  return rules;
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

// blackmatrix7 Clash classical 规则集（yaml，可含 DOMAIN/IP/PROCESS）。
// folder 与文件名通常一致，如 PikPak/PikPak.yaml。
function buildBmClassicalProvider(prefix, folder) {
  return {
    type: "http",
    behavior: "classical",
    format: "yaml",
    interval: 86400,
    path: `./ruleset/bm-${folder.toLowerCase()}.yaml`,
    url: `${prefix}/${folder}/${folder}.yaml`,
  };
}

// 构建有节点时的策略组（双层 + hidden + icon；名称纯文字，图标走 icon 字段）。
// - 自动选择：全局 url-test，面板可见
// - 地区外层 select（可见，挂国旗 icon）：首项「地区自动」+ 该区节点
// - 地区内层 url-test（hidden: true）：只测该区，面板不单独展示
function buildProxyGroups(G, urlTest, usableNodes, regionGroups, regionNames) {
  const urlTestBase = {
    type: "url-test",
    url: urlTest,
    interval: 300,
    tolerance: 50,
    lazy: true,
  };

  // 功能组图标：Koolson/Qure 图标集（jsdelivr）；面板需支持 icon 字段（metacubexd/Verge）。
  const ICON = "https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color";
  // 地区组国旗：circle-flags（HatScripts，MIT，圆形 SVG），按 ISO 3166-1 alpha-2 取。
  const FLAG =
    "https://cdn.jsdelivr.net/gh/HatScripts/circle-flags@gh-pages/flags";
  // 地区中文名 → ISO 代码（注意英国用 gb 不是 uk）。
  const REGION_ISO = {
    香港: "hk",
    台湾: "tw",
    日本: "jp",
    新加坡: "sg",
    美国: "us",
    韩国: "kr",
    英国: "gb",
    德国: "de",
    法国: "fr",
    荷兰: "nl",
    加拿大: "ca",
    澳大利亚: "au",
    泰国: "th",
    马来西亚: "my",
    越南: "vn",
    菲律宾: "ph",
    俄罗斯: "ru",
    土耳其: "tr",
    印度: "in",
  };

  // 跟总闸：节点选择优先（AI / 流媒体 / TG / 网盘 / 微软 / 游戏）。
  const followSelect = [
    G.select,
    G.auto,
    ...regionNames,
    "DIRECT",
    ...usableNodes,
  ];
  // 默认直连：Apple / B 站（需要时代理）。
  const directFirst = [
    "DIRECT",
    G.select,
    G.auto,
    ...regionNames,
    ...usableNodes,
  ];

  // 面板展示顺序：节点选择 / 自动选择 打底，功能组以 AI 为首。
  const groups = [
    {
      name: G.select,
      type: "select",
      icon: `${ICON}/Proxy.png`,
      proxies: [G.auto, ...regionNames, "DIRECT", ...usableNodes],
    },
    {
      name: G.auto,
      ...urlTestBase,
      icon: `${ICON}/Auto.png`,
      proxies: usableNodes,
    },
    {
      name: G.ai,
      type: "select",
      icon: `${ICON}/Bot.png`,
      proxies: followSelect,
    },
    {
      name: G.stream,
      type: "select",
      icon: `${ICON}/Streaming.png`,
      proxies: followSelect,
    },
    {
      name: G.telegram,
      type: "select",
      icon: `${ICON}/Telegram.png`,
      proxies: followSelect,
    },
    {
      // 默认 DIRECT：国区已由 applecn 直连；海外 Apple 需代理时再改。
      name: G.apple,
      type: "select",
      icon: `${ICON}/Apple_2.png`,
      proxies: directFirst,
    },
    {
      // 默认跟节点选择：国区仍由 microsoftcn/azurecn 直连；GitHub/海外微软随总闸。
      name: G.microsoft,
      type: "select",
      icon: `${ICON}/Microsoft.png`,
      proxies: followSelect,
    },
    {
      name: G.cloud,
      type: "select",
      // Qure 无 Cloud.png；Download 表示大流量网盘用途。
      icon: `${ICON}/Download.png`,
      proxies: followSelect,
    },
    {
      // 默认直连；港澳台内容可切地区/节点。
      name: G.bilibili,
      type: "select",
      icon: `${ICON}/Bilibili_2.png`,
      proxies: directFirst,
    },
    {
      // 默认跟节点选择；延迟敏感时可在组内改 DIRECT/地区。
      name: G.game,
      type: "select",
      icon: `${ICON}/Game.png`,
      proxies: followSelect,
    },
  ];

  for (const region of regionGroups) {
    const regionAuto = regionAutoLabel(region);
    const regionSelect = regionSelectLabel(region);
    groups.push({
      name: regionAuto,
      ...urlTestBase,
      proxies: region.nodes,
      // 仅作地区组内选项；需面板支持 hidden（metacubexd / Verge 等）
      hidden: true,
    });
    const regionGroup = {
      name: regionSelect,
      type: "select",
      proxies: [regionAuto, ...region.nodes],
    };
    const iso = REGION_ISO[region.name];
    if (iso) {
      regionGroup.icon = `${FLAG}/${iso}.svg`;
    }
    groups.push(regionGroup);
  }

  groups.push({
    name: G.final,
    type: "select",
    icon: `${ICON}/Final.png`,
    // 保持 fail-closed：不提供 DIRECT。
    proxies: [G.select, G.auto, ...regionNames, ...usableNodes],
  });

  return groups;
}

// 构建无节点时的策略组：全部 fail-closed 到 REJECT。
function buildRejectGroups(G) {
  const ICON = "https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color";
  return [
    {
      name: G.select,
      type: "select",
      icon: `${ICON}/Proxy.png`,
      proxies: ["REJECT"],
    },
    {
      // 无节点时保留组名，避免其它引用落空；国外 DoH 此时走 #节点选择 → REJECT。
      name: G.auto,
      type: "select",
      icon: `${ICON}/Auto.png`,
      proxies: ["REJECT"],
    },
    {
      name: G.ai,
      type: "select",
      icon: `${ICON}/Bot.png`,
      proxies: ["REJECT"],
    },
    {
      name: G.stream,
      type: "select",
      icon: `${ICON}/Streaming.png`,
      proxies: ["REJECT"],
    },
    {
      name: G.telegram,
      type: "select",
      icon: `${ICON}/Telegram.png`,
      proxies: ["REJECT"],
    },
    {
      name: G.apple,
      type: "select",
      icon: `${ICON}/Apple_2.png`,
      proxies: ["REJECT"],
    },
    {
      name: G.microsoft,
      type: "select",
      icon: `${ICON}/Microsoft.png`,
      proxies: ["REJECT"],
    },
    {
      name: G.cloud,
      type: "select",
      icon: `${ICON}/Download.png`,
      proxies: ["REJECT"],
    },
    {
      // 无节点时仍直连，避免 B 站/游戏被 REJECT。
      name: G.bilibili,
      type: "select",
      icon: `${ICON}/Bilibili_2.png`,
      proxies: ["DIRECT"],
    },
    {
      name: G.game,
      type: "select",
      icon: `${ICON}/Game.png`,
      proxies: ["DIRECT"],
    },
    {
      name: G.final,
      type: "select",
      icon: `${ICON}/Final.png`,
      proxies: ["REJECT"],
    },
  ];
}
