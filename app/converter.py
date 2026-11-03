"""节点解析与各客户端订阅格式转换

流程: 订阅里的节点/远程订阅 -> collect_links 展开为节点链接 -> parse_nodes 解析成 clash 格式字典
-> 各 *_encode 函数转换成对应客户端格式
"""
import base64, copy, ipaddress, json, os, re, socket, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor
import requests, yaml

path = os.path.dirname(os.path.abspath(__file__))
HTTP_TIMEOUT = 15  # 拉取远程订阅超时(秒)
SUB_CACHE_TTL = 60  # 远程订阅缓存时间(秒),避免多个客户端同时更新时重复拉取
http = requests.Session()
settings = {'udp': False, 'skipcert': False, 'emoji': False}  # 全局设置,每次生成订阅前从数据库加载

try:  # 有 libyaml 时使用 C 实现,大模板解析/输出快很多
    YamlLoader, YamlDumper = yaml.CSafeLoader, yaml.CSafeDumper
except AttributeError:
    YamlLoader, YamlDumper = yaml.SafeLoader, yaml.SafeDumper


def decode_base64_if(text):  # base64解码,不是base64则返回原文
    try:
        name = ''
        decoded_text = text
        at = ''
        if '#' in decoded_text:
            name = '#' + decoded_text.split('#')[1]
            decoded_text = decoded_text.split('#')[0]
        if '@' in decoded_text:
            at = '@' + decoded_text.split('@')[1]
        padding = 4 - (len(decoded_text) % 4)
        if padding > 0 and padding < 4:
            decoded_text += "=" * padding
        decoded_text = base64.b64decode(decoded_text).decode('utf-8')
        return decoded_text + at + name
    except Exception:
        return text
def decode_sub_text(text):  # 远程订阅内容解码,兼容明文/标准base64/urlsafe base64
    text = text.strip()
    if '://' in text:
        return text
    try:
        data = re.sub(r'\s+', '', text).replace('+', '-').replace('/', '_')
        data += '=' * (-len(data) % 4)
        return base64.urlsafe_b64decode(data).decode('utf-8')
    except Exception:
        return text
def if_ipv6_address(string):  # [ipv6] 去掉中括号
    match = re.search(r'\[([0-9a-fA-F:]+)\]', string)
    return match.group(1) if match else string
def split_host_port(server_port, default_port=443):  # 服务器:端口 拆分,兼容[ipv6]:端口和未写端口
    server_port = server_port.split('/')[0].split('?')[0]
    if server_port.startswith('['):
        host, _, rest = server_port[1:].partition(']')
        port = rest[1:] if rest.startswith(':') else ''
    elif ':' in server_port:
        host, port = server_port.rsplit(':', 1)
    else:
        host, port = server_port, ''
    match = re.match(r'\d+', port)  # 端口跳跃 443,20000-30000 取第一个端口
    return host, int(match.group()) if match else default_port
def is_true(value):
    return str(value).lower() in ('1', 'true')


_emoji_cache = {}
def get_country_emoji(hostname):  # 根据服务器ip获取国旗emoji,结果缓存
    if hostname in _emoji_cache:
        return _emoji_cache[hostname]
    try:
        try:
            ip = str(ipaddress.ip_address(hostname))
        except ValueError:
            ip = socket.gethostbyname(hostname)
        js = http.get(f"http://ipwho.is/{ip}", timeout=5).json()
        emoji = (js.get('flag') or {}).get('emoji') or ''
        _emoji_cache[hostname] = emoji
        return emoji
    except Exception:  # 查询失败不缓存,下次再试
        return ''


class NodeParse():  # 节点链接 -> clash(mihomo) 格式字典
    def __init__(self, proxy_test=''):
        self.proxy_test = proxy_test
    @staticmethod
    def _query(parse):
        return {key: value[0] for key, value in urllib.parse.parse_qs(parse.query).items()}
    @staticmethod
    def _name(name, server):
        if settings['emoji']:
            return get_country_emoji(server) + name
        return name
    @staticmethod
    def _cert(proxy, query, *insecure_keys):  # query中cert/insecure等参数覆盖跳过证书验证
        for key in insecure_keys:
            if is_true(query.get(key)):
                proxy['skip-cert-verify'] = True
        if query.get('cert'):
            proxy['skip-cert-verify'] = query.get('cert').lower() == 'true'
        return proxy
    @staticmethod
    def _transport(proxy, network, path=None, host=None, service_name=None):  # ws/grpc 传输层
        if network == 'ws':
            proxy['network'] = 'ws'
            proxy['ws-opts'] = {'path': path or '/'}
            if host:
                proxy['ws-opts']['headers'] = {'Host': host}
        elif network == 'grpc':
            proxy['network'] = 'grpc'
            proxy['grpc-opts'] = {'grpc-service-name': service_name or ''}
        return proxy

    def vless(self):
        parse = urllib.parse.urlparse(self.proxy_test)
        query = self._query(parse)
        info = parse.netloc + parse.path if parse.path != '/' else parse.netloc
        urlpath = decode_base64_if(info)  # uuid@服务器:端口
        uuid = decode_base64_if(urlpath.rsplit('@', 1)[0])
        server, port = split_host_port(urlpath.rsplit('@', 1)[1])
        security = query.get('security', '')
        proxy = {
            'name': self._name(urllib.parse.unquote(parse.fragment), server),
            'type': 'vless',
            'uuid': uuid,
            'server': server,
            'client-fingerprint': query.get('fp') or 'chrome',
            'port': port,
            'network': query.get('type') or 'tcp',
            'udp': settings['udp'],
            'skip-cert-verify': settings['skipcert'],
            'tfo': False,
            'tls': security in ('tls', 'reality', 'xtls'),  # security=none 不启用tls
        }
        if query.get('sni'):
            proxy['servername'] = query.get('sni')
        if query.get('flow'):
            proxy['flow'] = query.get('flow')
        if security == 'reality':
            proxy['reality-opts'] = {'public-key': query.get('pbk')}
            if query.get('sid'):
                proxy['reality-opts']['short-id'] = query.get('sid')
        self._transport(proxy, query.get('type'), query.get('path'), query.get('host'), query.get('serviceName'))
        return self._cert(proxy, query, 'allowInsecure', 'insecure')
    def vmess(self):
        parse = urllib.parse.urlparse(self.proxy_test)
        cert = None
        if parse.query != '':  # 非标准格式(小火箭) vmess://base64(加密方式:uuid@服务器:端口)?remarks=..
            query = self._query(parse)
            info = decode_base64_if(parse.netloc)
            name = query.get('remarks', '')
            cipher, uuid = info.rsplit('@', 1)[0].split(':', 1)
            server, port = split_host_port(info.rsplit('@', 1)[1])
            aid = query.get('alterId')
            network = 'ws' if query.get('obfs') == 'websocket' else query.get('obfs', '')
            tls = query.get('tls')
            path_a = query.get('path')
            host = query.get('obfsParam')
            sni = query.get('peer')
            cert = query.get('cert')
        else:  # 标准格式 vmess://base64(json)
            info = parse.netloc + parse.path if parse.path != '/' else parse.netloc
            node = json.loads(decode_base64_if(info))  # 不能用eval,否则订阅内容可执行任意代码
            name = node.get('ps', '')
            uuid = node.get('id')
            server = node.get('add')
            port = int(node.get('port'))
            aid = node.get('aid')
            cipher = node.get('scy') or 'auto'
            network = node.get('net', '')
            tls = node.get('tls')
            path_a = node.get('path')
            host = node.get('host')
            sni = node.get('sni')
        proxy = {
            'name': self._name(name, server),
            'type': 'vmess',
            'uuid': uuid,
            'server': server,
            'port': int(port),
            'client-fingerprint': 'chrome',
            'tfo': False,
            'udp': settings['udp'],
            'skip-cert-verify': settings['skipcert'],
            'alterId': int(aid or 0),
            'cipher': cipher,
            'network': network if network in ('ws', 'grpc', 'h2', 'http') else 'tcp',
            'tls': str(tls).lower() in ('tls', '1', 'true', 'xtls'),  # 缺省/none/空 均为不启用
        }
        if sni:
            proxy['servername'] = sni
        self._transport(proxy, network, path_a, host, path_a)  # v2rayN 的 grpc serviceName 存在 path 中
        if cert:
            proxy['skip-cert-verify'] = cert.lower() == 'true'
        return proxy
    def ss(self):
        parse = urllib.parse.urlparse(self.proxy_test)
        info = parse.netloc + parse.path if parse.path != '/' else parse.netloc
        urlpath = decode_base64_if(info)
        server, port = split_host_port(urlpath.rsplit('@', 1)[-1])
        index = urlpath.rfind("@")  # 最后一个@前面是 加密方式:密码
        decode = decode_base64_if(urlpath[:index] if index != -1 else urlpath)
        cipher, password = decode.split(':', 1)
        return {
            'name': self._name(urllib.parse.unquote(parse.fragment), server),
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': cipher,
            'password': password,
            'client-fingerprint': 'chrome',
            'tfo': False,
            'udp': settings['udp'],
            'skip-cert-verify': settings['skipcert']
        }
    def ssr(self):
        parse = urllib.parse.urlparse(self.proxy_test.replace('-', '+').replace('_', '/'))
        info = parse.netloc + parse.path if parse.path != '/' else parse.netloc
        urlpath = decode_base64_if(info)
        query = urllib.parse.parse_qs(parse.query)
        server = if_ipv6_address(urlpath.split(':')[0])
        port = int(urlpath.split(':')[1])
        protocol = urlpath.split(':')[2]
        cipher = urlpath.split(':')[3]
        obfs = urlpath.split(':')[4]
        parse2 = urllib.parse.urlparse(urlpath.rsplit(':', 1)[1])
        password = decode_base64_if(parse2.path.replace('/', ''))
        query2 = urllib.parse.parse_qs(parse2.query)
        name = ""
        if query.get('remarks'):
            name = decode_base64_if(query.get('remarks')[0])
        if query2.get('remarks'):
            name = decode_base64_if(query2.get('remarks')[0])
        proxy = {
            'name': self._name(name, server),
            'type': 'ssr',
            'server': server,
            'port': port,
            'protocol': protocol,
            'cipher': cipher,
            'obfs': obfs,
            'password': password,
            'udp': settings['udp'],
            'skip-cert-verify': settings['skipcert']
        }
        for key, clash_key in (('protoparam', 'protocol-param'), ('obfsparam', 'obfs-param')):
            value = (query2.get(key) or query.get(key) or [''])[0]
            if value:
                proxy[clash_key] = decode_base64_if(value)
        return self._cert(proxy, {k: v[0] for k, v in query2.items()})
    def trojan(self):
        parse = urllib.parse.urlparse(self.proxy_test)
        info = parse.netloc + parse.path if parse.path != '/' else parse.netloc
        urlpath = decode_base64_if(info)
        query = self._query(parse)
        server, port = split_host_port(urlpath.rsplit('@', 1)[1])
        proxy = {
            'name': self._name(urllib.parse.unquote(parse.fragment), server),
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': urllib.parse.unquote(urlpath.rsplit('@', 1)[0]),
            'client-fingerprint': query.get('fp') or 'chrome',
            'udp': settings['udp'],
            'skip-cert-verify': settings['skipcert']
        }
        if query.get('sni') or query.get('peer'):
            proxy['sni'] = query.get('sni') or query.get('peer')
        if query.get('flow'):
            proxy['flow'] = query.get('flow')
        self._transport(proxy, query.get('type'), query.get('path'), query.get('host'), query.get('serviceName'))
        return self._cert(proxy, query, 'allowInsecure', 'insecure')
    def hysteria(self):
        parse = urllib.parse.urlparse(self.proxy_test)
        server, port = split_host_port(decode_base64_if(parse.netloc))
        query = self._query(parse)
        proxy = {
            'name': self._name(urllib.parse.unquote(parse.fragment), server),
            'type': 'hysteria',
            'server': server,
            'port': port,
            'client-fingerprint': 'chrome',
            'protocol': 'udp',
            'udp': settings['udp'],
            'skip-cert-verify': settings['skipcert']
        }
        if query.get('auth'):
            proxy['auth_str'] = query.get('auth')
        if query.get('upmbps'):
            proxy['up'] = query.get('upmbps')
        if query.get('downmbps'):
            proxy['down'] = query.get('downmbps')
        if query.get('alpn'):
            proxy['alpn'] = [query.get('alpn')]
        if query.get('peer'):
            proxy['sni'] = query.get('peer')
        return self._cert(proxy, query, 'insecure')
    def hysteria2(self):
        parse = urllib.parse.urlparse(self.proxy_test)
        urlpath = decode_base64_if(parse.netloc)
        query = self._query(parse)
        password = urllib.parse.unquote(urlpath.rsplit('@', 1)[0]) if '@' in urlpath else ''
        server, port = split_host_port(urlpath.rsplit('@', 1)[-1])
        proxy = {
            'name': self._name(urllib.parse.unquote(parse.fragment), server),
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
            'auth': password,
            'client-fingerprint': 'chrome',
            'udp': settings['udp'],
            'skip-cert-verify': settings['skipcert']
        }
        if query.get('sni'):
            proxy['sni'] = query.get('sni')
        if query.get('obfs') not in (None, '', 'none'):
            proxy['obfs'] = query.get('obfs')
        if query.get('obfs-password'):
            proxy['obfs-password'] = query.get('obfs-password')
        return self._cert(proxy, query, 'insecure')
    def tuic(self):
        # tuic://uuid:password@server:port?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=xx&allow_insecure=1#name
        parse = urllib.parse.urlparse(self.proxy_test)
        info = parse.netloc + parse.path if parse.path != '/' else parse.netloc
        urlpath = decode_base64_if(info)  # uuid:password@服务器:端口
        query = self._query(parse)
        userinfo = urlpath.rsplit('@', 1)[0]
        server, port = split_host_port(urlpath.rsplit('@', 1)[1])
        proxy = {
            'name': self._name(urllib.parse.unquote(parse.fragment), server),
            'type': 'tuic',
            'server': server,
            'port': port,
            'uuid': urllib.parse.unquote(userinfo.split(':', 1)[0]),
            'password': urllib.parse.unquote(userinfo.split(':', 1)[1]) if ':' in userinfo else '',
            'alpn': query.get('alpn').split(',') if query.get('alpn') else ['h3'],
            'congestion-controller': query.get('congestion_control', 'bbr'),
            'udp-relay-mode': query.get('udp_relay_mode', 'native'),
            'reduce-rtt': True,
            'udp': settings['udp'],
            'skip-cert-verify': settings['skipcert']
        }
        if query.get('sni'):
            proxy['sni'] = query.get('sni')
        if is_true(query.get('disable_sni')):
            proxy['disable-sni'] = True
        return self._cert(proxy, query, 'allow_insecure', 'allowInsecure', 'insecure')
    def anytls(self):
        # anytls://password@server:port/?sni=xx&insecure=1&fp=chrome#name
        parse = urllib.parse.urlparse(self.proxy_test)
        query = self._query(parse)
        server, port = split_host_port(parse.netloc.rsplit('@', 1)[1])
        proxy = {
            'name': self._name(urllib.parse.unquote(parse.fragment), server),
            'type': 'anytls',
            'server': server,
            'port': port,
            'password': urllib.parse.unquote(parse.netloc.rsplit('@', 1)[0]),
            'client-fingerprint': query.get('fp') or 'chrome',
            'udp': settings['udp'],
            'skip-cert-verify': settings['skipcert']
        }
        if query.get('sni'):
            proxy['sni'] = query.get('sni')
        if query.get('alpn'):
            proxy['alpn'] = query.get('alpn').split(',')
        return self._cert(proxy, query, 'insecure')

PARSERS = {
    'vless': NodeParse.vless,
    'vmess': NodeParse.vmess,
    'ss': NodeParse.ss,
    'ssr': NodeParse.ssr,
    'trojan': NodeParse.trojan,
    'hysteria': NodeParse.hysteria,
    'hy2': NodeParse.hysteria2,
    'hysteria2': NodeParse.hysteria2,
    'tuic': NodeParse.tuic,
    'anytls': NodeParse.anytls,
}
def node_scheme(link):  # 节点类型
    return link.split('://', 1)[0].strip().lower() if '://' in link else ''
def parse_node(link):  # 节点链接解析成clash格式字典,不支持的协议返回None
    parser = PARSERS.get(node_scheme(link))
    return parser(NodeParse(link.strip())) if parser else None


_sub_cache = {}
def fetch_sub(url):  # 拉取远程订阅,返回节点链接列表;失败返回空列表不影响其它节点
    cached = _sub_cache.get(url)
    if cached and time.time() - cached[0] < SUB_CACHE_TTL:
        return cached[1]
    try:
        response = http.get(url, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f'拉取订阅失败,已跳过: {url} {e}')
        return []
    links = [line.strip() for line in decode_sub_text(response.text).splitlines() if '://' in line]
    _sub_cache[url] = (time.time(), links)
    return links
def collect_links(subs):  # 订阅中的节点链接,远程订阅(http/https)并发拉取后展开
    remote = list(dict.fromkeys(sub.node for sub in subs if node_scheme(sub.node) in ('http', 'https')))
    fetched = {}
    if remote:
        with ThreadPoolExecutor(max_workers=min(8, len(remote))) as pool:
            fetched = dict(zip(remote, pool.map(fetch_sub, remote)))
    links = []
    for sub in subs:
        links.extend(fetched[sub.node] if sub.node in fetched else [sub.node.strip()])
    return links
def parse_nodes(links):  # 批量解析,单个节点出错跳过;节点名称去重(clash/sing-box 要求名称唯一)
    def safe_parse(link):
        try:
            return parse_node(link)
        except Exception as e:
            print(f'节点解析失败,已跳过: {link[:80]} {e!r}')
            return None
    if settings['emoji'] and len(links) > 1:  # emoji 需要联网查询,并发解析
        with ThreadPoolExecutor(max_workers=8) as pool:
            proxies = list(pool.map(safe_parse, links))
    else:
        proxies = [safe_parse(link) for link in links]
    names = set()
    result = []
    for proxy in proxies:
        if not proxy:
            continue
        base = proxy.get('name') or f"{proxy['server']}:{proxy['port']}"
        name, index = base, 1
        while name in names:
            index += 1
            name = f'{base} {index}'
        proxy['name'] = name
        names.add(name)
        result.append(proxy)
    return result
def expand_auto(items, names):  # 分组里的 auto 替换为本订阅所有节点名称(原位置插入)
    result = []
    for item in items or []:
        if item == 'auto':
            result.extend(names)
        else:
            result.append(item)
    return result


_template_cache = {}
def load_template(filename, loader):  # 读取 db 目录下的规则模板,按修改时间缓存解析结果
    file_path = os.path.join(path, 'db', filename)
    mtime = os.path.getmtime(file_path)
    cached = _template_cache.get(filename)
    if not cached or cached[0] != mtime:
        with open(file_path, 'r', encoding='utf-8') as file:
            cached = (mtime, loader(file))
        _template_cache[filename] = cached
    return copy.deepcopy(cached[1])
def bool_str(value):  # surge/loon/qx 配置中的布尔值
    return 'true' if value else 'false'


def clash_encode(links):  # clash(mihomo)
    proxies = parse_nodes(links)
    names = [proxy['name'] for proxy in proxies]
    data = load_template('clash.yaml', lambda f: yaml.load(f, Loader=YamlLoader))
    data['proxies'] = proxies
    for group in data.get('proxy-groups') or []:
        group['proxies'] = expand_auto(group.get('proxies'), names)
    return yaml.dump(data, Dumper=YamlDumper, sort_keys=False, allow_unicode=True)


def surge_line(proxy):
    name, server, port = proxy['name'], proxy['server'], proxy['port']
    common = f"skip-cert-verify={bool_str(proxy.get('skip-cert-verify'))}, udp-relay={bool_str(proxy.get('udp'))}"
    proxy_type = proxy['type']
    if proxy_type == 'ss':
        return f"{name} = ss, {server}, {port}, encrypt-method={proxy['cipher']}, password={proxy['password']}, " \
               f"tfo={bool_str(proxy.get('tfo'))}, udp-relay={bool_str(proxy.get('udp'))}"
    if proxy_type in ('vmess', 'trojan'):
        if proxy.get('network') not in ('tcp', 'ws', None):
            return None  # surge 不支持 grpc 等传输
        ws_opts = proxy.get('ws-opts') or {}
        host = (ws_opts.get('headers') or {}).get('Host')
        if proxy_type == 'vmess':
            line = f"{name} = vmess, {server}, {port}, username={proxy['uuid']}, tls={bool_str(proxy.get('tls'))}, " \
                   f"vmess-aead={bool_str(proxy.get('alterId', 0) == 0)}, {common}"
            sni = proxy.get('servername') or host if proxy.get('tls') else None
        else:
            line = f"{name} = trojan, {server}, {port}, password={proxy['password']}, {common}"
            sni = proxy.get('sni')
        if sni:
            line += f", sni={sni}"
        if proxy.get('network') == 'ws':
            line += f", ws=true, ws-path={ws_opts.get('path') or '/'}"
            if host:
                line += f", ws-headers=Host:{host}"
        return line
    if proxy_type == 'hysteria2':
        line = f"{name} = hysteria2, {server}, {port}, password={proxy['password']}, {common}"
        return line + (f", sni={proxy['sni']}" if proxy.get('sni') else '')
    if proxy_type == 'tuic':
        line = f"{name} = tuic-v5, {server}, {port}, password={proxy['password']}, uuid={proxy['uuid']}, " \
               f"alpn={proxy['alpn'][0]}, {common}"  # surge 参数以逗号分隔,alpn只能填一个
        return line + (f", sni={proxy['sni']}" if proxy.get('sni') else '')
    if proxy_type == 'anytls':
        line = f"{name} = anytls, {server}, {port}, password={proxy['password']}, {common}"
        return line + (f", sni={proxy['sni']}" if proxy.get('sni') else '')
    return None  # surge 不支持 ssr/vless/hysteria
def surge_encode(links):
    lines, names = [], []
    for proxy in parse_nodes(links):
        line = surge_line(proxy)
        if line:
            lines.append(line)
            names.append(proxy['name'])
    with open(os.path.join(path, 'db', 'surge.conf'), 'r', encoding='utf-8') as file:
        config_lines = file.read().splitlines()
    result, section, inserted = [], '', False
    for line in config_lines:
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            section = stripped.lower()
            result.append(line)
            if section == '[proxy]' and not inserted:  # [Proxy] 下插入节点
                result.extend(lines)
                inserted = True
            continue
        if section == '[proxy group]' and '=' in line and not stripped.startswith('#'):
            key, value = line.split('=', 1)  # 只替换分组列表里单独的 auto,不影响其它包含auto的内容
            items = [item.strip() for item in value.split(',')]
            if 'auto' in items:
                line = f"{key.rstrip()} = {', '.join(expand_auto(items, names))}"
        result.append(line)
    if not inserted:
        print("Proxy section not found in the configuration file.")
    return '\n'.join(result) + '\n'


def singbox_outbound(proxy):  # clash格式字典转sing-box出站,不支持的返回None
    def tls(utls=True):
        conf = {
            'enabled': True,
            'server_name': proxy.get('sni') or proxy.get('servername') or proxy.get('server'),
            'insecure': bool(proxy.get('skip-cert-verify'))
        }
        if proxy.get('alpn'):
            conf['alpn'] = proxy.get('alpn')
        if utls and proxy.get('client-fingerprint'):
            conf['utls'] = {'enabled': True, 'fingerprint': proxy.get('client-fingerprint')}
        return conf
    def transport():
        if proxy.get('network') == 'ws':
            ws_opts = proxy.get('ws-opts') or {}
            conf = {'type': 'ws', 'path': ws_opts.get('path') or '/'}
            if ws_opts.get('headers'):
                conf['headers'] = ws_opts.get('headers')
            return conf
        if proxy.get('network') == 'grpc':
            grpc_opts = proxy.get('grpc-opts') or {}
            return {'type': 'grpc', 'service_name': grpc_opts.get('grpc-service-name', '')}
        return None
    def mbps(value, default):
        match = re.search(r'\d+', str(value)) if value else None
        return int(match.group()) if match else default

    proxy_type = proxy.get('type')
    outbound = {
        'tag': proxy.get('name'),
        'server': proxy.get('server'),
        'server_port': int(proxy.get('port'))
    }
    if proxy_type == 'ss':
        outbound['type'] = 'shadowsocks'
        outbound['method'] = proxy.get('cipher')
        outbound['password'] = proxy.get('password')
    elif proxy_type == 'vmess':
        outbound['type'] = 'vmess'
        outbound['uuid'] = proxy.get('uuid')
        outbound['security'] = proxy.get('cipher') or 'auto'
        outbound['alter_id'] = int(proxy.get('alterId') or 0)
        if proxy.get('tls'):
            outbound['tls'] = tls()
            ws_host = ((proxy.get('ws-opts') or {}).get('headers') or {}).get('Host')
            if ws_host and not proxy.get('servername'):
                outbound['tls']['server_name'] = ws_host
    elif proxy_type == 'vless':
        outbound['type'] = 'vless'
        outbound['uuid'] = proxy.get('uuid')
        if proxy.get('flow'):
            outbound['flow'] = proxy.get('flow')
        if proxy.get('tls'):
            outbound['tls'] = tls()
            reality = proxy.get('reality-opts')
            if reality:
                outbound['tls']['reality'] = {'enabled': True, 'public_key': reality.get('public-key')}
                if reality.get('short-id'):
                    outbound['tls']['reality']['short_id'] = reality.get('short-id')
                outbound['tls']['utls'] = {'enabled': True, 'fingerprint': proxy.get('client-fingerprint') or 'chrome'}
    elif proxy_type == 'trojan':
        outbound['type'] = 'trojan'
        outbound['password'] = proxy.get('password')
        outbound['tls'] = tls()
    elif proxy_type == 'hysteria':
        outbound['type'] = 'hysteria'
        outbound['up_mbps'] = mbps(proxy.get('up'), 50)
        outbound['down_mbps'] = mbps(proxy.get('down'), 100)
        if proxy.get('auth_str'):
            outbound['auth_str'] = proxy.get('auth_str')
        outbound['tls'] = tls(utls=False)
    elif proxy_type == 'hysteria2':
        outbound['type'] = 'hysteria2'
        outbound['password'] = proxy.get('password')
        if proxy.get('obfs'):
            outbound['obfs'] = {'type': proxy.get('obfs'), 'password': proxy.get('obfs-password', '')}
        outbound['tls'] = tls(utls=False)
    elif proxy_type == 'tuic':
        outbound['type'] = 'tuic'
        outbound['uuid'] = proxy.get('uuid')
        outbound['password'] = proxy.get('password')
        outbound['congestion_control'] = proxy.get('congestion-controller', 'bbr')
        outbound['udp_relay_mode'] = proxy.get('udp-relay-mode', 'native')
        outbound['zero_rtt_handshake'] = bool(proxy.get('reduce-rtt'))
        outbound['tls'] = tls(utls=False)
        if proxy.get('disable-sni'):
            outbound['tls']['disable_sni'] = True
    elif proxy_type == 'anytls':
        outbound['type'] = 'anytls'
        outbound['password'] = proxy.get('password')
        outbound['tls'] = tls()
    else:
        return None  # sing-box 不支持 ssr 等协议
    if proxy_type in ('vmess', 'vless', 'trojan'):
        conf = transport()
        if conf:
            outbound['transport'] = conf
    if proxy_type in ('ss', 'vmess', 'vless', 'trojan') and not proxy.get('udp'):
        outbound['network'] = 'tcp'
    return outbound
def singbox_encode(links):  # sing-box
    outbounds = [o for o in map(singbox_outbound, parse_nodes(links)) if o]
    data = load_template('singbox.json', json.load)
    groups = data.get('outbounds') or []
    names = [outbound['tag'] for outbound in outbounds]
    for group in groups:
        if 'outbounds' in group:
            group['outbounds'] = expand_auto(group['outbounds'], names)
    data['outbounds'] = groups + outbounds
    return json.dumps(data, ensure_ascii=False, indent=2)


def loon_line(proxy):  # Loon 节点格式
    name, server, port = proxy['name'], proxy['server'], proxy['port']
    proxy_type = proxy['type']
    udp, tfo = bool_str(proxy.get('udp')), bool_str(proxy.get('tfo'))
    skip = bool_str(proxy.get('skip-cert-verify'))
    def transport():
        if proxy.get('network') == 'ws':
            ws_opts = proxy.get('ws-opts') or {}
            conf = f"transport=ws,path={ws_opts.get('path') or '/'}"
            host = (ws_opts.get('headers') or {}).get('Host')
            return conf + (f",host={host}" if host else '')
        return 'transport=tcp'
    if proxy_type in ('vmess', 'vless', 'trojan') and proxy.get('network') not in ('tcp', 'ws', None):
        return None  # loon 节点格式只生成 tcp/ws 传输
    if proxy_type == 'ss':
        return f'{name} = Shadowsocks,{server},{port},{proxy["cipher"]},"{proxy["password"]}",fast-open={tfo},udp={udp}'
    if proxy_type == 'ssr':
        return f'{name} = ShadowsocksR,{server},{port},{proxy["cipher"]},"{proxy["password"]}",protocol={proxy["protocol"]},' \
               f'protocol-param={proxy.get("protocol-param", "")},obfs={proxy["obfs"]},obfs-param={proxy.get("obfs-param", "")},' \
               f'fast-open={tfo},udp={udp}'
    if proxy_type == 'vmess':
        cipher = proxy.get('cipher') if proxy.get('cipher') in ('auto', 'aes-128-gcm', 'chacha20-poly1305', 'none') else 'auto'
        line = f'{name} = vmess,{server},{port},{cipher},"{proxy["uuid"]}",{transport()},alterId={proxy.get("alterId", 0)},' \
               f'over-tls={bool_str(proxy.get("tls"))}'
        if proxy.get('tls'):
            sni = proxy.get('servername') or ((proxy.get('ws-opts') or {}).get('headers') or {}).get('Host')
            line += (f',sni={sni}' if sni else '') + f',skip-cert-verify={skip}'
        return line + f',fast-open={tfo},udp={udp}'
    if proxy_type == 'vless':
        line = f'{name} = VLESS,{server},{port},"{proxy["uuid"]}",{transport()},over-tls={bool_str(proxy.get("tls"))}'
        if proxy.get('tls'):
            line += (f',sni={proxy["servername"]}' if proxy.get('servername') else '') + f',skip-cert-verify={skip}'
        if proxy.get('flow'):
            line += f',flow={proxy["flow"]}'
        reality = proxy.get('reality-opts')
        if reality:
            line += f',public-key="{reality.get("public-key")}"'
            if reality.get('short-id'):
                line += f',short-id={reality["short-id"]}'
        return line + f',fast-open={tfo},udp={udp}'
    if proxy_type == 'trojan':
        line = f'{name} = trojan,{server},{port},"{proxy["password"]}",{transport()}'
        line += (f',sni={proxy["sni"]}' if proxy.get('sni') else '') + f',skip-cert-verify={skip}'
        return line + f',fast-open={tfo},udp={udp}'
    if proxy_type == 'hysteria2':
        line = f'{name} = Hysteria2,{server},{port},"{proxy["password"]}"'
        line += (f',sni={proxy["sni"]}' if proxy.get('sni') else '') + f',skip-cert-verify={skip}'
        if proxy.get('obfs') == 'salamander' and proxy.get('obfs-password'):
            line += f',salamander-password={proxy["obfs-password"]}'
        return line + f',udp={udp}'
    return None  # loon 节点格式不生成 hysteria/tuic/anytls
def loon_encode(links):  # Loon 节点订阅(在 Loon 中作为订阅节点添加)
    lines = [loon_line(proxy) for proxy in parse_nodes(links)]
    return '\n'.join(line for line in lines if line) + '\n'


def quanx_line(proxy):  # Quantumult X server_remote 节点格式
    name, server, port = proxy['name'], proxy['server'], proxy['port']
    proxy_type = proxy['type']
    common = f"fast-open={bool_str(proxy.get('tfo'))}, udp-relay={bool_str(proxy.get('udp'))}, tag={name}"
    verify = f"tls-verification={bool_str(not proxy.get('skip-cert-verify'))}"
    def obfs(tls_host):  # ws/wss/over-tls
        network = proxy.get('network') or 'tcp'
        if network == 'ws':
            ws_opts = proxy.get('ws-opts') or {}
            host = (ws_opts.get('headers') or {}).get('Host') or tls_host
            conf = f"obfs={'wss' if proxy.get('tls') else 'ws'}, obfs-uri={ws_opts.get('path') or '/'}"
            conf += f", obfs-host={host}" if host else ''
        elif proxy.get('tls'):
            conf = 'obfs=over-tls' + (f", obfs-host={tls_host}" if tls_host else '')
        else:
            return ''
        return conf + (f", {verify}" if proxy.get('tls') else '') + ', '
    if proxy_type in ('vmess', 'vless', 'trojan') and proxy.get('network') not in ('tcp', 'ws', None):
        return None  # quantumult x 不支持 grpc
    if proxy_type == 'ss':
        return f"shadowsocks={server}:{port}, method={proxy['cipher']}, password={proxy['password']}, {common}"
    if proxy_type == 'ssr':
        line = f"shadowsocks={server}:{port}, method={proxy['cipher']}, password={proxy['password']}, " \
               f"ssr-protocol={proxy['protocol']}, ssr-protocol-param={proxy.get('protocol-param', '')}, obfs={proxy['obfs']}"
        return line + (f", obfs-host={proxy['obfs-param']}" if proxy.get('obfs-param') else '') + f", {common}"
    if proxy_type == 'vmess':
        cipher = proxy.get('cipher')
        cipher = cipher if cipher in ('aes-128-gcm', 'chacha20-poly1305', 'chacha20-ietf-poly1305', 'none') else 'chacha20-poly1305'
        line = f"vmess={server}:{port}, method={cipher}, password={proxy['uuid']}, {obfs(proxy.get('servername'))}"
        if proxy.get('alterId'):
            line += 'aead=false, '
        return line + common
    if proxy_type == 'vless':
        line = f"vless={server}:{port}, method=none, password={proxy['uuid']}, {obfs(proxy.get('servername'))}"
        reality = proxy.get('reality-opts')
        if reality:
            line += f"reality-base64-pubkey={reality.get('public-key')}, "
            if reality.get('short-id'):
                line += f"reality-hex-shortid={reality['short-id']}, "
        if proxy.get('flow'):
            line += f"vless-flow={proxy['flow']}, "
        return line + common
    if proxy_type == 'trojan':
        if proxy.get('network') == 'ws':
            proxy = dict(proxy, tls=True)  # trojan 总是 tls
            return f"trojan={server}:{port}, password={proxy['password']}, {obfs(proxy.get('sni'))}{common}"
        line = f"trojan={server}:{port}, password={proxy['password']}, over-tls=true, "
        line += f"tls-host={proxy['sni']}, " if proxy.get('sni') else ''
        return line + f"{verify}, {common}"
    return None  # quantumult x 不生成 hysteria/hysteria2/tuic/anytls
def quanx_encode(links):  # Quantumult X 节点订阅(作为 server_remote 引用)
    lines = [quanx_line(proxy) for proxy in parse_nodes(links)]
    return '\n'.join(line for line in lines if line) + '\n'


def general_encode(links):  # 通用格式: 明文节点链接,一行一个(远程订阅已展开)
    return '\n'.join(links) + '\n'
def v2ray_encode(links):  # v2ray: 节点链接 base64
    return base64.b64encode('\n'.join(links).encode('utf-8')).decode('utf-8')

ENCODERS = {  # 订阅类型: (编码函数, mimetype, 文件后缀)
    'clash': (clash_encode, 'text/plain', ''),
    'surge': (surge_encode, 'text/plain', ''),
    'singbox': (singbox_encode, 'application/json', '.json'),
    'sing-box': (singbox_encode, 'application/json', '.json'),
    'loon': (loon_encode, 'text/plain', '.txt'),
    'quanx': (quanx_encode, 'text/plain', '.txt'),
    'general': (general_encode, 'text/plain', '.txt'),
    'v2ray': (v2ray_encode, 'text/html', '.txt'),
}
