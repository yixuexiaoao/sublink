"""订阅转换冒烟测试(不依赖外网): python tests/test_sub.py [输出目录]

会在 app/db 下创建测试数据; 设置 SINGBOX_BIN 环境变量时额外用 sing-box check 校验生成的配置
"""
import base64, hashlib, json, os, subprocess, sys, tempfile
import yaml
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from app import converter, create_app, view
from app.model import create_db

OUT = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp()
UUID = 'b831381d-6324-4d53-ad4f-8cda48b30811'
PBK = 'jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0'

class FakeResp:
    status_code = 200
    def __init__(self, text): self.text = text
    def raise_for_status(self): pass
REMOTE = '\r\n'.join([  # 远程订阅: urlsafe base64 + CRLF
    'tuic://c1e6dbe2-f417-4890-994c-9ee15b926597:p%40ss@remote.example.com:8443?congestion_control=cubic&udp_relay_mode=quic&alpn=h3,spdy/3.1&sni=remote.example.com&allow_insecure=1#remote-tuic',
    'anytls://remotepw@[2001:db8::1]:8443/?sni=r.example.com#remote-anytls',
    'ssr://' + base64.urlsafe_b64encode(b'1.2.3.4:8388:origin:aes-256-cfb:plain:' + base64.urlsafe_b64encode(b'pw') + b'/?remarks=' + base64.urlsafe_b64encode(b'ssr-node')).decode(),
    'trojan://dup@dup.example.com:443#same-name',
    'trojan://dup2@dup2.example.com:443#same-name',
])
def fake_get(url, *args, **kwargs):
    if 'broken' in url:
        raise converter.requests.ConnectionError('boom')
    return FakeResp(base64.urlsafe_b64encode(REMOTE.encode()).decode())
converter.http.get = fake_get
view.save_ip_address = lambda: None

EVIL = base64.b64encode(b'__import__("os").system("echo pwned")').decode()
NODES = [
    'tuic://c1e6dbe2-f417-4890-994c-9ee15b926597:mypassword@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tuic.example.com#🇯🇵 tuic节点|tuic备注',
    'anytls://my%3Apass@anytls.example.com:443/?sni=anytls.example.com&insecure=1&fp=firefox#anytls节点',
    'anytls://pw2@anytls2.example.com/?sni=anytls2.example.com#anytls默认端口',
    f'vless://{UUID}@vless.example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk={PBK}&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision#vless-reality',
    f'vless://{UUID}@vless2.example.com:443?security=tls&sni=vless2.example.com&type=grpc&serviceName=gsvc#vless-grpc',
    f'vless://{UUID}@vless3.example.com:80?security=none&type=ws&path=%2Fv&host=cdn.example.com#vless-none',
    'vmess://' + base64.b64encode(json.dumps({'v': '2', 'ps': 'vmess-ws', 'add': 'vmess.example.com', 'port': '443', 'id': UUID, 'aid': '0', 'net': 'ws', 'type': 'none', 'host': 'cdn.example.com', 'path': '/ws', 'tls': 'tls'}).encode()).decode(),
    'vmess://' + base64.b64encode(json.dumps({'v': '2', 'ps': 'vmess-notls', 'add': 'vmess2.example.com', 'port': 8080, 'id': UUID, 'net': 'tcp'}).encode()).decode(),
    'vmess://' + base64.b64encode(f'auto:{UUID}@vmess3.example.com:443'.encode()).decode() + '?remarks=vmess-rocket&obfs=websocket&tls=1&cert=true&alterId=0',
    'vmess://' + EVIL,
    'ss://' + base64.b64encode(b'aes-256-gcm:sspass').decode() + '@ss.example.com:8388#ss-node',
    'trojan://trojanpw@trojan.example.com:443?sni=trojan.example.com&type=ws&path=%2Ftr&host=trojan.example.com#trojan-ws',
    'trojan://tr2@trojan2.example.com:443?sni=trojan2.example.com#trojan-tcp',
    'hysteria2://hy2pw@hy2.example.com:443?sni=hy2.example.com&obfs=salamander&obfs-password=ob&insecure=1#hy2-node',
    'hysteria://hy.example.com:443?auth=hyauth&upmbps=50&downmbps=200&alpn=h3&peer=hy.example.com#hy-node',
    'https://example.com/sub',
    'https://broken.example.com/sub',
]

def main():
    app = create_app()
    with app.app_context():
        create_db()
    c = app.test_client()
    tok = c.post('/login', json={'username': 'admin', 'password': hashlib.md5(b'admin').hexdigest()}).get_json()['token']
    H = {'Authorization': 'Bearer ' + tok}
    forged = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.x'
    assert c.post('/get_subs', headers={'Authorization': 'Bearer ' + forged}).status_code in (401, 422)

    c.post('/del_sub/测试订阅', headers=H)
    r = c.post('/create_sub', json={'name': '测试订阅', 'node': NODES + ['', 'not a node', 'class: ss']}, headers=H).get_json()
    assert r['code'] == 200, r
    assert len(c.post('/get_sub/测试订阅', headers=H).get_json()) == len(NODES)  # 无效行被过滤
    assert c.post('/create_node', json={'name': 'x', 'node': '', 'remarks': ''}, headers=H).get_json()['code'] == 400
    assert c.post('/del_sub_node/999999', headers=H).get_json()['code'] == 400
    assert c.post('/set_node', json={'id': 999999, 'node': NODES[0]}, headers=H).get_json()['code'] == 400
    assert c.post('/singbox_config', json={'index': 'save', 'text': '{bad'}, headers=H).get_json()['code'] == 400
    assert c.post('/clash_config', json={'index': 'save', 'text': 'a: [b'}, headers=H).get_json()['code'] == 400
    assert c.post('/set_conifg', json={'udp': True, 'skipcert': False, 'emoji': False}, headers=H).get_json()['code'] == 200
    assert c.post('/get_conifg', headers=H).get_json() == {'udp': True, 'skipcert': False, 'emoji': False}
    converter.settings['udp'] = False  # 模拟其它 worker 进程,生成订阅时必须重新从数据库读取

    name = base64.b64encode('测试订阅'.encode()).decode()
    out = {}
    for target in converter.ENCODERS:
        resp = c.get(f'/sub/{target}/{name}')
        assert resp.status_code == 200, (target, resp.status_code)
        out[target] = resp.data.decode('utf-8')
        print(f'{target:8} {len(resp.data):7} bytes')
    assert c.get(f'/sub/unknown/{name}').get_json()['code'] == 400
    for target, filename in (('clash', 'clash.yaml'), ('surge', 'surge.conf'), ('singbox', 'singbox.json'),
                             ('loon', 'loon.txt'), ('quanx', 'quanx.txt'), ('general', 'general.txt')):
        with open(os.path.join(OUT, filename), 'w', encoding='utf-8') as f:
            f.write(out[target])

    clash = yaml.safe_load(out['clash'])
    proxies = {p['name']: p for p in clash['proxies']}
    assert len(clash['proxies']) == 19, len(clash['proxies'])  # 本地 14 个(恶意 vmess 跳过) + 远程 5 个(拉取失败的订阅跳过)
    assert 'same-name' in proxies and 'same-name 2' in proxies  # 重名自动加序号
    assert proxies['vless-none']['tls'] is False
    assert proxies['vmess-notls']['tls'] is False and proxies['vmess-ws']['tls'] is True
    assert proxies['vmess-rocket']['skip-cert-verify'] is True and proxies['vmess-rocket']['network'] == 'ws'
    assert proxies['hy2-node']['skip-cert-verify'] is True
    assert proxies['anytls默认端口']['port'] == 443 and proxies['remote-anytls']['server'] == '2001:db8::1'
    assert proxies['🇯🇵 tuic节点']['udp'] is True  # 全局设置生效
    for group in clash['proxy-groups']:
        assert 'auto' not in group['proxies']
    names = [p['name'] for p in clash['proxies']]
    select = clash['proxy-groups'][0]['proxies']
    assert select[:2] == ['♻️ 自动选择', 'DIRECT'] and select[2:] == names, select[:4]  # auto 原位替换

    sb = json.loads(out['singbox'])
    assert 'auto' not in json.dumps([o.get('outbounds') for o in sb['outbounds']])
    assert 'ssr' not in [o['type'] for o in sb['outbounds']]

    surge = out['surge']
    assert '= tuic-v5,' in surge and '= anytls,' in surge and 'True' not in surge.split('[Proxy]')[1].split('[')[0]
    assert 'alpn=h3,' not in surge.replace('alpn=h3, ', '')  # 多个 alpn 只取第一个

    loon, quanx = out['loon'].splitlines(), out['quanx'].splitlines()
    assert any(l.startswith('vless-reality = VLESS,') and f'public-key="{PBK}"' in l for l in loon)
    assert any(l.startswith('hy2-node = Hysteria2,') and 'salamander-password=ob' in l for l in loon)
    assert any(l.startswith('ssr-node = ShadowsocksR,') for l in loon)
    assert not any('vless-grpc' in l for l in loon + quanx)
    assert any(l.startswith('vmess=vmess.example.com:443') and 'obfs=wss' in l and 'obfs-host=cdn.example.com' in l for l in quanx)
    assert any(l.startswith('trojan=trojan2.example.com:443') and 'over-tls=true' in l for l in quanx)
    assert any(l.startswith('vless=vless.example.com:443') and 'reality-base64-pubkey=' in l for l in quanx)

    general = base64.b64decode(out['general']).decode().splitlines()  # 通用格式为 base64
    assert 'https://example.com/sub' not in general and any(l.startswith('tuic://') for l in general)
    assert base64.b64decode(out['v2ray']).decode().splitlines() == general

    singbox_bin = os.environ.get('SINGBOX_BIN')
    if singbox_bin:
        subprocess.run([singbox_bin, 'check', '-c', os.path.join(OUT, 'singbox.json')], check=True)
        print('sing-box check OK')
    c.post('/del_sub/测试订阅', headers=H)
    print('ALL TESTS PASSED')

if __name__ == '__main__':
    main()
