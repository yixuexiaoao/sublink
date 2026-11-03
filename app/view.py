import datetime
import json
from io import BytesIO
from flask import Blueprint,request,jsonify,render_template,send_file,make_response
from .model import *
from . import converter
import base64,yaml,urllib.parse,os
from flask_jwt_extended import jwt_required,get_jwt_identity,create_access_token,create_refresh_token
blue = Blueprint('blue',__name__)
path = os.path.dirname(os.path.abspath(__file__))
subname_list =['vless','vmess','ss','ssr','trojan','hysteria','hy2','hysteria2','tuic','anytls','http','https']
def is_valid_node(node): # 只按协议头判断,避免 'ss' 之类的关键字误匹配任意文本
    return converter.node_scheme(node) in subname_list
def split_nodes(nodes): # 批量节点 "节点|备注" 拆分,过滤无效行
    result = []
    for i in nodes or []:
        node, _, remarks = i.strip().partition('|')
        node = node.strip()
        if node != '' and is_valid_node(node):
            result.append((node, remarks))
    return result
def db_commit(): # 提交事务,失败回滚并返回错误响应
    try:
        db.session.commit()
        return None
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'code': 400,
            'msg': '错误信息：' + str(e)
        })
def save_ip_address(): # 记录登录ip地址,查询失败不影响登录
    ip_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    address = ''
    try:
        res = converter.http.get('https://whois.pconline.com.cn/ipJson.jsp', params={'ip': ip_address, 'json': 'true'}, timeout=5)
        if res.status_code == 200 and res.text:
            address = json.loads(res.text).get('addr', '')
    except Exception as e:
        print('查询ip地址失败:' + str(e))
    timer = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    db.session.add(Login(ip=ip_address, address=address, time=timer))
    db_commit()
def decode_base64_if_emoji(encoded_text):#base64带emoji解码
    encoded_text = urllib.parse.unquote(encoded_text)
    return base64.b64decode(encoded_text.encode('utf-8')).decode('utf-8')
def load_config(): # 从数据库加载全局设置(多个 worker 进程之间保持一致)
    data = {}
    for i in Config.query.all():
        data[i.key] = str(i.value).lower() in ('1', 'true')  # 旧版本存的是布尔值
        if i.key in converter.settings:
            converter.settings[i.key] = data[i.key]
    return data
@blue.route('/sub/<string:target>/<path:name>',methods=['GET']) #订阅地址
def get_sub_url(target,name):
    try:
        name = decode_base64_if_emoji(name)
    except Exception:
        return jsonify({'code': 400, 'msg': '订阅名称错误'})
    encoder = converter.ENCODERS.get(target.lower())
    if not encoder:
        return jsonify({
            'code': 400,
            'msg': '不支持的订阅类型,可选:' + ' '.join(converter.ENCODERS)
        })
    subs = Sub.query.filter_by(name=name).all()
    if not subs:
        return jsonify({
            'code':400,
            'msg':'订阅不存在'
        })
    load_config()
    encode, mimetype, suffix = encoder
    data = encode(converter.collect_links(subs))
    if target.lower() == 'surge':
        data = f'#!MANAGED-CONFIG {request.url} interval=86400 strict=false\n' + data #更新时间
    return make_response(send_file(BytesIO(data.encode('utf-8')), mimetype=mimetype, as_attachment=False,
                                   download_name=name + suffix))
def template_config(filename, validate): # 规则模板读取/保存
    data = request.get_json()
    index = data.get('index')
    file_path = os.path.join(path, 'db', filename)
    if index == 'read':
        with open(file_path, 'r', encoding='utf-8') as file:
            return jsonify({
                'code':200,
                'msg':file.read()
            })
    if index == 'save':
        text = data.get('text')
        if not text:
            return jsonify({
                'code': 400,
                'msg': '不能为空'
            })
        try:
            validate(text)
        except Exception as e:
            return jsonify({
                'code': 400,
                'msg': '格式错误:' + str(e)
            })
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(text)
        return jsonify({
            'code':200,
            'msg':'保存成功'
        })
    return jsonify({'code': 400, 'msg': '参数错误'})
@blue.route('/clash_config',methods=['POST']) #clash配置修改
@jwt_required()
def clash_config():
    return template_config('clash.yaml', yaml.safe_load)
@blue.route('/surge_config',methods=['POST']) #surge配置修改
@jwt_required()
def surge_config():
    return template_config('surge.conf', lambda text: None)
@blue.route('/singbox_config',methods=['POST']) #sing-box配置修改
@jwt_required()
def singbox_config():
    return template_config('singbox.json', json.loads)

@blue.route('/') #前台程序
def get_index():
    return render_template('index.html')
@blue.route('/login',methods=['POST'])
def get_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({
            'code': 404,
            'msg': '账号不存在'
        })
    if user.username == username and user.password == password:
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)
        save_ip_address() # 记录登录ip
        return jsonify({
            'code': 200,
            'token':access_token,
            'refresh':refresh_token,
            'msg': '登录成功'
        })
    return jsonify({
        'code':404,
        'msg':'账号或者密码错误'
    })
@blue.route('/refresh' ,methods=['POST']) #刷新令牌
@jwt_required(refresh=True)
def get_refresh():
    current_user = get_jwt_identity()
    if current_user:
        return create_access_token(current_user)
    return '没获取到'
@blue.route('/create_sub',methods=['POST']) # 新建订阅
@jwt_required()
def get_create_sub():
    data = request.get_json()
    name = data.get('name')
    if not name:
        return jsonify({'code': 400, 'msg': '订阅名称不能为空'})
    if Sub.query.filter_by(name=name).first():
        return jsonify({
            'code':400,
            'msg':'订阅名字已经存在'
        })
    nodes = split_nodes(data.get('node'))
    if not nodes:
        return jsonify({'code': 400, 'msg': '没有有效的节点或订阅'})
    db.session.add_all([Sub(name=name, node=node, remarks=remarks) for node, remarks in nodes])
    return db_commit() or jsonify({
        'code':200,
        'msg':'创建成功'
    })
@blue.route('/create_node',methods=['POST']) # 新建节点
@jwt_required()
def create_node():
    data = request.get_json()
    name = data.get('name')
    remarks = data.get('remarks') or ''
    node = (data.get('node') or '').strip()
    if not is_valid_node(node):
        return jsonify({
            'code': 400,
            'msg': '不是有效的协议,请检查后重新输入'
        })
    db.session.add(Sub(name=name, node=node, remarks=remarks))
    return db_commit() or jsonify({
        'code': 200,
        'msg': '创建成功'
    })
@blue.route('/get_subs',methods=['POST']) #获取所有的订阅
@jwt_required()
def get_subs():
    data = []
    for sub in Sub.query.all():
        data.append({
            'id':sub.id,
            'name':sub.name,
            'node':sub.node,
            'remarks':sub.remarks if sub.remarks !='' else '无备注'
        })
    return jsonify(data)
@blue.route('/rename_sub/<path:name>',methods=['POST']) #修改订阅名称
@jwt_required()
def rename_sub(name):
    newName = request.get_json().get('newName')
    if not newName:
        return jsonify({'code': 400, 'msg': '名字不能为空'})
    if Sub.query.filter_by(name=newName).first():
        return jsonify({
            'code': 400,
            'msg': f'名字已存在'
        })
    Sub.query.filter_by(name=name).update({'name': newName})
    return db_commit() or jsonify({
        'code':200,
        'msg':'成功'
    })
@blue.route('/get_sub/<path:name>',methods=['POST']) #获取单个订阅
@jwt_required()
def get_sub(name):
    data = []
    for sub in Sub.query.filter_by(name=name).all():
        data.append({
            'id':sub.id,
            'name':sub.name,
            'node':sub.node,
            'remarks':sub.remarks if sub.remarks !='' else 'null'
        })
    return jsonify(data)
@blue.route('/del_sub/<path:name>',methods=['POST']) #删除指定订阅
@jwt_required()
def del_sub(name):
    if not Sub.query.filter_by(name=name).delete():
        return jsonify({
            'code': 400,
            'msg': '不存在'
        })
    return db_commit() or jsonify({
        'code': 200,
        'msg': '删除成功'
    })
@blue.route('/del_sub_node/<int:id>',methods=['POST']) #删除指定节点
@jwt_required()
def del_sub_node(id):
    sub = Sub.query.filter_by(id=id).first()
    if not sub:
        return jsonify({
            'code': 400,
            'msg': '不存在'
        })
    db.session.delete(sub)
    return db_commit() or jsonify({
        'code': 200,
        'msg': '删除成功'
    })
@blue.route('/set_sub',methods=['POST']) # 修改节点
@jwt_required()
def get_set_sub():
    data = request.get_json()
    name = data.get('name')
    nodes = split_nodes(data.get('newNode'))
    if not nodes:
        return jsonify({'code': 400, 'msg': '没有有效的节点或订阅'})
    # 删除旧节点和写入新节点在同一个事务里,失败不会丢数据
    Sub.query.filter_by(name=name).delete()
    db.session.add_all([Sub(name=name, node=node, remarks=remarks) for node, remarks in nodes])
    return db_commit() or jsonify({
        'code':200,
        'msg':'修改成功'
    })
@blue.route('/set_node',methods=['POST']) # 修改单个节点
@jwt_required()
def get_set_node():
    data = request.get_json()
    node = (data.get('node') or '').strip()
    if not is_valid_node(node):
        return jsonify({
            'code': 400,
            'msg': '节点格式不对'
        })
    sub = Sub.query.filter_by(id=data.get('id')).first()
    if not sub:
        return jsonify({'code': 400, 'msg': '节点不存在'})
    sub.node = node
    sub.remarks = data.get('remarks') or ''
    return db_commit() or jsonify({
        'code': 200,
        'msg': '修改成功'
    })
@blue.route('/set_user',methods=['POST']) # 修改账号信息
@jwt_required()
def get_set_user():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if not user:
        return jsonify({
            'code':400,
            'msg':'账号不正确'
        })
    user.username = data.get('newUserName')
    user.password = data.get('password')
    return db_commit() or jsonify({
        'code': 200,
        'msg': '修改成功'
    })
@blue.route('/decode_sub',methods=['POST']) # 订阅解析
@jwt_required()
def decode_sub():
    datas = []
    for url in request.get_json().get('urls') or []:
        try:
            response = converter.http.get(url, timeout=converter.HTTP_TIMEOUT)
        except Exception as e:
            return jsonify({'code': 400, 'msg': f'拉取失败: {e}'})
        if response.status_code != 200:
            return jsonify({
                'code': response.status_code,
                'msg': response.text
            })
        datas.append(converter.decode_sub_text(response.text))
    return jsonify({
        'code': 200,
        'msg': datas
    })
@blue.route('/get_ip_address',methods=['POST']) # 获取已经登录过的ip记录
@jwt_required()
def get_ip_address():
    data = []
    for i in Login.query.order_by(Login.time.desc()).all():
        data.append({
            'id':i.id,
            'ip':i.ip,
            'address':i.address,
            'time':i.time
        })
    return jsonify(data)
@blue.route("/set_conifg",methods=['POST'])
@jwt_required()
def set_config():
    data = request.get_json()
    for key in ('udp', 'skipcert', 'emoji'):
        Config.query.filter_by(key=key).delete()
        db.session.add(Config(key=key, value='1' if data.get(key) else '0'))
    return db_commit() or jsonify({
        'code':200,
        'msg':'设置保存成功'
    })
@blue.route("/get_conifg",methods=['POST'])
@jwt_required()
def get_config():
    return jsonify(load_config())
