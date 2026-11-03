from flask import Flask
from .exts import init_exts
from .view import blue
from datetime import timedelta
import os,secrets
def jwt_secret(db_dir): # JWT密钥: 优先环境变量,否则首次启动随机生成并保存到数据目录(多进程共用)
    secret = os.environ.get('JWT_SECRET_KEY')
    if secret:
        return secret
    file_path = os.path.join(db_dir, 'jwt_secret')
    try:
        fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as file:
            file.write(secrets.token_hex(32))
    except FileExistsError:
        pass
    with open(file_path, 'r') as file:
        return file.read().strip()
def create_app():
    app = Flask(__name__)
    app.register_blueprint(blueprint=blue)
    path = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(path + '/db', exist_ok=True)  # 未挂载数据目录时自动创建,否则sqlite无法打开数据库
    db_url = 'sqlite:///' + path + '/db/sub.db'
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config["JWT_SECRET_KEY"] = jwt_secret(path + '/db')  # 原来固定为"sub",任何人都能伪造登录令牌
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)  #30分钟后过期
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=15)  #15天后刷新令牌过期
    app.config['TRUSTED_PROXIES'] = ['proxy_ip']
    env = os.environ.get('ENV')
    if env == 'development':
        print(f'你现在处于开发环境{env}')
    else:
        print(f'你现在处于部署环境{env}')
    init_exts(app=app) #第三方插件绑定app
    return app
