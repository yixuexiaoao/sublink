from app import create_app
from app.model import create_db
from app.exts import db
app = create_app()
with app.app_context():
    create_db()
    db.engine.dispose()  # gunicorn --preload 时在 fork 前释放连接,各 worker 重新建立
if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True)