# server.py - نسخة للأندرويد
from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime, timedelta
import jwt
import secrets
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-super-secret-key-change-this'
DB_PATH = 'sessions.db'
ID_FILE = 'id.txt'

# ========== قراءة IDs من الملف ==========

def load_allowed_ids():
    """قراءة Telegram IDs المسموح لهم من id.txt"""
    try:
        with open(ID_FILE, 'r') as f:
            ids = set()
            for line in f:
                line = line.strip()
                if line and line.isdigit():
                    ids.add(int(line))
            return ids
    except FileNotFoundError:
        return set()

def is_allowed(telegram_id):
    """التحقق إذا الـ ID موجود في id.txt"""
    return int(telegram_id) in load_allowed_ids()

# ========== Database Setup ==========

def init_db():
    """إنشاء قاعدة بيانات الجلسات فقط"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            session_token TEXT UNIQUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ========== Helper Functions ==========

def generate_session_token(telegram_id, device_id):
    """توليد JWT token"""
    payload = {
        'telegram_id': telegram_id,
        'device_id': device_id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_session_token(token):
    """التحقق من التوكن"""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return True, payload
    except jwt.ExpiredSignatureError:
        return False, "Session expired"
    except jwt.InvalidTokenError:
        return False, "Invalid token"

# ========== Admin Routes ==========

@app.route('/admin/list', methods=['POST'])
def admin_list():
    """عرض كل IDs الموجودة في id.txt"""
    data = request.get_json()
    if data.get('admin_key') != 'YOUR-ADMIN-SECRET-KEY':
        return jsonify({'error': 'Unauthorized'}), 401

    ids = load_allowed_ids()
    return jsonify({
        'success': True,
        'count': len(ids),
        'ids': list(ids)
    })

@app.route('/admin/add', methods=['POST'])
def admin_add():
    """إضافة ID جديد إلى id.txt"""
    data = request.get_json()
    if data.get('admin_key') != 'YOUR-ADMIN-SECRET-KEY':
        return jsonify({'error': 'Unauthorized'}), 401

    telegram_id = str(data.get('telegram_id', '')).strip()
    if not telegram_id.isdigit():
        return jsonify({'error': 'Invalid Telegram ID'}), 400

    ids = load_allowed_ids()
    if int(telegram_id) in ids:
        return jsonify({'error': 'ID already exists'}), 400

    with open(ID_FILE, 'a') as f:
        f.write(telegram_id + '\n')

    return jsonify({'success': True, 'message': f'ID {telegram_id} added'})

@app.route('/admin/remove', methods=['POST'])
def admin_remove():
    """حذف ID من id.txt"""
    data = request.get_json()
    if data.get('admin_key') != 'YOUR-ADMIN-SECRET-KEY':
        return jsonify({'error': 'Unauthorized'}), 401

    telegram_id = int(data.get('telegram_id', 0))
    ids = load_allowed_ids()

    if telegram_id not in ids:
        return jsonify({'error': 'ID not found'}), 404

    ids.discard(telegram_id)

    with open(ID_FILE, 'w') as f:
        for tid in ids:
            f.write(str(tid) + '\n')

    return jsonify({'success': True, 'message': f'ID {telegram_id} removed'})

# ========== Client Routes ==========

@app.route('/auth/activate', methods=['POST'])
def activate():
    """تفعيل الأداة"""
    data = request.get_json()

    telegram_id = data.get('telegram_id')
    device_id = data.get('device_id')

    if not telegram_id or not device_id:
        return jsonify({'error': 'Missing telegram_id or device_id'}), 400

    # التحقق من الـ ID في الملف
    if not is_allowed(telegram_id):
        return jsonify({'error': 'غير مشترك أو غير مصرح له'}), 403

    # إنشاء توكن جلسة
    session_token = generate_session_token(telegram_id, device_id)
    expires_at = (datetime.utcnow() + timedelta(hours=24)).isoformat()

    conn = get_db()
    cursor = conn.cursor()

    # حذف الجلسات القديمة لنفس الجهاز
    cursor.execute(
        'DELETE FROM sessions WHERE telegram_id = ? AND device_id = ?',
        (telegram_id, device_id)
    )

    cursor.execute('''
        INSERT INTO sessions (telegram_id, device_id, session_token, expires_at)
        VALUES (?, ?, ?, ?)
    ''', (telegram_id, device_id, session_token, expires_at))

    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'session_token': session_token,
        'expires_at': expires_at,
        'message': 'تم التفعيل بنجاح'
    })

@app.route('/auth/verify', methods=['GET'])
def verify():
    """التحقق من الجلسة"""
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid token'}), 401

    token = auth_header.split(' ')[1]
    valid, payload = verify_session_token(token)

    if not valid:
        return jsonify({'error': payload}), 401

    # التحقق إن الـ ID لا يزال في الملف
    telegram_id = payload.get('telegram_id')
    if not is_allowed(telegram_id):
        return jsonify({'error': 'تم إلغاء الاشتراك'}), 403

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM sessions WHERE session_token = ?', (token,))
    session = cursor.fetchone()
    conn.close()

    if not session:
        return jsonify({'error': 'Session not found'}), 401

    if datetime.utcnow() > datetime.fromisoformat(session['expires_at']):
        return jsonify({'error': 'Session expired'}), 401

    return jsonify({
        'success': True,
        'telegram_id': telegram_id,
        'device_id': payload.get('device_id'),
        'expires_at': session['expires_at']
    })

@app.route('/auth/heartbeat', methods=['POST'])
def heartbeat():
    """نبضة قلب"""
    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return jsonify({'error': 'Missing token'}), 401

    token = auth_header.split(' ')[1]
    valid, payload = verify_session_token(token)

    if not valid:
        return jsonify({'error': 'Invalid session'}), 401

    # تحقق إضافي من الملف
    if not is_allowed(payload.get('telegram_id')):
        return jsonify({'error': 'غير مصرح له'}), 403

    return jsonify({'success': True, 'status': 'alive'})

@app.route('/')
def home():
    return jsonify({'status': 'Server is running', 'version': '2.0'})

# ========== Initialize ==========

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)