from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from functools import wraps
import os
import json
import firebase_admin
from firebase_admin import credentials, auth

app = Flask(__name__, static_folder='.', static_url_path='')

# ========================================================
# SECURITY & PRODUCTION CONFIG
# ========================================================
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif'}

# Firebase Admin SDK の初期化（Render Secret Files 直参照）
try:
    # デバッグ用：シークレットディレクトリ内のファイル一覧をログに出力
    if os.path.exists('/etc/secrets'):
        print("Secret files available:", os.listdir('/etc/secrets'))
    else:
        print("WARNING: /etc/secrets directory not found. Local environment assumed.")

    if not firebase_admin._apps:
        # Render上の秘密ファイルへの絶対パス
        secret_path = "/etc/secrets/firebase-credentials.json"
        
        if os.path.exists(secret_path):
            cred = credentials.Certificate(secret_path)
            firebase_admin.initialize_app(cred)
            print("Firebase Admin initialized successfully.")
        else:
            print(f"WARNING: '{secret_path}' not found. Token verification will fail.")
except Exception as e:
    print(f"Firebase init error: {e}")

ADMIN_EMAIL_WHITELIST = "kd1427178@st.kobedenshi.ac.jp"

# Renderの永続ディスク用パス、またはローカルのフォールバック
STORAGE_BASE = os.environ.get('RENDER_DISK_MOUNT_PATH', '.')
UPLOAD_FOLDER = os.path.join(STORAGE_BASE, 'uploads')
DATA_FILE = os.path.join(STORAGE_BASE, 'site_data.json')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ========================================================
# DEFAULT DATA STRUCTURE
# ========================================================
default_site_data = {
    "topBannerText": "本日も明石昼網より獲れたて新鮮な「活だこ」が入荷しております！",
    "categories": [
        {"key": "octopus", "label": "明石だこ・鮮魚"},
        {"key": "kushikatsu", "label": "名物 串カツ"},
        {"key": "ippin", "label": "大将手作りの逸品"},
        {"key": "drinks", "label": "厳選の美酒"}
    ],
    "specialRecommendation": {
        "badge": "本日のイチオシ",
        "title": "極上 明石だこの姿造り",
        "desc": "コリコリとした抜群の歯ごたえと、噛むほどに広がる濃厚な甘み。吸盤の湯引きも添えて、本場の味をお届けします。",
        "price": "1,480円（税込1,628円）",
        "image": "images/reco_octopus.jpg"
    },
    "menuItems": [
        {
            "id": "item-oct-01",
            "category": "octopus",
            "name": "明石だこぶつ切り（湯引き）",
            "price": "880円",
            "desc": "職人が絶妙な火加減でサッと茹で上げました。特製ポン酢または梅肉でさっぱりとどうぞ。",
            "image": "images/menu_oct_butsu.jpg",
            "isAvailable": True
        }
    ]
}

def load_site_data():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_site_data, f, ensure_ascii=False, indent=4)
        return default_site_data
    
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading site_data.json: {e}")
        return default_site_data

def save_site_data(data):
    try:
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        return True
    except Exception as e:
        print(f"Error saving site_data.json: {e}")
        return False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ========================================================
# SECURITY AUTHENTICATION DECORATOR MIDDLEWARE
# ========================================================
def require_admin_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"success": False, "message": "認証エラー: ログインしてください"}), 401
        
        id_token = auth_header.split('Bearer ')[1]
        
        try:
            decoded_token = auth.verify_id_token(id_token)
            user_email = decoded_token.get('email')
            
            if user_email != ADMIN_EMAIL_WHITELIST:
                return jsonify({"success": False, "message": f"アクセス拒否: {user_email} は管理者権限がありません"}), 403
                
            return f(*args, **kwargs)
            
        except Exception as e:
            return jsonify({"success": False, "message": f"認証トークンの検証に失敗しました: {str(e)}"}), 401
            
    return decorated_function

# ========================================================
# API SERVER ROUTING ENDPOINTS
# ========================================================

@app.route('/api/site-data', methods=['GET'])
def get_site_data():
    return jsonify(load_site_data())

@app.route('/api/site-data', methods=['POST'])
@require_admin_token
def update_site_data():
    try:
        new_data = request.get_json()
        if not new_data:
            return jsonify({"success": False, "message": "データが空です"}), 400
            
        if save_site_data(new_data):
            return jsonify({"success": True, "message": "ウェブサイトのデータを正常に更新保存しました！"})
        else:
            return jsonify({"success": False, "message": "ファイルへの書き込みに失敗しました"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/upload', methods=['POST'])
@require_admin_token
def upload_file():
    try:
        if 'image' not in request.files:
            return jsonify({"success": False, "message": "ファイルが見つかりません"}), 400
            
        file = request.files['image']
        if file.filename == '':
            return jsonify({"success": False, "message": "ファイル名が空です"}), 400

        if not allowed_file(file.filename):
            return jsonify({"success": False, "message": "許可されていないファイル形式です（画像のみ可）"}), 400

        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        counter = 1
        final_filename = filename

        while os.path.exists(os.path.join(UPLOAD_FOLDER, final_filename)):
            final_filename = f"{base}_{counter}{ext}"
            counter += 1

        save_path = os.path.join(UPLOAD_FOLDER, final_filename)
        file.save(save_path)

        return jsonify({
            "success": True,
            "path": f"/uploads/{final_filename}"
        })

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/uploads/<filename>')
def serve_uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/admin')
def serve_admin():
    return send_from_directory('.', 'admin.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
