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
# Enforce a 5MB maximum file upload payload restriction (Prevents DoS attacks)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

# Explicitly whitelist allowed image extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif'}

# Initialize Firebase Admin SDK inside the backend
# In production, set the GOOGLE_APPLICATION_CREDENTIALS environment variable 
# pointing to your downloaded service account JSON file.
try:
    if not firebase_admin._apps:
        firebase_admin.initialize_app()
except Exception as e:
    print(f"Warning: Firebase Admin failed to load automatically. Error: {e}")
    print("Ensure GOOGLE_APPLICATION_CREDENTIALS env variable is configured in your production hosting platform.")

# Whitelisted Administrator Email Target Address
ADMIN_EMAIL_WHITELIST = "kd1427178@st.kobedenshi.ac.jp"

STORAGE_BASE = os.environ.get('RENDER_DISK_MOUNT_PATH', '.')
UPLOAD_FOLDER = os.path.join(STORAGE_BASE, 'uploads')
DATA_FILE = os.path.join(STORAGE_BASE, 'site_data.json')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Helper extension checker
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ========================================================
# BACKEND SECURITY DECORATOR
# ========================================================
def require_admin_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"success": False, "message": "認証エラー：ログイン情報が見つかりません。"}), 401
        
        # Extract ID token passed from client
        id_token = auth_header.split('Bearer ')[1]
        try:
            # Verify the validity and integrity of the token via Firebase server side
            decoded_token = auth.verify_id_token(id_token)
            user_email = decoded_token.get('email')
            
            # Check if authenticated user matches target email
            if user_email != ADMIN_EMAIL_WHITELIST:
                return jsonify({"success": False, "message": "アクセス拒否：認可されていないアカウントです。"}), 403
                
        except Exception as err:
            return jsonify({"success": False, "message": f"認証トークンの検証に失敗しました: {str(err)}"}), 401
            
        return f(*args, **kwargs)
    return decorated_function

# ========================================================
# DEFAULT BACKEND STRUCT INITIALIZATION
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
        "subtitle": "CHEF'S SPECIALS",
        "title": "店主厳選の極み一皿",
        "footer": {
            "open": "営業時間: 17:00 〜 24:00 (L.O. 23:30)",
            "extra": "※仕入れ状況により売り切れ次第終了"
        },
        "items": [
            {
                "category": "看板料理",
                "name": "明石だこのレアぶつ切り",
                "description": "コリコリ抜群の歯ごたえと噛むほどに溢れる甘み",
                "image": "",
                "icon": "fa-solid fa-star"
            }
        ]
    },
    "galleryData": [],
    "menuData": []
}

def load_site_data():
    if not os.path.exists(DATA_FILE):
        return default_site_data
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default_site_data

# ========================================================
# API ROUTES
# ========================================================
@app.route('/api/site-data', methods=['GET'])
def get_site_data():
    return jsonify(load_site_data())

@app.route('/api/site-data', methods=['POST'])
@require_admin_auth  # Protected Route
def save_site_data():
    try:
        new_data = request.get_json()
        if not new_data:
            return jsonify({"success": False, "message": "データが空です"}), 400
            
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(new_data, f, ensure_ascii=False, indent=4)
            
        return jsonify({"success": True, "message": "サーバー上のサイトデータを正常に更新しました。"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/upload', methods=['POST'])
@require_admin_auth  # Protected Route
def upload_file():
    try:
        if 'image' not in request.files:
            return jsonify({"success": False, "message": "ファイルが見つかりません"}), 400
            
        file = request.files['image']
        if file.filename == '':
            return jsonify({"success": False, "message": "ファイル名が空です"}), 400

        # Validate file suffix matching extensions array rules
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
    # For local testing only. Production environments should use a WSGI server like Gunicorn.
    app.run(host='0.0.0.0', port=5000, debug=False)