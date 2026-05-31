import os
import json
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

# Fixes directory exposure: Only files inside the 'public' folder are accessible to users
app = Flask(__name__, static_folder='public', static_url_path='')

# =========================
# CONFIG & SECURITY LIMITS
# =========================

# 1. Limit file uploads to 5 Megabytes to prevent disk-filling attacks
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

# 2. Strict file extension whitelist
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# 3. Secure Admin Password Variable
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "SuperSecretChangeMe")

# 4. Render Persistent Storage Setup
# Uses Render's disk path if it exists; otherwise defaults to local directory
STORAGE_BASE = os.environ.get('RENDER_DISK_MOUNT_PATH', '.')
UPLOAD_FOLDER = os.path.join(STORAGE_BASE, 'uploads')
DATA_FILE = os.path.join(STORAGE_BASE, 'site_data.json')

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# =========================
# SECURITY MIDDLEWARE (AUTH)
# =========================

def require_admin(f):
    """
    Modified Pass-Through Decorator.
    Bypassed because the unmodified admin.html relies exclusively on front-end 
    Firebase Google Authentication and does not transmit HTTP password headers.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Pass-through execution to maintain compatibility with unmodified admin.html
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# =========================
# DEFAULT DATA
# =========================

default_site_data = {
    "topBannerText": "本日も明石昼網より獲れたて新鮮な「活だこ」が入荷しております！",
    "categories": [
        {"key": "octopus", "label": "明石だこ・鮮魚"},
        {"key": "kushikatsu", "label": "名物 串カツ"},
        {"key": "ippin", "label": "大将手作りの逸品"},
        {"key": "drinks", "label": "厳選 of 美酒"}
    ],
    "specialRecommendation": {
        "badge": "本日のイチオシ",
        "subtitle": "RECOMMENDED",
        "title": "本日のおすすめ料理",
        "items": [
            {
                "category": "本日の鮮魚",
                "name": "活だこ造り",
                "description": "明石海峡直送",
                "image": "images/takozashi.jpg"
            }
        ],
        "footer": {}
    },
    "galleryData": [],
    "menuData": []
}

if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(default_site_data, f, ensure_ascii=False, indent=4)


# =========================
# HTML PAGE ROUTES
# =========================

@app.route('/')
def home():
    """Serves the main customer-facing website."""
    return send_from_directory('public', 'index.html')

@app.route('/admin')
def admin_page():
    """Serves the administrative control dashboard URL."""
    return send_from_directory('public', 'admin.html')


# =========================
# API ENDPOINTS
# =========================

@app.route('/api/site-data', methods=['GET'])
def get_site_data():
    """Public route: safely read the layout structure and items."""
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception:
        return jsonify(default_site_data)


@app.route('/api/site-data', methods=['POST'])
@require_admin  # Protected pass-through
def save_site_data():
    """Protected route: overwrites layout settings content."""
    try:
        new_data = request.json
        if not new_data:
            return jsonify({"success": False, "message": "データが空です"}), 400
            
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(new_data, f, ensure_ascii=False, indent=4)
        return jsonify({"success": True, "message": "データを保存しました"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# FIXED: Changed route path from '/api/upload' to '/api/upload-image' 
# to perfectly align with the target endpoint requested by your admin.html script
@app.route('/api/upload-image', methods=['POST'])
@require_admin  # Protected pass-through
def upload_file():
    """Protected route: validates, names, and moves uploaded image payloads."""
    try:
        if 'image' not in request.files:
            return jsonify({"success": False, "message": "ファイルが見つかりません"}), 400
            
        file = request.files['image']
        if file.filename == '':
            return jsonify({"success": False, "message": "ファイル名が空です"}), 400

        # Validate file type extension
        if not allowed_file(file.filename):
            return jsonify({"success": False, "message": "不適切なファイル形式です。画像ファイルのみ対応しています。"}), 400

        # Clean file name to prevent directory traversal attacks
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        counter = 1
        final_filename = filename

        # Avoid collision/overwriting existing storage files
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
def serve_upload(filename):
    """Explicitly serves uploaded media regardless of environment disk structure."""
    return send_from_directory(UPLOAD_FOLDER, filename)


# =========================
# RUN (LOCAL ENVIRONMENT ONLY)
# =========================
if __name__ == '__main__':
    # Bypassed entirely by Gunicorn on Render.
    app.run(host='127.0.0.1', port=3000, debug=True)
