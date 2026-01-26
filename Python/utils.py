import customtkinter as ctk
import pyperclip, os, hashlib, config, cv2, aes, io, json, time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
import numpy as np
from PIL import Image, ImageFilter

def read_qr_from_bytes(image_bytes):
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return None
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img)
        return data
    except Exception as e:
        return None

def load_otps_from_decrypted(decrypted_otps):
    return sorted(decrypted_otps, key=lambda x: x.get('platform', '').lower())

def clean_uri(uri):
    if not uri or "otpauth://" not in uri:
        return "", "", ""
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)
    label = unquote(parsed.path.split('/')[-1])
    if ':' in label:
        label_issuer, username = label.split(':', 1)
    else:
        label_issuer = username = label
    query_issuer = query.get("issuer", [label_issuer])[0]
    if label_issuer != query_issuer:
        query['issuer'] = [label_issuer]
    parsed = parsed._replace(query=urlencode(query, doseq=True))
    return urlunparse(parsed), label_issuer, username

def generate_id(platform, secret, salt=None):
    if salt is None:
        salt = str(time.time())
    combo = f"{platform}{secret}{salt}"
    return hashlib.sha256(combo.encode()).hexdigest()

def save_otps_encrypted(otp_list, key):
    crypto = aes.Crypto(key)
    json_data = json.dumps(otp_list)
    encrypted_data = crypto.encrypt_aes(json_data)
    with open(config.ENCODED_FILE, 'w') as f:
        f.write(encrypted_data)

def decode_encrypted_file():
    if not config.decrypt_key: return []
    if not os.path.exists(config.ENCODED_FILE): return []
    
    crypto = aes.Crypto(config.decrypt_key)
    try:
        with open(config.ENCODED_FILE, 'r') as infile:
            content = infile.read().strip()
            if not content: return []
            
            try:
                decrypted_content = crypto.decrypt_aes(content)
                data = json.loads(decrypted_content)
                if isinstance(data, list):
                    return data
            except Exception:
                return [] 
    except Exception:
        return []
    return []

def extract_secret_from_uri(uri):
    try:
        parsed = urlparse(uri)
        query = parse_qs(parsed.query)
        return query.get('secret', [None])[0]
    except Exception:
        return None

def load_image_paths():
    if not os.path.exists(config.IMAGE_PATH_FILE):
        return {}
    try:
        with open(config.IMAGE_PATH_FILE, 'r') as f:
            content = f.read().strip()
            if not content:
                return {}
            return json.loads(content)
    except Exception:
        return {}

def save_image_path(cred_id, enc_img_path):
    image_paths = load_image_paths()
    image_paths[cred_id] = enc_img_path
    try:
        with open(config.IMAGE_PATH_FILE, 'w') as f:
            f.write(json.dumps(image_paths))
        return True
    except Exception:
        return False

def get_image_path(cred_id):
    image_paths = load_image_paths()
    return image_paths.get(cred_id)

def delete_image_path(cred_id):
    image_paths = load_image_paths()
    if cred_id in image_paths:
        del image_paths[cred_id]
        try:
            with open(config.IMAGE_PATH_FILE, 'w') as f:
                f.write(json.dumps(image_paths))
            return True
        except Exception:
            return False
    return True

def get_qr_image(cred_id, key, blur=True):
    enc_img_path = get_image_path(cred_id)
    if not enc_img_path or not os.path.exists(enc_img_path):
        return None
    crypto = aes.Crypto(key)
    try:
        with open(enc_img_path, 'rb') as f:
            enc_data = f.read()
        img_bytes = crypto.decrypt_bytes(enc_data)
        img = Image.open(io.BytesIO(img_bytes))
        if img.mode != "RGBA":
            img = img.convert("RGBA")
        img = img.resize((200, 200), Image.Resampling.LANCZOS)
        if blur:
            img = img.filter(ImageFilter.GaussianBlur(radius=15))
        return img
    except Exception:
        return None

def save_password(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    pw_path = os.path.join(config.APP_FOLDER, "password.hash")
    try:
        with open(pw_path, "w") as f:
            f.write(hashed)
        try:
            os.chmod(pw_path, 0o600)
        except Exception:
            pass
        return True
    except Exception:
        return False

def get_stored_password():
    pw_path = os.path.join(config.APP_FOLDER, "password.hash")
    try:
        with open(pw_path, "r") as f:
            return f.read().strip()
    except Exception:
        return None

def delete_credential(cred_id, key):
    otps = decode_encrypted_file()
    new_otps = []
    deleted = False
    
    for cred in otps:
        if cred.get('id') == cred_id:
            enc_img_path = get_image_path(cred_id)
            if enc_img_path and os.path.exists(enc_img_path):
                try:
                    os.remove(enc_img_path)
                except Exception:
                    pass
            delete_image_path(cred_id)
            deleted = True
            continue
        new_otps.append(cred)
        
    if deleted:
        save_otps_encrypted(new_otps, key)
        return True
    return False

def bind_enter(root, button):
    root.unbind_all("<Return>")
    root.bind_all("<Return>", lambda event: button.invoke())
def truncate_platform_name(name, max_length=20):
    if len(name) > max_length:
        return name[:max_length] + "..."
    return name

def truncate_username(username, max_length=35):
    if len(username) > max_length:
        return username[:max_length] + "..."
    return username