import customtkinter as ctk
import hashlib, os, config, utils, aes

def reencrypt_all_data(old_key, new_key):
    original_key = config.decrypt_key
    config.decrypt_key = old_key
    
    otps = utils.decode_encrypted_file()
    if not otps and os.path.exists(config.ENCODED_FILE):
        config.decrypt_key = original_key
        return False

    old_crypto = aes.Crypto(old_key)
    new_crypto = aes.Crypto(new_key)
    
    try:
        image_paths = utils.load_image_paths()
        for cred_id, enc_img_path in image_paths.items():
            if enc_img_path and os.path.exists(enc_img_path):
                try:
                    with open(enc_img_path, 'rb') as img_f:
                        old_enc_data = img_f.read()
                    
                    raw_img_data = old_crypto.decrypt_bytes(old_enc_data)
                    new_enc_data = new_crypto.encrypt_bytes(raw_img_data)
                    
                    with open(enc_img_path, 'wb') as img_f:
                        img_f.write(new_enc_data)
                except Exception as e:
                    print(f"Warning: Failed to re-encrypt image {enc_img_path}: {e}")

        utils.save_otps_encrypted(otps, new_key)
        
        config.decrypt_key = new_key
        return True
    except Exception as e:
        print(f"Re-encryption failed: {e}")
        config.decrypt_key = original_key
        return False

def reset_password_full_ui(root, otp_entries, build_main_ui_callback):
    for widget in root.winfo_children():
        widget.destroy()
    
    frame = ctk.CTkFrame(root, fg_color="#1e1e1e", corner_radius=0)
    frame.pack(expand=True, fill="both")
    
    root.unbind_all("<Return>")
    root.unbind_all("<Escape>")

    def create_entry(label_text):
        ctk.CTkLabel(frame, text=label_text, text_color="white", font=("Segoe UI", 14, "bold")).pack(pady=(15, 5))
        row = ctk.CTkFrame(frame, fg_color="transparent")
        entry = ctk.CTkEntry(row, show="*", font=("Segoe UI", 14), justify="center", width=210, height=40)
        entry.pack(side="left")
        entry.is_hidden = True
        toggle_lbl = ctk.CTkLabel(row, text="👁️", width=48, height=44, fg_color="#444", text_color="white", corner_radius=10, font=("Segoe UI Emoji", 20))
        def toggle_click(ev=None, e=entry, l=toggle_lbl):
            if getattr(e, 'is_hidden', True):
                e.configure(show="")
                e.is_hidden = False
                l.configure(text="🙈")
            else:
                e.configure(show="*")
                e.is_hidden = True
                l.configure(text="👁️")
        toggle_lbl.bind("<Button-1>", toggle_click)
        toggle_lbl.pack(side="left", padx=(8,0))
        row.pack()
        return entry

    ctk.CTkLabel(frame, text="🔐 Reset Password", font=("Segoe UI", 20, "bold"), text_color="white").pack(pady=(40, 30))

    current_entry = create_entry("Enter current password:")
    current_entry.focus_set()
    new_entry = create_entry("New password:")
    confirm_entry = create_entry("Confirm new password:")

    button_frame = ctk.CTkFrame(frame, fg_color="transparent")
    button_frame.pack(pady=30)

    def show_toast(message, is_error=False):
        if config.toast_label:
            config.toast_label.destroy()
        color = "#ff4d4d" if is_error else "#22cc22"
        config.toast_label = ctk.CTkLabel(root, text=message, fg_color=color, text_color="white",
                               font=("Segoe UI", 14), corner_radius=10, padx=16, pady=12)
        config.toast_label.place(relx=0.5, rely=0.9, anchor='s')
        root.after(2500, lambda: config.toast_label.destroy() if config.toast_label else None)

    def perform_reset():
        stored_hash = utils.get_stored_password()
        current_pwd = current_entry.get()
        current_hash = hashlib.sha256(current_pwd.encode()).hexdigest()
        
        if current_hash != stored_hash:
            show_toast("❌ Incorrect current password", is_error=True)
        elif new_entry.get() != confirm_entry.get():
            show_toast("❌ New passwords do not match", is_error=True)
        elif len(new_entry.get()) < 8:
            show_toast("❌ Password too short (min 8 chars)", is_error=True)
        else:
            new_pwd = new_entry.get()
            if reencrypt_all_data(current_pwd, new_pwd):
                utils.save_password(new_pwd)
                config.decrypt_key = new_pwd
                otp_entries[:] = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
                show_toast("✅ Password reset successfully")
                root.after(1500, lambda: build_main_ui_callback(root, otp_entries))
            else:
                show_toast("❌ Failed to re-encrypt data", is_error=True)

    def go_back():
        otp_entries[:] = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
        build_main_ui_callback(root, otp_entries)

    reset_btn = ctk.CTkButton(button_frame, text="✅ Submit", command=perform_reset,
                          font=("Segoe UI", 13, "bold"), width=120, height=40, fg_color="#444")
    reset_btn.pack(side="left", padx=5)
    
    cancel_btn = ctk.CTkButton(button_frame, text="❌ Cancel", command=go_back,
                          font=("Segoe UI", 13, "bold"), width=120, height=40, fg_color="#3d3d3d")
    cancel_btn.pack(side="left", padx=5)

    def safe_perform_reset(event=None):
        try:
            if current_entry.winfo_exists() and new_entry.winfo_exists() and confirm_entry.winfo_exists():
                perform_reset()
        except Exception:
            pass
    
    def safe_go_back(event=None):
        try:
            if frame.winfo_exists():
                go_back()
        except Exception:
            pass
    
    root.bind("<Return>", safe_perform_reset)
    root.bind("<Escape>", safe_go_back)


def reset_password_popup(parent, root, otp_entries, build_main_ui_callback):
    reset_password_full_ui(root, otp_entries, build_main_ui_callback)
