import sqlite3, os, hashlib, binascii, pyotp

DB_PATH = "data/app.db"

def hash_password(password, salt=None):
    if salt is None:
        salt = binascii.hexlify(os.urandom(16)).decode()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return binascii.hexlify(dk).decode(), salt

def create_admin(email, password):
    if not os.path.exists(DB_PATH):
        print("⚠️ La base de datos no existe. Ejecuta primero server.py una vez para inicializarla.")
        return
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Verificar si ya existe
    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    if cur.fetchone():
        print(f"⚠️ El usuario {email} ya existe.")
        conn.close()
        return

    # Hash de contraseña
    h, s = hash_password(password)

    # Generar secret para 2FA
    totp_secret = pyotp.random_base32()

    cur.execute("""
        INSERT INTO users (email, password_hash, salt, role, totp_secret, is_active)
        VALUES (?, ?, ?, ?, ?, 1)
    """, (email, h, s, "admin", totp_secret))

    conn.commit()
    conn.close()

    print("✅ Usuario administrador creado:")
    print(f"   Email: {email}")
    print(f"   Contraseña: {password}")
    print(f"   Clave secreta 2FA: {totp_secret}")
    print("\nUsa Google Authenticator o Authy para configurar el código 2FA con esta clave.")

if __name__ == "__main__":
    # Cambia estos valores si quieres
    create_admin("admin@example.com", "Admin123!")