import os, sqlite3, hashlib, binascii, time, hmac, logging, uuid, datetime, smtplib
from email.message import EmailMessage
from functools import wraps
from flask import Flask, request, g, render_template, redirect, url_for, session, flash, jsonify

import pyotp
import qrcode
from io import BytesIO
import base64
import csv, io
# carga configuración
import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

DB_PATH = config.DB_PATH
SESSION_TIMEOUT = config.SESSION_TIMEOUT_SECONDS

# logging de auditoría
os.makedirs('logs', exist_ok=True)
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
fh = logging.FileHandler('logs/audit.log')
fh.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
audit_logger.addHandler(fh)

# ---------- UTIL: DB ----------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
        g._database = db
    return db

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        totp_secret TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        failed_attempts INTEGER DEFAULT 0,
        locked_until INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT,
        action TEXT,
        details TEXT,
        ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    db.commit()
    
     # ⚡ Crear admin si no existe
    admin_email = "admin@example.com"
    cur.execute("SELECT id FROM users WHERE email=?", (admin_email,))
    if not cur.fetchone():
        pwd = "Admin123!"   # cámbiala luego en el panel
        password_hash, salt = hash_password(pwd)
        totp_secret = pyotp.random_base32()
        cur.execute("INSERT INTO users (email, password_hash, salt, role, totp_secret, is_active) VALUES (?,?,?,?,?,1)",
                    (admin_email, password_hash, salt, "admin", totp_secret))
        db.commit()
        print(f"✅ Usuario admin creado: {admin_email} | Password: {pwd}")
    

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# ---------- UTIL: Password hashing (PBKDF2) ----------
def hash_password(password, salt=None):
    if salt is None:
        salt = binascii.hexlify(os.urandom(16)).decode()
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 200_000)
    return binascii.hexlify(dk).decode(), salt

def verify_password(stored_hash, salt, provided_password):
    h, _ = hash_password(provided_password, salt)
    return h == stored_hash

# ---------- UTIL: Email ----------
def send_email(to_email, subject, body_html, body_text=None):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = f"{config.FROM_NAME} <{config.SMTP_USER}>"
    msg['To'] = to_email
    if body_text is None:
        body_text = "Revisa el contenido HTML del correo."
    msg.set_content(body_text)
    msg.add_alternative(body_html, subtype='html')
    # enviar por smtplib
    with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as s:
        s.starttls()
        s.login(config.SMTP_USER, config.SMTP_PASSWORD)
        s.send_message(msg)

# ---------- UTIL: Audit log ----------
def audit(user_email, action, details=''):
    audit_logger.info(f"{user_email or '-'} | {action} | {details}")
    db = get_db()
    db.execute("INSERT INTO audit_logs (user_email, action, details) VALUES (?,?,?)",
               (user_email, action, details))
    db.commit()

# ---------- DECORATORS ----------
def login_required(role=None):
    def deco(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'user_email' not in session:
                return redirect(url_for('login', next=request.path))
            # timeout check
            last = session.get('last_seen', 0)
            if time.time() - last > SESSION_TIMEOUT:
                audit(session.get('user_email'), 'session_timeout', f'auto-logout after inactivity')
                session.clear()
                flash("Sesión cerrada por inactividad.", "warning")
                return redirect(url_for('login'))
            session['last_seen'] = time.time()
            # role check
            if role:
                if session.get('role') != role and session.get('role') != 'admin':
                    flash('Acceso denegado: permiso insuficiente', 'danger')
                    return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return wrapped
    return deco

# ---------- ROUTES: UI ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        # Validaciones (HU-01 y HU-07 / HU-08)
        errors = []
        if not email:
            errors.append('Email es obligatorio.')
        if not validate_email_format(email):
            errors.append('Formato de email inválido.')
        pwd_ok, pwd_msg = validate_password_strength(password)
        if not pwd_ok:
            errors.append(pwd_msg)
        if errors:
            return render_template('register.html', errors=errors, form=request.form)
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        if cur.fetchone():
            errors.append('El correo ya está registrado. (HU-04)')
            return render_template('register.html', errors=errors, form=request.form)
        password_hash, salt = hash_password(password)
        # crear TOTP secret y dejar pendiente la verificación
        totp_secret = pyotp.random_base32()
        cur.execute("INSERT INTO users (email, password_hash, salt, role, totp_secret) VALUES (?,?,?,?,?)",
                    (email, password_hash, salt, 'user', totp_secret))
        db.commit()
        audit(email, 'create_user', 'Registro de cuenta')
        # enviar email con instrucciones de 2FA
        otpauth = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=email, issuer_name="UserMgmtApp")
        # generar imagen QR para el email (codificada base64)
        qr_b64 = generate_qr_base64(otpauth)
        html = f"""
        <p>Hola {email},</p>
        <p>Tu cuenta ha sido creada correctamente.</p>
        <p>Para activar la autenticación de dos factores (2FA) sigue estos pasos:</p>
        <ol>
          <li>Instala una app de autenticación (Google Authenticator, Authy, etc.)</li>
          <li>Escanea este código QR con la app:</li>
          <li><img src="data:image/png;base64,{qr_b64}" alt="QR 2FA" /></li>
          <li>Si no puedes escanear, añade esta clave manualmente: <b>{totp_secret}</b></li>
          <li>En el login, después de tu contraseña te pediremos el código de 6 dígitos que genere la app.</li>
        </ol>
        <p>Saludos.<br/>Equipo</p>
        """
        try:
            send_email(email, 'Cuenta creada | Instrucciones 2FA', html, body_text="Cuenta creada. Revisa HTML.")
        except Exception as e:
            # log y aviso al admin (en producción hacer retry / queue)
            audit(email, 'email_sent_failed', str(e))
        flash("Cuenta creada. Revisa tu correo para activar 2FA.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        code = request.form.get('code','').strip()
        db = get_db()
        cur = db.cursor()
        row = cur.execute("SELECT * FROM users WHERE email=? AND is_active=1", (email,)).fetchone()
        if not row:
            flash('Credenciales inválidas', 'danger')
            return render_template('login.html')
        # check lockout
        now_ts = int(time.time())
        if row['locked_until'] and now_ts < row['locked_until']:
            flash('Cuenta bloqueada temporalmente. Revisa tu correo.', 'danger')
            return render_template('login.html')
        # verify password
        if not verify_password(row['password_hash'], row['salt'], password):
            # incrementar contador
            failed = row['failed_attempts'] + 1
            locked_until = row['locked_until']
            if failed >= 3:
                # bloquear por 5 minutos
                locked_until = now_ts + 5*60
                audit(email, 'account_locked', '3 intentos fallidos')
                # enviar alerta
                try:
                    send_email(email, 'Alerta: cuenta bloqueada', f"<p>Se han detectado 3 intentos fallidos. Tu cuenta está bloqueada hasta {datetime.datetime.fromtimestamp(locked_until)}</p>")
                except:
                    pass
                flash('Cuenta bloqueada tras 3 intentos fallidos. Se envió un correo.', 'danger')
            else:
                flash('Credenciales inválidas', 'danger')
            cur.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE email=?", (failed, locked_until, email))
            db.commit()
            return render_template('login.html')
        # si la contraseña es correcta, verificar 2FA
        totp_secret = row['totp_secret']
        if not totp_secret:
            flash('Cuenta sin 2FA configurado. Contacta al admin.', 'danger')
            return render_template('login.html')
        # si no proporcionó código en formulario, pedirlo
        if not code:
            # renderizar formulario pidiendo código
            return render_template('login.html', ask_code=True, email=email)
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(code, valid_window=1):
            # incrementar contador de fallos de autenticación
            failed = row['failed_attempts'] + 1
            locked_until = row['locked_until']
            if failed >= 3:
                locked_until = now_ts + 5*60
                audit(email, 'account_locked', '3 intentos fallidos (2FA)')
                try:
                    send_email(email, 'Alerta: cuenta bloqueada', f"<p>Se han detectado 3 intentos fallidos en 2FA. Tu cuenta está bloqueada hasta {datetime.datetime.fromtimestamp(locked_until)}</p>")
                except:
                    pass
                flash('Cuenta bloqueada tras 3 intentos fallidos. Se envió un correo.', 'danger')
            else:
                flash('Código 2FA erróneo', 'danger')
            cur.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE email=?", (failed, locked_until, email))
            db.commit()
            return render_template('login.html')
        # login exitoso
        cur.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE email=?", (email,))
        db.commit()
        session['user_email'] = email
        session['role'] = row['role']
        session['last_seen'] = time.time()
        audit(email, 'login', 'login successful')
        flash('Inicio de sesión correcto', 'success')
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
@login_required()
def dashboard():
    return render_template('dashboard.html', email=session.get('user_email'), role=session.get('role'))

# ADMIN - listar usuarios
@app.route('/admin/users')
@login_required(role='admin')
def manage_users():
    db = get_db()
    users = db.execute("SELECT id, email, role, is_active, created_at FROM users").fetchall()
    return render_template('manage_users.html', users=users)

# ver usuario detalle y acción eliminar (requiere reauth)
@app.route('/admin/users/<int:user_id>', methods=['GET','POST'])
@login_required(role='admin')
def user_detail(user_id):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('manage_users'))
    if request.method == 'POST':
        # reautenticación: pedir password del admin
        admin_pwd = request.form.get('admin_password','')
        cur_admin = db.execute("SELECT * FROM users WHERE email=?", (session['user_email'],)).fetchone()
        if not verify_password(cur_admin['password_hash'], cur_admin['salt'], admin_pwd):
            flash('Contraseña de admin inválida para confirmar la eliminación', 'danger')
            return render_template('confirm_delete.html', user=u)

        # no permitir eliminarse a sí mismo
        if u['email'] == session['user_email']:
            flash('No puedes eliminar tu propia cuenta desde el panel.', 'danger')
            return redirect(url_for('manage_users'))

        # ⚠️ Aquí se deberían validar procesos asociados (ejemplo con pedidos, registros, etc.)
        # Por ahora simulamos que no tiene dependencias
        has_dependencies = False  

        if has_dependencies:
            # Si tiene procesos activos → solo se desactiva (soft delete)
            db.execute("UPDATE users SET is_active=0 WHERE id=?", (user_id,))
            db.commit()
            audit(session['user_email'], 'soft_delete_user', f"deactivated {u['email']}")
            flash('El usuario tiene procesos activos → se ha desactivado en lugar de eliminar.', 'warning')
        else:
            # Hard delete: eliminar definitivamente
            db.execute("DELETE FROM users WHERE id=?", (user_id,))
            db.commit()
            audit(session['user_email'], 'delete_user', f"deleted {u['email']}")
            flash('Usuario eliminado permanentemente.', 'success')

        return redirect(url_for('manage_users'))
    return render_template('user_detail.html', user=u)

@app.route('/logout')
def logout():
    email = session.get('user_email')
    session.clear()
    audit(email, 'logout', 'user logged out')
    flash('Cerraste sesión.', 'info')
    return redirect(url_for('login'))

# API para comprobaciones (email formato)
def validate_email_format(email):
    # simple regex-like check sin dependencia externa
    return '@' in email and '.' in email.split('@')[-1]

def validate_password_strength(pwd):
    # HU-01: mínimo 8 caracteres, mayúsculas, minúsculas, dígitos y carácter especial
    if len(pwd) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if not any(c.islower() for c in pwd):
        return False, "La contraseña debe tener al menos una minúscula."
    if not any(c.isupper() for c in pwd):
        return False, "La contraseña debe tener al menos una mayúscula."
    if not any(c.isdigit() for c in pwd):
        return False, "La contraseña debe tener al menos un número."
    if not any(c in '!@#$%^&*()-_=+[{]}\\|;:\'",<.>/?`~' for c in pwd):
        return False, "La contraseña debe tener al menos un carácter especial."
    return True, "OK"

def generate_qr_base64(data_uri):
    img = qrcode.make(data_uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

# página de confirm delete (mostrar reauth form)
@app.route('/admin/users/<int:user_id>/confirm_delete')
@login_required(role='admin')
def confirm_delete(user_id):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('manage_users'))
    return render_template('confirm_delete.html', user=u)


# Cambiar rol user <-> admin
@app.route("/admin/users/<int:user_id>/toggle_role", methods=["POST"])
@login_required(role="admin")
def toggle_role(user_id):
    db = get_db()
    u = db.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        flash("Usuario no encontrado", "danger")
        return redirect(url_for("manage_users"))
    new_role = "admin" if u["role"] == "user" else "user"
    db.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
    db.commit()
    audit(session["user_email"], "change_role", f"user_id={user_id} to {new_role}")
    flash("Rol actualizado", "success")
    return redirect(url_for("manage_users"))

# Activar / Desactivar usuario
@app.route("/admin/users/<int:user_id>/toggle_active", methods=["POST"])
@login_required(role="admin")
def toggle_active(user_id):
    db = get_db()
    u = db.execute("SELECT is_active FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        flash("Usuario no encontrado", "danger")
        return redirect(url_for("manage_users"))
    new_state = 0 if u["is_active"] else 1
    db.execute("UPDATE users SET is_active=? WHERE id=?", (new_state, user_id))
    db.commit()
    audit(session["user_email"], "toggle_active", f"user_id={user_id} to {new_state}")
    flash("Estado de usuario actualizado", "success")
    return redirect(url_for("manage_users"))

# Carga masiva de CSV
@app.route("/admin/users/upload_csv", methods=["POST"])
@login_required(role="admin")
def upload_csv():
    if "csvfile" not in request.files:
        flash("No se subió ningún archivo.", "danger")
        return redirect(url_for("manage_users"))

    file = request.files["csvfile"]
    if not file.filename.endswith(".csv"):
        flash("El archivo debe ser CSV.", "danger")
        return redirect(url_for("manage_users"))

    import csv, io, random, string
    stream = io.StringIO(file.stream.read().decode("utf-8"))
    reader = csv.reader(stream)
    next(reader, None)  # saltar encabezado si existe

    db = get_db()
    errors = []
    count = 0
    for row in reader:
        if len(row) < 2:
            errors.append(f"Fila inválida: {row}")
            continue
        email, role = row[0].strip(), row[1].strip()
        if role not in ("user", "admin"):
            errors.append(f"Rol inválido para {email}")
            continue
        if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            errors.append(f"El correo {email} ya existe.")
            continue
        # contraseña temporal
        temp_pwd = "".join(random.choices(string.ascii_letters + string.digits, k=10))
        h, s = hash_password(temp_pwd)
        totp_secret = pyotp.random_base32()
        db.execute(
            "INSERT INTO users (email,password_hash,salt,role,totp_secret,is_active) VALUES (?,?,?,?,?,1)",
            (email, h, s, role, totp_secret),
        )
        count += 1

    db.commit()
    if errors:
        flash("Errores en el CSV:<br>" + "<br>".join(errors), "danger")
    if count:
        flash(f"Se cargaron {count} usuarios correctamente.", "success")
    return redirect(url_for("manage_users"))

with app.app_context():
    init_db()
    

