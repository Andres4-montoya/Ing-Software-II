# SMTP config - completar con tu servidor SMTP (ej: Gmail SMTP, o Mailhog en local)
SMTP_HOST = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USER = 'andresmontoyabedoya100@gmail.com'
SMTP_PASSWORD = 'femi mywl tlkf zmvg'
FROM_NAME = 'App Admin'

# App settings
SECRET_KEY = '123456789'  # obligatorio cambiar
SESSION_TIMEOUT_SECONDS = 600  # 10 minutos inactividad


import os
DB_PATH = os.path.join(os.getcwd(), "data", "app.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

