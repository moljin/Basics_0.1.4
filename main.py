from fastapi_mail import FastMail

from app.core.inits import create_app
from app.core.settings import mail_conf

fastapi_email = FastMail(mail_conf)

app = create_app()

