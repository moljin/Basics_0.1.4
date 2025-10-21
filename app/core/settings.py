import datetime
import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi.templating import Jinja2Templates
from fastapi_csrf_jinja.jinja_processor import csrf_token_processor
from fastapi_mail import ConnectionConfig
from pydantic import SecretStr, EmailStr, TypeAdapter

# Load .env
load_dotenv()

# APP_ENV = "development"
APP_ENV = "production"
APP_NAME = "Develop_FastAPI"
APP_VERSION = "0.1.4"
APP_DESCRIPTION = "인프런 강의를 종합한 첫번째 프로젝트"

"""
프로그램 개발 과정에서 디버깅 모드(debug mode)는 일반적으로 true로 설정하고, 
배포 시에는 false로 설정하는 것이 일반적입니다. 
개발 단계에서는 상세한 오류 메시지와 디버깅 정보를 활용하여 
코드의 문제점을 찾고 수정하는 것이 중요하므로 디버깅 모드를 활성화합니다. 
반면, 배포 시에는 보안 및 성능상의 이유로 
디버깅 모드를 비활성화하여 불필요한 정보 노출을 방지하고 성능 저하를 최소화합니다. 
"""

PRESENT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_DIR = Path(__file__).resolve().parent.parent
print("APP_DIR: ", APP_DIR)
ROOT_DIR = Path(__file__).resolve().parent.parent.parent  ## root폴더
print("ROOT 디렉토리: ", ROOT_DIR)

ENV_PATH = os.path.join(ROOT_DIR, ".env")
TEMPLATE_DIR = os.path.join(APP_DIR, 'templates')
STATIC_DIR = os.path.join(APP_DIR, 'static')

templates = Jinja2Templates(
    directory=TEMPLATE_DIR,
    context_processors=[csrf_token_processor("csrf_token", "X-CSRF-Token")]
)

# 실제 배포시에는 환경 변수로 보관해야 합니다
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# PROFILE_IMAGE_UPLOAD_DIR = os.path.join(STATIC_DIR, os.getenv("PROFILE_IMAGE_DIR"))
# ARTICLE_THUMBNAIL_UPLOAD_DIR = os.path.join(STATIC_DIR, os.getenv("ARTICLE_THUMBNAIL_DIR"))
#
# ARTICLE_QUILLS_USER_IMG_UPLOAD_DIR = os.path.join(STATIC_DIR, os.getenv("ARTICLE_QUILLS_USER_IMG_DIR"))
# ARTICLE_QUILLS_USER_VIDEO_UPLOAD_DIR = os.path.join(STATIC_DIR, os.getenv("ARTICLE_QUILLS_USER_VIDEO_DIR"))
PROFILE_IMAGE_UPLOAD_DIR = os.path.join(STATIC_DIR, "media"+"/"+"user_images"+"/"+"accounts"+"/"+"profiles")
ARTICLE_THUMBNAIL_UPLOAD_DIR = os.path.join(STATIC_DIR, "media"+"/"+"user_images"+"/"+"articles"+"/"+"thumbnails")

ARTICLE_QUILLS_USER_IMG_UPLOAD_DIR = os.path.join(STATIC_DIR, "media"+"/"+"user_images"+"/"+"articles"+"/"+"quills")
ARTICLE_QUILLS_USER_VIDEO_UPLOAD_DIR = os.path.join(STATIC_DIR, "media"+"/"+"user_videos"+"/"+"articles"+"/"+"quills")

# 생성할 디렉토리 경로 목록
directory_list = [
    PROFILE_IMAGE_UPLOAD_DIR,
    ARTICLE_THUMBNAIL_UPLOAD_DIR,
    ARTICLE_QUILLS_USER_IMG_UPLOAD_DIR,
    ARTICLE_QUILLS_USER_VIDEO_UPLOAD_DIR
]

# 목록의 각 경로에 대해 디렉토리 생성
for path in directory_list:
    os.makedirs(path, exist_ok=True)
    print(f"디렉토리 '{path}'가 생성되었거나 이미 존재합니다.")

# 로그인 시 쿠키에 저장한 이름과 동일해야 합니다.
# Pydantic model인 class TokenResponse(BaseModel): 여기 인자의 이름과도 동일해야 한다.
# 여기와 pydantic model의 인자 이름과 동일하기만 하면 나머지는 모두 해결된다.
ACCESS_COOKIE_NAME = os.getenv("ACCESS_TOKEN")
REFRESH_COOKIE_NAME = os.getenv("REFRESH_TOKEN")
# 아래 숫자는 단위가 없다. set_cookie 때는 max_age가 초단위이므로 *60을 해야 분으로 계산된다.
ACCESS_TOKEN_EXPIRE = 30
REFRESH_TOKEN_EXPIRE = 7

ACCESS_COOKIE_MAX_AGE = ACCESS_TOKEN_EXPIRE * 60 # 초 1800 : 30분
REFRESH_COOKIE_EXPIRE = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE)

# 로그인 시 쿠키에 저장한 이름과 동일해야 합니다.
# 여기는 내부적으로만 사용되므로 굳이 변경할 필요는 없다.
NEW_ACCESS_COOKIE_NAME = os.getenv("NEW_ACCESS_TOKEN")
NEW_REFRESH_COOKIE_NAME = os.getenv("NEW_REFRESH_TOKEN")

# -------------- 설정 (.env 사용) --------------
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USERNAME)
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))

CODE_TTL_SECONDS = 10 * 60  # 10분

# -------------- FastMail 설정 --------------
if not SMTP_FROM:
    raise RuntimeError("SMTP_FROM environment variable is not set")
# 유효한 이메일인지 검증
MAIL_FROM: EmailStr = TypeAdapter(EmailStr).validate_python(SMTP_FROM)
mail_conf = ConnectionConfig(
    MAIL_USERNAME=SMTP_USERNAME,
    MAIL_PASSWORD=SecretStr(SMTP_PASSWORD or ""),
    MAIL_FROM=MAIL_FROM,
    MAIL_PORT=SMTP_PORT,
    MAIL_SERVER=SMTP_HOST,
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)

# ----------------- 인증코드 이메일 HTML 템플릿(스트링) -----------------
AUTHCODE_EMAIL_HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{{ title }}</title>
  <style>
    /* 이메일에서 간단히 적용되는 스타일 (대부분 이메일 클라이언트에서 지원) 직접 태그에 스타일을 먹여야 네이버에서도 적용된다.*/
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial; margin:0; padding:0; background:#f6f9fc; }
    .container { max-width:600px; margin:30px auto; background:#ffffff; border-radius:8px; padding:24px; box-shadow:0 2px 8px rgba(0,0,0,0.06); }
    .logo { text-align:center; margin-bottom:8px; }
    h1 { font-size:20px; margin:6px 0 14px; color:#111827; }
    p { color:#374151; font-size:15px; line-height:1.5; }
    .code { display:block; text-align:center; font-size:28px; font-weight:700; letter-spacing:4px; background:#f3f4f6; padding:12px 18px; margin:18px auto; border-radius:8px; width:fit-content; color:#111827; }
    .small { font-size:13px; color:#6b7280; margin-top:12px; }
    .footer { font-size:12px; color:#9ca3af; text-align:center; margin-top:18px; }
    .btn { display:inline-block; text-decoration:none; background:#2563eb; color:white; padding:10px 16px; border-radius:6px; }
  </style>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial; margin:0; padding:0; background:#f6f9fc;">
  <div class="container" style="max-width:600px; margin:30px auto; background:#ffffff; border-radius:8px; padding:24px; box-shadow:0 2px 8px rgba(0,0,0,0.06);">
    <div class="logo" style="text-align:center; margin-bottom:8px;">
      <!-- 로고를 원하면 img 태그 추가 -->
    </div>

    <h1 style="font-size:20px; margin:6px 0 14px; color:#111827;">회원가입을 위한 인증번호</h1>

    <p style="color:#374151; font-size:15px; line-height:1.5;">안녕하세요. 회원가입 절차를 위해 아래 인증번호를 입력해주세요. 인증번호는 <strong>10분</strong> 동안 유효합니다.</p>

    <div class="code" style="display:block; text-align:center; font-size:28px; font-weight:700; letter-spacing:4px; background:#f3f4f6; padding:12px 18px; margin:18px auto; border-radius:8px; width:fit-content; color:#111827;">{{ code }}</div>

    <p class="small" style="font-size:13px; color:#6b7280; margin-top:12px;">인증요청을 직접 하신 적이 없다면 이 메일을 무시하셔도 됩니다.</p>

    <div class="footer" style="font-size:12px; color:#9ca3af; text-align:center; margin-top:18px;">© 2025 Your Company — 안전한 서비스</div>
  </div>
</body>
</html>
"""


NOW_TIME_UTC= datetime.datetime.now(datetime.timezone.utc)
NOW_TIME = datetime.datetime.now()
print("NOW_TIME_UTC: ", NOW_TIME_UTC)
print("NOW_TIME: ", NOW_TIME)


LOTTO_LATEST_URL = os.getenv("LOTTO_LATEST_URL")
# LOTTO_FILEPATH = os.path.join(STATIC_DIR, os.getenv("LOTTO_FILEPATH"))# STATIC_DIR + os.getenv("LOTTO_FILEPATH")
LOTTO_FILEPATH = os.path.join(STATIC_DIR, "media"+"/"+"default"+"/"+"lotto_init.xlsx") # STATIC_DIR + os.getenv("LOTTO_FILEPATH")
print("LOTTO_FILEPATH: ", LOTTO_FILEPATH)
ADMINS = [os.getenv("ADMIN_1"), os.getenv("ADMIN_2")]
