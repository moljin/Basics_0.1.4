import redis
from fastapi import FastAPI
from contextlib import asynccontextmanager

from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi_csrf_jinja.middleware import FastAPICSRFJinjaMiddleware

from starlette.exceptions import HTTPException as StarletteHTTPException

from app.test import exam
from app.utils import exc_handler
from app.utils.middleware import TokenSetCookieMiddleware

from app.apis import root, user, article, auth, quills
from app.views import user as views_user
from app.views import article as views_article
from app.lottos import views as views_lotto

from app.core.config import get_config, DevelopmentConfig
from app.core.database import ASYNC_ENGINE
from app.core.redis_config import redis_client
from app.core.settings import STATIC_DIR, templates, SECRET_KEY

config = get_config()

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Initializing database......")
    # FastAPI 인스턴스 기동시 필요한 작업 수행.
    try:
        await redis_client.ping() # Redis 연결 테스트
        print("Redis connection established......")
    except redis.exceptions.ConnectionError:
        print("Failed to connect to Redis......")
    print("Starting up...")
    yield
    # FastAPI 인스턴스 종료시 필요한 작업 수행
    await redis_client.aclose()
    print("Redis connection closed......")
    print("Shutting down...")
    await ASYNC_ENGINE.dispose()


def including_router(app):
    app.include_router(root.router, prefix="", tags=["Root"]) # root 페이지는 / 슬래시를 없애라.
    app.include_router(user.router, prefix="/apis/accounts", tags=["User"])
    app.include_router(article.router, prefix="/apis/articles", tags=["Article"])
    app.include_router(auth.router, prefix="/apis/auth", tags=["Auth"])

    app.include_router(views_user.router, prefix="/accounts", tags=["UserHTML"])
    app.include_router(views_article.router, prefix="/articles", tags=["ArticleHTML"])

    app.include_router(quills.router, prefix="/quills/file", tags=["Quills"])

    app.include_router(views_lotto.router, prefix="/lotto", tags=["Lotto"])

    app.include_router(exam.router, prefix="/test", tags=["Test"])

def including_middleware(app):
    app.add_middleware(CORSMiddleware,
                       allow_origins=["*"],  # 실제 프론트 주소
                       allow_methods=["*"],
                       allow_headers=["*"],
                       allow_credentials=True,
                       max_age=-1)
    app.add_middleware(TokenSetCookieMiddleware)
    app.add_middleware(FastAPICSRFJinjaMiddleware, secret=SECRET_KEY,
                       cookie_name="csrf_token", header_name="X-CSRF-Token")

def including_exception_handler(app):
    app.add_exception_handler(StarletteHTTPException,
                              exc_handler.custom_http_exception_handler)


def create_app():
    app = FastAPI(title=config.APP_NAME,
                  version=config.APP_VERSION,
                  description=config.APP_DESCRIPTION,
                  lifespan=lifespan,
                  docs_url=None)#, redoc_url=None)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    templates.env.globals["STATIC_URL"] = "/static"

    including_router(app)
    including_middleware(app)
    including_exception_handler(app)

    if config == DevelopmentConfig():
        print("create_app dev: ", config.APP_NAME)
    else:
        print("create_app prod: ", config.APP_NAME)

    return app