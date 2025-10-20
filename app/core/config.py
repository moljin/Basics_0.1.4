import os

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.settings import ENV_PATH, APP_ENV, APP_NAME, APP_VERSION, APP_DESCRIPTION

load_dotenv(ENV_PATH) # 환경설정 .env 파일을 사용하려면 반드시...

class BaseConfig(BaseSettings):
    APP_ENV: str = APP_ENV
    APP_NAME: str = APP_NAME
    APP_VERSION: str = APP_VERSION
    APP_DESCRIPTION: str = APP_DESCRIPTION
    DEBUG: bool = False

    DB_TYPE: str = os.environ.get("DB_TYPE")
    DB_DRIVER: str = os.environ.get("DB_DRIVER")
    DB_NAME: str
    DB_HOST: str
    DB_PORT: str
    DB_USER: str
    DB_PASSWORD: str

    SECRET_KEY: str = os.environ.get("SECRET_KEY")

    model_config = SettingsConfigDict(
        env_file="../../.env",
        env_file_encoding="utf-8"
    )


class DevelopmentConfig(BaseConfig):
    # APP_DESCRIPTION: str = '<a href="https://naver.com"><button>임시 버튼</button></a>'
    # html 코드로 넣을 때는 여기에다 직접 해라. .env파일에 넣으면 string이 적용되지 않는다.
    DEBUG: bool = os.environ.get("DEBUG_TRUE")

    DB_NAME: str = os.environ.get("DEV_DB_NAME")
    DB_HOST: str = os.environ.get("DEV_DB_HOST")
    DB_PORT: str = os.environ.get("DEV_DB_PORT")
    DB_USER: str = os.environ.get("DEV_DB_USER")
    DB_PASSWORD: str = os.environ.get("DEV_DB_PASSWORD")


class ProductionConfig(BaseConfig):
    # APP_DESCRIPTION: str = '<a href="https://naver.com"><button>임시 버튼</button></a>'
    # html 코드로 넣을 때는 여기에다 직접 해라. .env파일에 넣으면 string이 적용되지 않는다.

    DB_NAME: str = os.environ.get("PROD_DB_NAME")
    DB_HOST: str = os.environ.get("PROD_DB_HOST")
    DB_PORT: str = os.environ.get("PROD_DB_PORT")
    DB_USER: str = os.environ.get("PROD_DB_USER")
    DB_PASSWORD: str = os.environ.get("PROD_DB_PASSWORD")


def get_config():
    env = APP_ENV.lower()
    print("APP_ENV: ", env)
    """ 환경설정 .env 파일을 사용하여 os.environ.get)을 호출하려면,
     반드시 load_dotenv로 경로 설정이 되어 있어야 햔다. """
    if env == "production":
        return ProductionConfig()
    return DevelopmentConfig()