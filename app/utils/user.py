import re
import asyncio
from fastapi import HTTPException, status
from passlib.context import CryptContext

from app.core.settings import ADMINS
from app.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 미리 컴파일된 정규식 (알파벳, 숫자, 특수문자 포함 9~50자)
# PASSWORD_REGEX = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*?_=+-])[A-Za-z\d!@#$%^&*?_=+-]{9,50}$")

async def get_password_hash(password: str) -> str:
    # CPU 바운드 작업: 스레드 풀로 오프로드
    return await asyncio.to_thread(pwd_context.hash, password)

async def verify_password(plain_password: str, hashed_password: str) -> bool:
    # CPU 바운드 작업: 스레드 풀로 오프로드
    return await asyncio.to_thread(pwd_context.verify, plain_password, hashed_password)

def optimal_password(password: str):
    # password_optimal = PASSWORD_REGEX.search(str(password))
    # 가벼운 연산이라 굳이 비동기 함수가 필요하지는 않는다. 또한 field_validator는 비동기 함수를 지원하지 않는다.
    password_reg = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*?_=+-])[A-Za-z\d!@#$%^&*?_=+-]{9,50}$"
    regex = re.compile(password_reg)
    password_optimal = re.search(regex, str(password))
    print("password_optimal: password : ", password)

    if not password_optimal:
        from app.utils.exc_handler import CustomErrorException
        raise CustomErrorException(status_code=432, detail="비밀번호 정책 위반")
        # raise HTTPException(
        #     status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        #     detail="비밀번호는 알파벳, 특수문자와 숫자를 모두 포함한 9자리 이상이어야 합니다.",
        # )

def is_admin(current_user: User) -> bool:
    try:
        if current_user.username in ADMINS:
            return True
        else:
            return False
    except Exception as e:
        print("is_admin False error: ", e, f"==> False")
        return False