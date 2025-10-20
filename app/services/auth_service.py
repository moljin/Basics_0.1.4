from datetime import timedelta, datetime, timezone

from fastapi import Depends, HTTPException, status
from jose import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.settings import ACCESS_TOKEN_EXPIRE, ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME
from app.models.user import User
from app.schemas.auth import LoginRequest
from app.services.token_service import AsyncTokenService
from app.utils.user import verify_password
from app.utils.auth import create_access_token, create_refresh_token, verify_token


class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db

    """
    사용자 인증을 수행합니다.
    """

    async def authenticate_user(self, login_data: LoginRequest):
        # 사용자 조회
        query = (
            select(User).
            where(User.email == login_data.email)
        )
        result = await self.db.execute(query)
        user = result.scalar_one_or_none()

        if not user:
            return None

        password_ok = await verify_password(login_data.password, str(user.password))
        if not password_ok:
            from app.utils.exc_handler import CustomErrorException
            raise CustomErrorException(status_code=411,
                                       detail="비밀번호 불일치",
                                       headers={"WWW-Authenticate": "Bearer"})
        print("user: ", user)
        return user

    """
    사용자 정보를 기반으로 액세스 토큰을 생성합니다.
    """

    # AI Chat 권장: 정말 self/cls를 쓰지 않는다면 정적 메서드로 전환
    # - 메서드 선언에 @staticmethod를 붙이고 self 인자를 제거하세요.
    @staticmethod
    async def create_user_token(user: User):
    # async def create_user_token(self, user: User):
        # 토큰에 포함될 데이터
        token_data = {
            "username": user.username,
            "email": user.email,
            "user_id": user.id,
        }

        # 만료 시간 설정
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE)

        # 액세스 토큰 생성
        access_token = await create_access_token(
            data=token_data,
            expires_delta=access_token_expires
        )
        try:
            unverified = jwt.get_unverified_claims(access_token)
            exp_ts = unverified.get("exp")
            if exp_ts:
                print("============== access_token의 만료기간 관련 정보 ==============")
                print("exp:", datetime.fromtimestamp(exp_ts, tz=timezone.utc))
                print("now:", datetime.now(timezone.utc))
                print("seconds_left:", int(exp_ts - datetime.now(timezone.utc).timestamp()))
        except Exception as e:
            print("get_unverified_claims 실패는 단순 디버깅 용도이므로 그대로 진행", e)
            pass

        # 리프레시 토큰 생성
        refresh_token = await create_refresh_token(
            data=token_data
        )

        try:
            unverified = jwt.get_unverified_claims(refresh_token)
            exp_ts = unverified.get("exp")
            if exp_ts:
                print("============== refresh_token의 만료기간 관련 정보 ==============")
                print("exp:", datetime.fromtimestamp(exp_ts, tz=timezone.utc))
                print("now:", datetime.now(timezone.utc))
                print("seconds_left:", int(exp_ts - datetime.now(timezone.utc).timestamp()))
        except Exception as e:
            print("get_unverified_claims 실패는 단순 디버깅 용도이므로 그대로 진행", e)
            pass


        # refresh_token을 Redis에 저장
        await AsyncTokenService.store_refresh_token(user.id, refresh_token)

        return {
            ACCESS_COOKIE_NAME: access_token,
            REFRESH_COOKIE_NAME: refresh_token,
            "token_type": "bearer"
        }

    """
    리프레시 토큰을 사용하여 새 액세스 토큰을 발급합니다.
    """

    async def refresh_access_token(self, refresh_token: str):
        print("통신 중 0.0.0.0 refresh_access_token 리프레시 토큰으로 액세스 토큰 생성 시작: refresh_token: ", refresh_token)
        # 리프레시 토큰 검증
        payload = verify_token(refresh_token)
        if not payload:
            print("통신 중 0.0.0.1 refresh_access_token payload 없다.: ", payload)
            return None

        user_id = payload.get("user_id")

        if not user_id:
            print("통신 중 0.0.0.2 refresh_access_token user_id 없다.: ", user_id)
            return None

        """ # refresh_token이 만료기간이 남아 있는 경우 redis에 저장하는 로직을 한번 더 실행
        # 뭔가 redis 관련 문제로 인해 is_valid가 None으로 반환되어 버리는 오류?를 없애기 위해 인위적으로 redis에 저장하는 로직을 한번더 실행한다. """

        print("통신 중 0.0.0.0. refresh_access_token: refresh_token 인위적 다시 저장 시작")
        await AsyncTokenService.store_refresh_token(user_id, refresh_token)
        print("통신 중 0.0.0.0. refresh_access_token: refresh_token 인위적 다시 저장 끝 ===> Redis에서 리프레시 토큰 유효성 확인")

        # Redis에서 리프레시 토큰 유효성 확인
        is_valid = await AsyncTokenService.validate_refresh_token(user_id, refresh_token)
        if not is_valid:
            print("통신 중 0.0.0.3. refresh_access_token is_valid 안됐다.: ", is_valid)
            return None

        # 사용자 조회
        query = (select(User).where(User.id == user_id))
        result = await self.db.execute(query)
        user = result.scalar_one_or_none()
        if not user:
            print("통신 중 0.0.0.3.0 refresh_access_token user 없다.: ", user)
            return None

        # 토큰에 포함될 데이터
        token_data = {
            "username": user.username,
            "email": user.email,
            "user_id": user.id,
        }

        # 새 액세스 토큰 생성
        access_token = await create_access_token(token_data)
        print("통신 중 0.0.0.0. refresh_access_token access_token 만들었다.: ", access_token)

        return {
            ACCESS_COOKIE_NAME: access_token,
            "token_type": "bearer"
        }

def get_auth_service(db: AsyncSession = Depends(get_db)):
    return AuthService(db)