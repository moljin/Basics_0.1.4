from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from fastapi import Depends, Response, Request

from app.core.database import get_db
from app.core.settings import ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME, REFRESH_COOKIE_EXPIRE, ACCESS_COOKIE_MAX_AGE, NEW_ACCESS_COOKIE_NAME, \
    NEW_REFRESH_COOKIE_NAME
from app.services.auth_service import AuthService


class TokenSetCookieMiddleware(BaseHTTPMiddleware):
    '''# 로컬서버 재부팅 후 사이트 진입시 바로 살아있는 refresh_token으로 부터 access_token 생성'''

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # 현재 요청의 쿠키 상태 확인
        access_cookie: Optional[str] = request.cookies.get(ACCESS_COOKIE_NAME)
        refresh_cookie: Optional[str] = request.cookies.get(REFRESH_COOKIE_NAME)
        print("TokenSetCookieMiddleware 0.2.1 access_cookie: ", access_cookie)
        print("TokenSetCookieMiddleware 0.2.1 refresh_cookie: ", refresh_cookie)

        new_access: Optional[str] = None
        first_new_access: Optional[str] = None

        # access_token이 없고 refresh_token만 있으면 액세스 토큰 재발급 시도
        if not access_cookie and refresh_cookie:
            async for db in get_db():
                try:
                    auth_service = AuthService(db=db)
                    token_payload = await auth_service.refresh_access_token(refresh_cookie)
                    print('token_payload.get("access_token"): ', token_payload.get(ACCESS_COOKIE_NAME))

                    # 반환 타입에 맞춰 액세스 토큰 꺼냄
                    if isinstance(token_payload, dict):
                        first_new_access = token_payload.get(ACCESS_COOKIE_NAME)
                    elif isinstance(token_payload, str):
                        first_new_access = token_payload
                except Exception as e:
                    print("리프레시 실패 시 이후에서 쿠키 정리: TokenSetCookieMiddleware except Exception as e::::: ", e)
                    first_new_access = None
                finally: # get_db는 async generator이므로 한 번만 사용하고 빠져나옵니다.
                    print("TokenSetCookieMiddleware 0.2.1 get_db finally: ", db)
                break
        new_access = first_new_access
        """# 애플리케이션 핸들러 호출
        response = await call_next(request)
        if hasattr(request.state, "new_access_token"):
            print("TokenSetCookieMiddleware 0.2.1 통신 후 미들웨어로 진입 if hasattr:new_access_token: ", request.state.new_access_token)

        if getattr(request.state, "skip_set_cookie", False):  # 회원 탈퇴시 쿠키 삭제 위해서
            return response  # 아무것도 안 붙이고 그대로 반환

        print("first_new_access: ", first_new_access)
        second_new_access = getattr(request.state, NEW_ACCESS_COOKIE_NAME, None)
        print("second_new_access: ", second_new_access)

        if first_new_access:
            new_access = first_new_access
        elif second_new_access:
            new_access = second_new_access

        print("new_access: ", new_access)
        if new_access:
            response.set_cookie(
                key=ACCESS_COOKIE_NAME,
                value=new_access,
                httponly=True,
                secure=False,  # https라면 True로 조정
                samesite="lax",  # 크로스 도메인이라면 "none"으로 조정(https 필요)
                path="/",
                # domain="예: .example.com",  # 필요 시 설정
                max_age=ACCESS_COOKIE_MAX_AGE, # 초  # 필요 시 만료 설정
            )

        new_refresh = getattr(request.state, NEW_REFRESH_COOKIE_NAME, None)
        if new_refresh:
            response.set_cookie(
                key=REFRESH_COOKIE_NAME,
                value=new_refresh,
                httponly=True,
                samesite="strict",
                secure=False,  # HTTPS면 True
                path="/",
                expires=REFRESH_COOKIE_EXPIRE  # 날짜
            )

        # if not access_cookie and refresh_cookie and not new_access:
        #     # 재발급 실패: 무한 반복 방지를 위해 쿠키 정리
        #     response.delete_cookie(ACCESS_COOKIE_NAME, path="/")
        #     response.delete_cookie(REFRESH_COOKIE_NAME, path="/")

        return response
"""
    # async def dispatch(self, request: Request, call_next):
        #### 애플리케이션 핸들러 호출
        response: Response = await call_next(request)
        if hasattr(request.state, "new_access_token"):
            print("TokenSetCookieMiddleware 0.2.1 통신 후 미들웨어로 진입 if hasattr:new_access_token: ", request.state.new_access_token)

        if getattr(request.state, "skip_set_cookie", False): # 회원 탈퇴시 쿠키 삭제 위해서
            return response  # 아무것도 안 붙이고 그대로 반환

        new_access_token = getattr(request.state, NEW_ACCESS_COOKIE_NAME, None)
        access_token = getattr(request.state, ACCESS_COOKIE_NAME, None)
        # if new_access_token:
        #     new_access = new_access_token
        # elif access_token:
        #     new_access = access_token
        # else:
        #     new_access = None
        print("TokenSetCookieMiddleware new_access_token: ", new_access_token)
        print("TokenSetCookieMiddleware access_token: ", access_token)
        # new_access = new_access_token or access_token
        print("TokenSetCookieMiddleware new_access: ", new_access)
        if new_access:
            response.set_cookie(
                key=ACCESS_COOKIE_NAME,
                value=new_access,
                httponly=True,
                samesite="lax",
                secure=False,  # HTTPS면 True
                path="/",
                max_age=ACCESS_COOKIE_MAX_AGE, # 초
            )
            # 쿠키 기반 인증 변경 직후 캐시 금지 및 Vary 지정
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            response.headers["Vary"] = "Cookie"

        print("TokenSetCookieMiddleware request.cookies.get(ACCESS_COOKIE_NAME): ", request.cookies.get(ACCESS_COOKIE_NAME))

        new_refresh = getattr(request.state, NEW_REFRESH_COOKIE_NAME, None)
        print("TokenSetCookieMiddleware new_refresh: ", new_refresh)
        if new_refresh:
            response.set_cookie(
                key=REFRESH_COOKIE_NAME,
                value=new_refresh,
                httponly=True,
                samesite="strict",
                secure=False,  # HTTPS면 True
                path="/",
                expires=REFRESH_COOKIE_EXPIRE # 날짜
            )
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("Pragma", "no-cache")
            response.headers["Vary"] = "Cookie"
        print("TokenSetCookieMiddleware request.cookies.get(REFRESH_COOKIE_NAME): ", request.cookies.get(REFRESH_COOKIE_NAME))

        return response

