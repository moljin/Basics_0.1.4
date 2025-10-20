from __future__ import annotations

from typing import Optional, List, Tuple
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from fastapi import Response, Request

from app.core.database import get_db
from app.core.settings import ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME, REFRESH_COOKIE_EXPIRE, ACCESS_COOKIE_MAX_AGE, NEW_ACCESS_COOKIE_NAME, \
    NEW_REFRESH_COOKIE_NAME
from app.services.auth_service import AuthService



def _is_cross_site(request: Request) -> bool:
    """
    Origin 헤더와 요청 URL을 비교하여 크로스 사이트 여부를 판단합니다.
    Origin이 없으면 동일 사이트로 간주합니다(첫 네비게이션 등).
    """
    origin = request.headers.get("origin")
    if not origin:
        return False
    try:
        o = urlparse(origin)
        req_host = request.url.hostname
        req_port = request.url.port or (443 if request.url.scheme == "https" else 80)
        o_port = o.port or (443 if o.scheme == "https" else 80)
        return (o.scheme != request.url.scheme) or (o.hostname != req_host) or (o_port != req_port)
    except Exception as e:
        print("Exception: _is_cross_site: ", e)
        return False


def _cookie_attrs_for(request: Request) -> dict:
    """
    요청 특성에 맞춘 쿠키 속성 결정:
    - 동일 사이트: SameSite=Lax, Secure=(https일 때만)
    - 크로스 사이트: SameSite=None, Secure=True(브라우저 정책상 필수)
    """
    cross = _is_cross_site(request)
    if cross:
        return dict(httponly=True,
                    samesite="none",
                    secure=True,
                    path="/",
                    max_age=ACCESS_COOKIE_MAX_AGE  # 초  # 필요 시 만료 설정
                    )
    else:
        print("secure: ", request.url.scheme == "https")
        return dict(httponly=True,
                    samesite="lax",
                    secure=(request.url.scheme == "https"),
                    # secure=False,  # https라면 True로 조정
                    path="/",
                    max_age=ACCESS_COOKIE_MAX_AGE # 초  # 필요 시 만료 설정
                    )


class TokenSetCookieMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        print("TokenSetCookieMiddleware 시작 request.url: ", request.url)
        access_cookie: Optional[str] = request.cookies.get(ACCESS_COOKIE_NAME)
        refresh_cookie: Optional[str] = request.cookies.get(REFRESH_COOKIE_NAME)

        new_access: Optional[str] = None

        # 1) access_token이 없고 refresh_token만 있으면, 먼저 액세스 토큰을 발급
        if not access_cookie and refresh_cookie:
            async for db in get_db():
                try:
                    auth_service = AuthService(db=db)
                    refreshed = await auth_service.refresh_access_token(refresh_cookie)
                    if isinstance(refreshed, dict):
                        new_access = refreshed.get(ACCESS_COOKIE_NAME)
                        print("1. new_access: ", new_access)
                    elif isinstance(refreshed, str):
                        new_access = refreshed
                        print("2. new_access: ", new_access)
                except Exception as e:
                    # 개발 편의를 위해 로그만 남기고, refresh_token은 보존
                    print(f"[TokenSetCookieMiddleware] refresh failed: {e}")
                    new_access = None
                finally: # get_db는 async generator이므로 한 번만 사용하고 빠져나옵니다.
                    print("TokenSetCookieMiddleware 0.2.1 get_db finally: ", db)
                break

            print("TokenSetCookieMiddleware new_access: ", new_access)
            # 2) 첫 요청부터 인증이 통과되도록 Authorization 헤더 주입
            if new_access:
                try:
                    raw_headers: List[Tuple[bytes, bytes]] = list(request.scope.get("headers", []))
                    raw_headers.append((b"authorization", f"Bearer {new_access}".encode("utf-8")))
                    request.scope["headers"] = raw_headers
                except Exception as e: # 헤더 주입 실패 시에도 응답 쿠키로는 설정됨
                    print(f"[TokenSetCookieMiddleware] set auth header failed: {e}")
                    pass

        # 3) 애플리케이션 처리
        response = await call_next(request)

        # 4) 응답에 access_token 쿠키 설정(첫 응답부터 브라우저 저장)
        if new_access:
            attrs = _cookie_attrs_for(request)
            print("TokenSetCookieMiddleware attrs: ", attrs)
            response.set_cookie(
                key=ACCESS_COOKIE_NAME,
                value=new_access,
                **attrs,
            )
        else:
            # 재발급이 없었다면 기존 동작 유지. 실패했다고 바로 refresh_token을 삭제하지는 않음.
            # 필요 시 아래 주석을 풀어 access_token만 정리할 수 있습니다.
            # response.delete_cookie(ACCESS_COOKIE_NAME, path="/")
            pass
        print("TokenSetCookieMiddleware 끝 request.cookies.get(ACCESS_COOKIE_NAME): ", request.cookies.get(ACCESS_COOKIE_NAME))
        return response


