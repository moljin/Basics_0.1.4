import os
from typing import Optional
import httpx

from fastapi import Depends, HTTPException, Request, status, Response, Security

from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_config
from app.core.database import get_db
from app.core.settings import ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME, templates, NEW_ACCESS_COOKIE_NAME, NEW_REFRESH_COOKIE_NAME
from app.models.user import User
from app.services.auth_service import AuthService, get_auth_service
from app.services.token_service import AsyncTokenService
from app.utils.auth import payload_to_user, get_token_expiry

# 헤더는 선택적으로만 받도록 설정 (없어도 에러 발생 X)
bearer_scheme = HTTPBearer(auto_error=False)

"""
토큰에서 현재 사용자 정보를 가져오는 의존성 함수
"""

async def get_current_user(
        request: Request, response: Response,
        credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
        db: AsyncSession = Depends(get_db),
):
    # 1) 우선 Authorization: Bearer 토큰 확인,
    # swagger ui로 로그인할 때도 쿠키에 저장되기 때문에... 굳이 필요는 없지만...
    access_token = None
    try:
        if credentials and isinstance(credentials, HTTPAuthorizationCredentials):
            if credentials.scheme and credentials.scheme.lower() == "bearer":
                access_token = credentials.credentials

    except Exception as e:
        print("get_current_user except Exception as e::::: ", e)
        access_token = None

    # 2) 없으면 쿠키에서 access_token 확인
    if access_token is None:
        access_token = request.cookies.get(ACCESS_COOKIE_NAME)
    print("get_current_user 0.1.0.0 get_current_user::: access_token cookie::::::: ", access_token)

    if access_token is None:
        # 토큰이 전혀 없으면 401
        _refresh_token = request.cookies.get(REFRESH_COOKIE_NAME)
        csrf_token = request.cookies.get("csrf_token")
        print("get_current_user 0.1.0.0.0 get_current_user::: csrf_token cookie::::::: ", csrf_token)
        print("get_current_user 0.1.0.0.1 get_current_user::: refresh token cookie::::: ", _refresh_token)
        if _refresh_token:
            post_url = "/apis/auth/refresh"
            config = get_config()
            _API_BASE_URL = os.environ.get("PROD_API_BASE_URL") if config.APP_ENV == "production" else os.environ.get("DEV_API_BASE_URL")
            try:
                async with httpx.AsyncClient(base_url=_API_BASE_URL, timeout=5.0) as client:
                    '''csrf_token을 template에 장착해서 모든 템플릿 렌더링에 사용하기 때문에
                                        로그인 되어 있는 경우 get_current_user로 들어 왔을 때, access_token이 만료된 경우는
                                        refresh_token을 생성하려고 /refresh로 들어오게 되고, 이 때 csrf_token도 함께 보내줘야 한다.'''
                    if csrf_token:
                        resp = await client.post(post_url,
                                                 json={"refresh_token": _refresh_token},
                                                 headers={"Content-Type": "application/json",
                                                          "X-CSRF-Token": csrf_token, },  # 쿠키와 같은 값
                                                 cookies={"csrf_token": csrf_token})  # CSRF 쿠키 동기화
                    else:
                        resp = await client.post(post_url,
                                                 json={"refresh_token": _refresh_token},
                                                 headers={"Content-Type": "application/json"})
                    print("get_current_user 0.1.0.0.2 ::: resp.status_code::::: ", resp.status_code)
                    if resp.status_code == 200:
                        print("0.1.0.0.3 get_current_user resp.status_code == 200: ", resp.status_code)
                        data = resp.json() or {}
                        print("get_current_user 0.1.0.0.3 ::: data::::: ", data)

                        new_access_token = data.get(ACCESS_COOKIE_NAME)
                        new_refresh_token = data.get(REFRESH_COOKIE_NAME)  # 서버가 새 리프레시 토큰을 재발급할 수도 있음
                        print("get_current_user 0.1.0.0.4 통신 직후: new_access_token: ", new_access_token)
                        print("get_current_user 0.1.0.0.4 통신 직후: new_refresh_token: ", new_refresh_token)

                        if not new_access_token:
                            raise HTTPException(status_code=500, detail="refresh 응답에 access_token 없습니다.") # Chat GPT
                            # raise RuntimeError("refresh 응답에 access_token이 없습니다.") # 원래 껏
                            # return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

                        # 여기서 쿠키에 직접 심어줌 (1차 해결책) Chat GPT
                        response.set_cookie(
                            key=ACCESS_COOKIE_NAME,
                            value=new_access_token,
                            httponly=True,
                            secure=True,
                            samesite="lax",
                            path="/"
                        )
                        print("get_current_user 쿠키에 직접 new_access_token 심어줌 (1차 해결책) request.cookies.get(ACCESS_COOKIE_NAME): ", request.cookies.get(ACCESS_COOKIE_NAME))
                        if new_refresh_token:
                            response.set_cookie(
                                key=REFRESH_COOKIE_NAME,
                                value=new_refresh_token,
                                httponly=True,
                                secure=True,
                                samesite="lax",
                                path="/"
                            )
                        print("get_current_user 쿠키에 직접 new_refresh_token 심어줌 (1차 해결책) request.cookies.get(REFRESH_COOKIE_NAME): ", request.cookies.get(REFRESH_COOKIE_NAME))

                        # 또한 request.state에 담아서 Middleware에서도 세팅 가능 (2차 해결책)
                        request.state.new_access_token = new_access_token
                        request.state.new_refresh_token = new_refresh_token
                        print("get_current_user 0.1.0.0.5 통신 후: new_access_token를 request.state에 담아서 Middleware에서도 세팅 가능 (2차 해결책).")
                        print("(2차 해결책)request.state.new_access_token: ", request.state.new_access_token)
                        print("(2차 해결책)request.state.new_refresh_token: ", request.state.new_refresh_token)

                        access_token = new_access_token
                        user = await payload_to_user(access_token, db)
                        return user

                    elif resp.status_code in (400, 401, 403):
                        print("0.1.0.0.3 get_current_user resp.status_code in (400, 401, 403): ", resp.status_code)
                        # 리프레시 토큰이 만료/위조/차단된 경우
                        # 여기서 세션 정리나 강제 로그아웃 처리를 트리거

                        print("0.1.0.0.4 refresh_token 검증 실패로 액세스 토큰 재발급에 실패")
                        raise HTTPException(status_code=resp.status_code, detail="refresh 실패") # Chat GPT custom exc_hander로 홈으로 보낸다.
                        # raise RuntimeError("refresh_token 검증 실패로 액세스 토큰 재발급 실패했습니다.") # 원래 것
                    else:
                        # 기타 예외적인 상태 코드
                        raise RuntimeError(f"리프레시 요청 실패: status={resp.status_code}, body={resp.text}")

            except httpx.HTTPError as e:
                # 네트워크/타임아웃 등의 오류 처리
                raise RuntimeError(f"리프레시 서버와 통신 실패: {e}") from e

        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated: 로그인하지 않았습니다.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 토큰 검증
    user = await payload_to_user(access_token, db)
    return user

async def get_optional_current_user(request: Request, response: Response,
                                    db: AsyncSession = Depends(get_db)) -> Optional[User]:
    """
    인증 토큰이 없거나 유효하지 않은 경우 None을 반환하고, 다른 예외는 그대로 전달합니다.
    AI Chat:
        - 익명 접근을 허용하는 엔드포인트에서는 Depends(get_optional_current_user)를 사용하세요.
            이것을 적용하고 if current_user is None or current_user != user 로 분기하여 "Not authorized: 접근권한이 없습니다."로 raise 날려도 된다.
            그러면, Depends(get_current_user) 주입해서, "Not authenticated: 로그인하지 않았습니다."를 raise 날리는 것과 효과가 같다.
            효과는 같지만, 엄밀한 의미에서는 다르다.
        - 인증이 반드시 필요한 엔드포인트는 기존처럼 Depends(get_current_user)를 유지하면 됩니다.
    """
    try:
        # 핵심: get_current_user를 직접 호출하되, db를 명시적으로 전달
        return await get_current_user(request=request, response=response, db=db)
    except HTTPException as e:
        if e.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN):
            return None
        raise
