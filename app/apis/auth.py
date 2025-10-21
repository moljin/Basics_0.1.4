from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordRequestForm

from app.core.settings import ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME, REFRESH_COOKIE_EXPIRE, ACCESS_COOKIE_MAX_AGE
from app.schemas.auth import RefreshRequest, TokenResponse, LoginRequest
from app.services.auth_service import AuthService, get_auth_service
from app.services.token_service import AsyncTokenService
from app.utils.auth import get_token_expiry, verify_token

router = APIRouter()
bearer_scheme = HTTPBearer()

"""
사용자 로그인 및 JWT 토큰 발급
"""


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="사용자 로그인",
    description="사용자 로그인 후 JWT 토큰을 발급합니다.",
    responses={
        401: {
            "description": "인증 실패",
            "content": {"application/json": {"example": {"detail": "인증 실패"}}}
        }})
async def login(response: Response, request: Request,
                login_data: LoginRequest,
                auth_service: AuthService = Depends(get_auth_service)):

    user = await auth_service.authenticate_user(login_data)
    if not user:
        from app.utils.exc_handler import CustomErrorException
        raise CustomErrorException(status_code=411,
                                   detail="인증 실패",
                                   headers={"WWW-Authenticate": "Bearer"})

    # 토큰 생성 create_user_token
    token_data = await auth_service.create_user_token(user)
    _access_token = token_data.get(ACCESS_COOKIE_NAME)
    _refresh_token = token_data.get(REFRESH_COOKIE_NAME)

    """쿠키를 만들때 request.url을 기준으로 swagger UI에서는 만들지 말자"""
    referer_url = request.headers.get("referer", "").lower()
    parsed_path = urlparse(referer_url).path

    login_url = "/accounts/login"
    register_url = "/accounts/register"
    update_url = "/accounts/account/update/"+str(user.id)
    print("parsed_path: ", parsed_path)
    print("login_url: ", login_url)

    # 요청 정보로 HTTPS 여부 판별 (프록시가 있다면 x-forwarded-proto 우선)
    is_https = (request.headers.get("x-forwarded-proto") or request.url.scheme) == "https"

    if parsed_path == login_url or register_url or update_url:
        response.set_cookie(
            key=ACCESS_COOKIE_NAME,
            value=_access_token,
            httponly=True,
            secure=is_https,  # HTTPS 환경 권장
            samesite="lax",
            max_age=ACCESS_COOKIE_MAX_AGE,

        )

        response.set_cookie(
            key=REFRESH_COOKIE_NAME,
            value=_refresh_token,
            httponly=True,  # JavaScript에서 쿠키에 접근 불가능하도록 설정
            secure=is_https,  # HTTPS 환경에서만 쿠키 전송
            samesite="strict",  # CSRF 공격 방지
            expires = REFRESH_COOKIE_EXPIRE
        )

        return token_data
    else:
        return None


# OAuth2 호환 로그인 엔드포인트 (Swagger UI에서 인증 가능)
"""
OAuth2 호환 토큰 발급 (form 데이터 사용)
"""


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="OAuth2 호환 토큰 발급",
    description="OAuth2 호환 토큰을 발급합니다. \n "
                "username에 이메일을 넣으세요. \n "
                "OAuth2PasswordRequestForm이 username으로 받기때문에 임시 방편으로 사용하고 있다. \n 서버단에서 email에 할당하고 있다.",
    responses={
        401: {
            "description": "인증 실패",
            "content": {"application/json": {"example": {"detail": "인증 실패",}}}
        }})
async def login_for_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(),
        auth_service: AuthService = Depends(get_auth_service)
):
    # OAuth2 폼 데이터를 LoginRequest로 변환
    print("login_for_access_token form_data: ", form_data)
    login_data = LoginRequest(
        email=form_data.username, # 내가 수정: email 이지만 OAuth2PasswordRequestForm이 username으로 받기때문에 임시 방편으로 사용하고 있다.
        password=form_data.password
    )

    # 사용자 인증
    user = await auth_service.authenticate_user(login_data)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="인증 실패",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # 토큰 생성
    token_data = await auth_service.create_user_token(user)

    return token_data


"""
사용자 로그아웃 - 현재 토큰을 블랙리스트에 추가
"""


@router.post(
    "/logout",
    summary="사용자 로그아웃",
    description="사용자 로그아웃",
    responses={
        200: {
            "description": "로그아웃 성공",
            "content": {"application/json": {"example": {"message": "로그아웃되었습니다."}}}
        }})
async def logout(
        response: Response,
        request: Request,
        # credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
):
    print(f"logout: swagger UI 열쇠에서 로그인 해야 로그아웃이 된다.")
    # # 헤더에서 토큰 추출
    token = credentials.credentials
    print("logout token: ", token)

    # 현재 토큰의 만료 시간 계산
    token_expiry = get_token_expiry(token)
    print("logout token_expiry: ", token_expiry)

    # 토큰을 블랙리스트에 추가
    await AsyncTokenService.blacklist_token(token, token_expiry)

    return {"message": "로그아웃되었습니다."}


"""
Refresh 토큰을 사용하여 새로운 액세스 토큰 발급
"""


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="리프레시 토큰으로 액세스 토큰 갱신",
    description="리프레시 토큰을 사용하여 새로운 액세스 토큰을 발급합니다.",
    responses={
        401: {
            "description": "사용자 접근 권한 인증 실패",
            "content": {"application/json": {"example": {"detail": "사용자 접근이 유효하지 않습니다."}}}
        }})
async def refresh_token(refresh_data: RefreshRequest, response: Response, request: Request,
                        auth_service: AuthService = Depends(get_auth_service)):

    # 리프레시 토큰으로 새 액세스 토큰 발급
    tokens = await auth_service.refresh_access_token(refresh_data.refresh_token)
    print("0.0.1 통신 중 tokens====== new_access_token이 들어있다.", tokens)
    if not tokens:
        raise HTTPException(
            status_code=401,
            detail="사용자 접근이 유효하지 않습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # refresh_token 필드 추가 (기존 리프레시 토큰 유지)
    tokens[REFRESH_COOKIE_NAME] = refresh_data.refresh_token

    print("0.0.2 통신 중 tokens['access_token']::::::::: ", tokens.get(ACCESS_COOKIE_NAME))
    print("0.0.3 통신 중 tokens['refresh_token']::::::::: ", tokens.get(REFRESH_COOKIE_NAME))

    return tokens


"""
사용자의 모든 세션 로그아웃 - 현재 토큰을 블랙리스트에 추가하고
모든 리프레시 토큰 무효화
"""

@router.post(
    "/logout-all",
    summary="모든 기기 로그아웃",
    description="사용자의 모든 기기에서 로그아웃합니다.",
    responses={
        200: {
            "description": "모든 기기로부터 로그아웃 성공",
            "content": {"application/json": {"example": {"message": "모든 기기로부터 로그아웃되었습니다."}}}
        }})
async def logout_all_sessions(
        credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    token = credentials.credentials

    # 현재 액세스 토큰 블랙리스트에 추가
    token_expiry = get_token_expiry(token)
    await AsyncTokenService.blacklist_token(token, token_expiry)

    user_id = verify_token(token).get("user_id")
    await AsyncTokenService.revoke_refresh_token(user_id)

    return {"message": "모든 기기로부터 로그아웃되었습니다."}