from typing import Optional

from fastapi import Request, APIRouter, Response, status, Depends, HTTPException
from fastapi.responses import HTMLResponse

from app.dependencies.auth import get_optional_current_user
from app.models import User
from app.schemas import user as schema_user
from app.core.settings import templates, ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME
from app.services.token_service import AsyncTokenService
from app.services.user_service import get_user_service, UserService
from app.utils.auth import get_token_expiry

router = APIRouter()

@router.get("/register", response_class=HTMLResponse,
            summary="회원가입 HTML", description="회원가입 templates.TemplateResponse")
async def register_page(request: Request,
                        current_user: Optional[User] = Depends(get_optional_current_user)):
    # template = "accounts/update_auth_not_use.html"
    template = "accounts/register.html"
    context = {'request': request,
               'current_user': current_user}
    return templates.TemplateResponse(template, context)


@router.get("/login", response_class=HTMLResponse,
            summary="로그인 HTML", description="로그인 templates.TemplateResponse")
async def login_page(request: Request):
    template = "accounts/login.html"
    context = {'request': request}
    return templates.TemplateResponse(template, context)

@router.post(
    "/logout",
    summary="로그아웃 HTML",
    description="로그아웃 templates.TemplateResponse",
    responses={
        200: {
            "description": "로그아웃 성공",
            "content": {"application/json": {"example": {"message": "로그아웃되었습니다."}}}
        }})
async def logout(
        response: Response,
        request: Request
):

    #############################
    access_token = request.cookies.get(ACCESS_COOKIE_NAME)
    refresh_token = request.cookies.get(REFRESH_COOKIE_NAME)
    # 쿠키 삭제
    response.delete_cookie(key=ACCESS_COOKIE_NAME, path="/")
    response.delete_cookie(key=REFRESH_COOKIE_NAME, path="/")

    # 블랙리스트 처리
    if access_token:
        expiry = get_token_expiry(access_token)
        await AsyncTokenService.blacklist_token(access_token, expiry)
    if refresh_token:
        expiry = get_token_expiry(refresh_token)
        await AsyncTokenService.blacklist_token(refresh_token, expiry)
    print("로그아웃")

    return {"message": "로그아웃되었습니다."}


@router.get("/account/{user_id}", response_model=schema_user.UserOut,
            summary="특정 회원 조회 HTML", description="회원의 ID 기반으로 특정 회원 조회 templates.TemplateResponse",
            responses={404: {
                "description": "회원 조회 실패",
                "content": {"application/json": {"example": {"detail": "회원을 찾을 수 없습니다."}}}
            }})
async def get_user__by_id(request: Request, user_id: int,
                   user_service: UserService = Depends(get_user_service),
                   current_user: Optional[User] = Depends(get_optional_current_user)):

    user = await user_service.get_user_by_id(user_id)
    from app.utils.exc_handler import CustomErrorException
    if current_user is None:
        if not user or user:
            raise CustomErrorException(status_code=403, detail="로그인하지 않지 않았습니다.")
    else:
        if current_user.id != user_id or not user:
            raise CustomErrorException(status_code=403, detail="접근권한이 없습니다.")

    template = "accounts/detail.html"
    context = {'request': request,
               "current_user": current_user}
    return templates.TemplateResponse(template, context)


@router.get("/account/update/{user_id}", response_class=HTMLResponse,
            summary="회원정보 수정 페이지 HTML", description="회원정보 수정 페이지 templates.TemplateResponse")
async def user_update_ui(request: Request, user_id: int,
                         user_service: UserService = Depends(get_user_service),
                         current_user: Optional[User] = Depends(get_optional_current_user)):

    user = await user_service.get_user_by_id(user_id)
    from app.utils.exc_handler import CustomErrorException
    if current_user is None:
        if not user or user:
            raise CustomErrorException(status_code=403, detail="로그인하지 않지 않았습니다.")
    else:
        if current_user.id != user_id or not user:
            raise CustomErrorException(status_code=403, detail="접근권한이 없습니다.")

    template = "accounts/update.html"
    context = {'request': request,
               "current_user": current_user}
    return templates.TemplateResponse(template, context)


@router.get("/account/username/update/{user_id}", response_class=HTMLResponse,
            summary="회원 닉네임 수정 페이지 HTML", description="회원 닉네임 수정 페이지 templates.TemplateResponse")
async def update_username(request: Request, user_id: int,
                         user_service: UserService = Depends(get_user_service),
                         current_user: Optional[User] = Depends(get_optional_current_user)):
    user = await user_service.get_user_by_id(user_id)
    from app.utils.exc_handler import CustomErrorException
    if current_user is None:
        if not user or user:
            raise CustomErrorException(status_code=403, detail="로그인하지 않지 않았습니다.")
    else:
        if current_user.id != user_id or not user:
            raise CustomErrorException(status_code=403, detail="접근권한이 없습니다.")


    template = "accounts/each.html"
    context = {'request': request,
               "current_user": current_user,
               "username": current_user.username,}
    return templates.TemplateResponse(template, context)


@router.get("/account/email/update/{user_id}", response_class=HTMLResponse,
            summary="회원 이메일 수정 페이지 HTML", description="회원 이메일 수정 페이지 templates.TemplateResponse")
async def update_user_email(request: Request, user_id: int,
                         user_service: UserService = Depends(get_user_service),
                         current_user: Optional[User] = Depends(get_optional_current_user)):
    user = await user_service.get_user_by_id(user_id)
    from app.utils.exc_handler import CustomErrorException
    if current_user is None:
        if not user or user:
            raise CustomErrorException(status_code=403, detail="로그인하지 않지 않았습니다.")
    else:
        if current_user.id != user_id or not user:
            raise CustomErrorException(status_code=403, detail="접근권한이 없습니다.")

    template = "accounts/each.html"
    context = {'request': request,
               "current_user": current_user,
               "email": current_user.email,}
    return templates.TemplateResponse(template, context)


@router.get("/account/image/update/{user_id}", response_class=HTMLResponse,
            summary="회원 프로필 이미지 수정 페이지 HTML", description="회원 프로필 이미지 수정 페이지 templates.TemplateResponse")
async def update_user_image(request: Request, user_id: int,
                         user_service: UserService = Depends(get_user_service),
                         current_user: Optional[User] = Depends(get_optional_current_user)):
    user = await user_service.get_user_by_id(user_id)
    from app.utils.exc_handler import CustomErrorException
    if current_user is None:
        if not user or user:
            raise CustomErrorException(status_code=403, detail="로그인하지 않지 않았습니다.")
    else:
        if current_user.id != user_id or not user:
            raise CustomErrorException(status_code=403, detail="접근권한이 없습니다.")

    template = "accounts/each.html"
    context = {'request': request,
               "current_user": current_user,
               "image": "image",}
    return templates.TemplateResponse(template, context)


@router.get("/account/password/update/{user_id}", response_class=HTMLResponse,
            summary="회원 비밀번호 수정 페이지 HTML", description="회원 비밀번호 수정 페이지 templates.TemplateResponse")
async def update_user_password(request: Request, user_id: int,
                         user_service: UserService = Depends(get_user_service),
                         current_user: Optional[User] = Depends(get_optional_current_user)):

    user = await user_service.get_user_by_id(user_id)
    from app.utils.exc_handler import CustomErrorException
    if current_user is None:
        if not user or user:
            raise CustomErrorException(status_code=403, detail="로그인하지 않지 않았습니다.")
    else:
        if current_user.id != user_id or not user:
            raise CustomErrorException(status_code=403, detail="접근권한이 없습니다.")

    template = "accounts/each.html"
    context = {'request': request,
               "current_user": current_user,
               "password": current_user.password,}
    return templates.TemplateResponse(template, context)


@router.get("/account/lost/password/setting", response_class=HTMLResponse,
            summary="회원 비밀번호 분실/설정 페이지 HTML", description="회원 비밀번호 분실/설정 페이지 templates.TemplateResponse")
async def update_user_lost_password(request: Request,
                         user_service: UserService = Depends(get_user_service),
                         current_user: Optional[User] = Depends(get_optional_current_user)):
    template = "accounts/lost.html"
    context = {'request': request,
               "current_user": current_user}
    return templates.TemplateResponse(template, context)