import os
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status, Form, UploadFile, File, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from fastapi_mail import MessageSchema
from pydantic import ValidationError, EmailStr, TypeAdapter
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.redis_config import redis_client
from app.core.settings import PROFILE_IMAGE_UPLOAD_DIR, CODE_TTL_SECONDS, AUTHCODE_EMAIL_HTML_TEMPLATE, ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME, ARTICLE_THUMBNAIL_UPLOAD_DIR, \
    ARTICLE_QUILLS_USER_IMG_UPLOAD_DIR, ARTICLE_QUILLS_USER_VIDEO_UPLOAD_DIR
from app.dependencies.auth import get_optional_current_user
from app.models import User
from app.schemas import user as schema_user
from app.schemas.auth import LoginRequest
from app.schemas.user import EmailRequest, VerifyRequest
from app.services import auth_service, user_service
from app.services.auth_service import AuthService
from app.services.token_service import AsyncTokenService, REFRESH_TOKEN_PREFIX
from app.services.user_service import UserService, get_user_service
from app.utils.auth import get_token_expiry
from app.utils.commons import upload_single_image, old_image_remove, remove_dir_with_files, random_string, is_valid_email
from app.utils.exc_handler import CustomErrorException
from app.utils.user import verify_password


router = APIRouter()

@router.post("/register",
             response_model=schema_user.UserOut,
             summary="회원 가입", description="새로운 사용자 등록",
             responses={ 409: {
                 "description": "중복된 이메일로 회원가입 시도",
                 "content": {"application/json": {"example": {"detail": "이미 존재하는 이메일입니다."}}}
             }})
async def register_user(username: str = Form(...),
                        email: str = Form(...),
                        token: str = Form(...),
                        password: str = Form(...),
                        imagefile: UploadFile | None = File(None),
                        _user_service: UserService = Depends(get_user_service)):
    """이메일과 토큰은 입력값이 없어도 진입된다.
    username(닉네임), 비밀번호는 js단에서 빈값 및 validation을 처리한다. 이미지는 없어도 들어온다."""
    print("In register_user: ", username, email, token, password, imagefile)
    verified_key = f"verified:{email}"
    session_key = f"user:{email}"
    verified_token = await redis_client.get(verified_key)
    session_data = await redis_client.hgetall(session_key)

    if not verified_token: # email이 빈칸이어도 여기로 오지만, CustomError 발생시킨다.
        print("CustomErrorException STATUS_CODE: ", 410, "유효하지 않은 인증토큰")
        raise CustomErrorException(status_code=410, detail="유효하지 않은 인증토큰")
    if verified_token != token: # token이 빈칸이어도 여기로 오지만, CustomError 발생시킨다.
        print("CustomErrorException STATUS_CODE: ", 410, "인증토큰 불일치")
        raise CustomErrorException(status_code=410, detail="인증토큰 불일치")
    if not session_data or session_data.get("email") != email: # 들어온 이메일 값이 세션에 저장된 이메일과 다르면, CustomError 발생시킨다.
        print("CustomErrorException STATUS_CODE: ", 410, "세션 이메일 불일치")
        raise CustomErrorException(status_code=410, detail="세션 이메일 불일치")

    try:
        validated_email: EmailStr = TypeAdapter(EmailStr).validate_python(email)
        user_in = schema_user.UserIn(username=username, email=validated_email, password=password)
    except ValidationError as e:
        print("CustomErrorException STATUS_CODE: ", 432, "이메일 형식 부적합")
        raise CustomErrorException(status_code=432, detail="이메일 형식 부적합")

    existed_username = await _user_service.get_user_by_username(user_in.username)
    if existed_username:
        print("CustomErrorException STATUS_CODE: ", 499, "존재하는 닉네임")
        raise CustomErrorException(status_code=499, detail="존재하는 닉네임")

    existed_user_email = await _user_service.get_user_by_email(str(user_in.email))
    if existed_user_email:
        print("CustomErrorException STATUS_CODE: ", 499, "존재하는 이메일")
        raise CustomErrorException(status_code=499, detail="존재하는 이메일")
    created_user = await _user_service.create_user(user_in, img_path=None)

    img_path = None
    if imagefile:
        img_path = await upload_single_image(PROFILE_IMAGE_UPLOAD_DIR, created_user, imagefile)
    created_user = await _user_service.user_image_update(created_user.id, img_path)

    await redis_client.delete(verified_key)
    await redis_client.delete(session_key)

    return JSONResponse(status_code=201, content=jsonable_encoder(created_user))


from enum import Enum
class MessageType(str, Enum):
    PLAIN = "plain"
    HTML = "html"


@router.post("/authcode/request/email",
             summary="인증 코드", description="인증 코드 생성",
             responses={ 401: {
                 "description": "유효하지 않은 인증 코드 확인 시도",
                 "content": {"application/json": {"example": {"detail": "유효하지 않은 인증 코드입니다."}}}
             }})
async def authcode_request_email(payload: EmailRequest,
                                 current_user: Optional[User] = Depends(get_optional_current_user),
                                 _user_service: UserService = Depends(get_user_service)):
    """ 회원 가입시 인증 코드로 본인 확인 """
    email = str(payload.email).lower().strip()
    _type= payload.type
    print("_type: ", _type)
    print("email: ", email)

    try:
        validated_email: EmailStr = TypeAdapter(EmailStr).validate_python(email)
    except ValidationError as e:
        print("CustomErrorException STATUS_CODE: ", 432, "이메일 형식 부적합")
        raise CustomErrorException(status_code=432, detail="이메일 형식 부적합")

    if not is_valid_email(email):
        print("CustomErrorException STATUS_CODE: ", 413, "유효하지 않은 이메일")
        raise CustomErrorException(status_code=413, detail="유효하지 않은 이메일")

    if _type != "lost":
        existed_email_user = await _user_service.get_user_by_email(str(email))
        if current_user:
            if _type == "email":
                if existed_email_user and existed_email_user.email == current_user.email:
                    raise CustomErrorException(status_code=499, detail="동일한 이메일")
            if existed_email_user and existed_email_user.email != current_user.email: # 이런 경우는 없는 것 같은데...
                raise CustomErrorException(status_code=499, detail="존재하는 이메일")
        else: # register
            if existed_email_user:
                raise CustomErrorException(status_code=499, detail="존재하는 이메일")
    # 비번 lost
    recent_key = f"verify_recent:{email}"
    if await redis_client.exists(recent_key):
        print("CustomErrorException STATUS_CODE: ", 439, "과도한 요청")
        raise CustomErrorException(status_code=439, detail="과도한 요청")

    session_key = f"user:{email}" # Redis 해시 키 (세션 역할)
    await redis_client.hset(session_key, mapping={"email": email})  # Redis에 이메일 저장 (hset)
    await redis_client.expire(session_key, CODE_TTL_SECONDS)
    """ Redis의 hset() 명령 자체는 **만료시간(TTL)**을 직접 지정할 수 없어요.
        대신에 **키 전체(session_key)**에 대해 만료시간을 따로 expire() 또는 expireat()으로 설정해야 합니다.        
        즉, hset()으로 저장한 뒤에 expire()를 호출하는 방식으로 처리합니다. """

    authcode = str(await random_string(7, "number"))
    code_key = f"verify:{email}"
    await redis_client.set(code_key, authcode, ex=CODE_TTL_SECONDS) # Redis에 인증코드 저장하고 TTL 설정 (10분)
    await redis_client.set(recent_key, "1", ex=30) # 최근 요청 키(예: 30초 내 재요청 방지) - 선택

    print("await redis_client.get(code_key): ", await redis_client.get(code_key))

    title = None
    if _type == "register":
        title = "[서비스] 회원가입 인증번호"
    elif _type == "lost":
        title = "[서비스] 비밀번호 설정 인증번호"
    elif _type == "email":
        title = "[서비스] 이메일 변경 인증번호"

    from jinja2 import Template
    verify_link = f"{os.getenv('DEV_API_BASE_URL', 'http://localhost:8000')}/verify" # 사용하지 않았다.
    html_body = Template(AUTHCODE_EMAIL_HTML_TEMPLATE).render(code=authcode, title=title)#, verify_link=verify_link) # 직접 입력으로 교체

    message = MessageSchema(
        subject=title,
        recipients=[validated_email],
        body=html_body,
        subtype=MessageType.HTML, # "html", # Expected type 'MessageType', got 'str' instead (AI chat)
    )

    try:
        from main import fastapi_email
        await fastapi_email.send_message(message)
    except Exception as e:
        await redis_client.delete(code_key) # 실패 시 Redis에 저장된 코드 제거
        print("이메일 전송 실패: ", e)
        raise CustomErrorException(status_code=600, detail="이메일 전송 실패")

    return JSONResponse({"message": "인증번호를 이메일로 발송했습니다. (10분간 유효)"})


@router.post("/authcode/verify",
             summary="인증 코드", description="인증 코드 확인",
             responses={ 401: {
                 "description": "유효하지 않은 인증 코드 확인 시도",
                 "content": {"application/json": {"example": {"detail": "유효하지 않은 인증 코드입니다."}}}
             }})
async def authcode_verify(payload: VerifyRequest,
                          db: AsyncSession = Depends(get_db)):
    """ 회원 가입시 인증 코드로 본인 확인 """
    email = str(payload.email).lower().strip()
    authcode = payload.authcode.strip()
    _type = payload.type
    password = payload.password
    old_email = payload.old_email
    print("_type: ", _type)
    print("old_email: ", old_email)
    print("email: ", email)
    print("password", password)

    code_key = f"verify:{email}"
    session_key = f"user:{email}"
    stored_code = await redis_client.get(code_key) # Redis에서 코드 확인
    session_data = await redis_client.hgetall(session_key) # 세션에 저장된 이메일 확인
    print("stored_code: ", stored_code)
    print("session_data: ", session_data)
    if not stored_code:
        print("CustomErrorException STATUS_CODE: ", 410, "유효하지 않은 인증코드")
        raise CustomErrorException(status_code=410, detail="유효하지 않은 인증코드") # 만료되었거나 존재하지 않습니다.
    if stored_code != authcode:
        print("CustomErrorException STATUS_CODE: ", 410, "인증코드 불일치")
        raise CustomErrorException(status_code=410, detail="인증코드 불일치")
    if not session_data or session_data.get("email") != email:
        print("CustomErrorException STATUS_CODE: ", 410, "세션 이메일 불일치")
        raise CustomErrorException(status_code=410, detail="세션 이메일 불일치")

    if old_email and _type == "email":
        # 새로운 이메일 저장과정
        _user_service = UserService(db=db)
        old_user = await _user_service.get_user_by_email(old_email)
        if old_user:

            user_data = {"email": email, "password": password}
            login_data = LoginRequest(**user_data)

            password_ok = await verify_password(password, str(old_user.password))
            if password_ok:
                old_validated_email: EmailStr = TypeAdapter(EmailStr).validate_python(old_email)
                await _user_service.update_email(old_validated_email, payload.email)
                await redis_client.delete(code_key)  # 검증 성공 -> 코드 삭제(한번만 사용)
                return JSONResponse({"message": "이메일 변경 성공: 확인을 클릭하면, 새로운 이메일로 로그인됩니다."})
            else:
                raise CustomErrorException(status_code=411,
                                           detail="비밀번호 불일치",
                                           headers={"WWW-Authenticate": "Bearer"})
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="회원을 찾을 수 없습니다."
            )
    await redis_client.delete(code_key) # 검증 성공 -> 코드 삭제(한번만 사용)

    verified_token = str(uuid.uuid4())
    verified_key = f"verified:{email}"
    await redis_client.set(verified_key, verified_token, ex=CODE_TTL_SECONDS)  # 10분 동안 유지

    if _type == "register":
        message = "이메일 인증 성공: 회원가입을 진행하세요."
    else: # _type == "lost" # 비번 분실/설정
        message = "이메일 인증 성공: 비밀번호 설정을 진행하세요."
    return JSONResponse({"message": message,
                         "verified_token": verified_token})


@router.get("/",
            response_model=list[schema_user.UserOut],
            summary="모든 회원 조회", description="모든 회원들을 최신 등록순으로 조회",
            responses={404: {
                "description": "회원들 조회 실패",
                "content": {"application/json": {"example": {"detail": "게시글을 찾을 수 없습니다."}}}
            }})
async def get_users(_user_service: UserService = Depends(get_user_service)):
    users = await _user_service.get_users()

    if users is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="가입한 회원이 없습니다."
        )

    return users


@router.get("/{user_id}", response_model=schema_user.UserOut,
            summary="특정 회원 조회", description="회원의 ID 기반으로 특정 회원 조회",
            responses={404: {
                "description": "회원 조회 실패",
                "content": {"application/json": {"example": {"detail": "회원을 찾을 수 없습니다."}}}
            }})
async def get_user(user_id: int,
                   _user_service: UserService = Depends(get_user_service)):
    user = await _user_service.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="해당 회원이 존재하지 않습니다."
        )

    return user


@router.patch("/{user_id}", response_model=schema_user.UserOut,
              summary="회원 정보 수정", description="특정 회원의 정보를 수정합니다.",
              responses={404: {
                  "description": "회원 정보 수정 실패",
                  "content": {"application/json": {"example": {"detail": "회원을 찾을 수 없습니다."}}},
                  403: {
                      "description": "회원 정보 수정 권한 없슴",
                      "content": {"application/json": {"example": {"detail": "접근 권한이 없습니다."}}}
                  }
              }})
async def update_user(user_id: int,
                      username: str | None = Form(None),
                      email: str | None = Form(None),
                      imagefile: UploadFile | None = File(None),
                      password: str | None = Form(None),
                      _user_service: UserService = Depends(get_user_service)):

    from app.utils.exc_handler import CustomErrorException
    user = await _user_service.get_user_by_id(user_id)

    existed_username_user = await _user_service.get_user_by_username(username)
    if existed_username_user and existed_username_user.username != user.username:
        raise CustomErrorException(status_code=499, detail="존재하는 닉네임")

    existed_email_user = await _user_service.get_user_by_email(str(email))
    if existed_email_user and existed_email_user.email != user.email:
        raise CustomErrorException(status_code=499, detail="존재하는 이메일")

    try:
        user_update = schema_user.UserUpdate(username=username, email=email)
        password_ok = await verify_password(password, str(user.password))
        if password_ok:
            updated_user = await _user_service.update_user(user_id, user_update)
            if imagefile is not None:
                filename_only, ext = os.path.splitext(imagefile.filename)
                if len(imagefile.filename.strip()) > 0 and len(filename_only) > 0:
                    if user.img_path:
                        await old_image_remove(imagefile.filename, user.img_path)
                    img_path = await upload_single_image(PROFILE_IMAGE_UPLOAD_DIR, updated_user, imagefile)
                    updated_user = await _user_service.user_image_update(updated_user.id, img_path)
            else:
                img_path = user.img_path # user.img_path인 경우도 적용된다.
                updated_user = await _user_service.user_image_update(updated_user.id, img_path)
        else:
            raise CustomErrorException(status_code=411, detail="비밀번호 불일치")

        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="회원을 찾을 수 없습니다."
            )
        return updated_user

    except ValidationError as e:
        print("except ValidationError as e:", e.errors())
        print("except ValidationError as e.errors():", e.errors()[0]["loc"][0])
        # 요청 본문에 대한 자동 422 변환이 아닌, 수동으로 422로 변환해 주는 것이 좋습니다.
        if email is not None and e.errors()[0]["loc"][0]=="email":
            raise CustomErrorException(status_code=432, detail="이메일 형식 부적합")
        elif username is not None and e.errors()[0]["loc"][0]=="username":
            raise CustomErrorException(status_code=432, detail="닉네임 정책 위반")


@router.patch("/{user_id}/image", response_model=schema_user.UserOut,
              summary="회원 프로필 이미지 수정", description="특정 회원의 프로필 이미지를 수정합니다.",
              responses={404: {
                  "description": "회원 프로필 이미지 수정 실패",
                  "content": {"application/json": {"example": {"detail": "회원을 찾을 수 없습니다."}}},
                  403: {
                      "description": "회원 프로필 이미지 수정 권한 없슴",
                      "content": {"application/json": {"example": {"detail": "접근 권한이 없습니다."}}}
                  }
              }}) # 이 라우터는 사용하지 않고 있다.
async def update_user_image(user_id: int,
                            imagefile: UploadFile | None = File(None),
                            _user_service: UserService = Depends(get_user_service)):
    user = await _user_service.get_user_by_id(user_id)
    if user:
        if len(imagefile.filename.strip()) > 0:
            ## My Add ############## 이미지 교체하면, 예전에 있던 이미지 삭제하기
            if user.img_path:
                await old_image_remove(imagefile.filename, user.img_path)
            ## Add End ##############
            img_path = await upload_single_image(PROFILE_IMAGE_UPLOAD_DIR, user, imagefile)
            await _user_service.user_image_update(user_id, img_path)
        else:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="입력된 이미지 파일이 없습니다."
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="회원을 찾을 수 없습니다."
        )

    return user


@router.patch("/password/{user_id}", response_model=schema_user.UserOut,
              summary="회원 비밀번호 수정", description="특정 회원의 비밀번호를 수정합니다.",
              responses={404: {
                  "description": "회원 비밀번호 수정 실패",
                  "content": {"application/json": {"example": {"detail": "회원을 찾을 수 없습니다."}}},
                  403: {
                      "description": "회원 비밀번호 수정 권한 없슴",
                      "content": {"application/json": {"example": {"detail": "접근 권한이 없습니다."}}}
                  }
              }})
async def update_user_password(user_id: int,
                               password: str = Form(...),
                               newpassword: str = Form(...),
                               _user_service: UserService = Depends(get_user_service)):

    user = await _user_service.get_user_by_id(user_id)
    if user:
        password_update = schema_user.UserPasswordUpdate(password=newpassword)
        password_ok = await verify_password(password, str(user.password))
        if password_ok:
            await _user_service.update_password(user_id, password_update)
        else:
            # raise HTTPException(
            #     status_code=status.HTTP_401_UNAUTHORIZED,
            #     detail="기존 비밀번호 불일치",
            #     headers={"WWW-Authenticate": "Bearer"}
            # )
            raise CustomErrorException(status_code=411, detail="기존 비밀번호 불일치")

    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="회원을 찾을 수 없습니다."
        )

    return user


@router.patch("/lost/password/setting",# response_model=schema_user.UserOut,
              summary="회원 비밀번호 분실/설정", description="특정 회원의 비밀번호를 분실하여 재설정합니다.",
              responses={404: {
                  "description": "회원 비밀번호 설정 실패",
                  "content": {"application/json": {"example": {"detail": "회원을 찾을 수 없습니다."}}},
                  403: {
                      "description": "회원 비밀번호 수정 권한 없슴",
                      "content": {"application/json": {"example": {"detail": "접근 권한이 없습니다."}}}
                  }
              }})
async def update_user_lost_password(email: str = Form(...),
                                    token: str = Form(...),
                                    newpassword: str = Form(...),
                                    _user_service: UserService = Depends(get_user_service)):
    verified_key = f"verified:{email}"
    session_key = f"user:{email}"
    verified_token = await redis_client.get(verified_key)
    session_data = await redis_client.hgetall(session_key)

    if not verified_token:  # email이 빈칸이어도 여기로 오지만, CustomError 발생시킨다.
        raise CustomErrorException(status_code=410, detail="유효하지 않은 인증토큰")
    if verified_token != token: # token이 빈칸이어도 여기로 오지만, CustomError 발생시킨다.
        raise CustomErrorException(status_code=410, detail="인증토큰 불일치")
    if not session_data or session_data.get("email") != email: # 들어온 이메일 값이 세션에 저장된 이메일과 다르면, CustomError 발생시킨다.
        raise CustomErrorException(status_code=410, detail="세션 이메일 불일치")

    user = await _user_service.get_user_by_email(email)
    if user:
        password_update = schema_user.UserPasswordUpdate(password=newpassword)
        await _user_service.update_password(user.id, password_update)

    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="회원을 찾을 수 없습니다."
        )

    await redis_client.delete(verified_key)
    await redis_client.delete(session_key)

    # return user
    return JSONResponse({"message": "비밀번호 설정 성공: 확인을 클릭하면, 설정된 비밀번호로 로그인됩니다."})




@router.delete("/delete/{user_id}",
               summary="회원 탈퇴",
               description="특정 회원을 탈퇴 시킵니다.",
               responses={200: {
                   "description": "회원 탈퇴 성공",
                   "content": {"application/json": {"example": {"detail": "회원의 탈퇴가 성공적으로 이루어 졌습니다."}}},
                   404: {
                       "description": "회원 탈퇴 실패",
                       "content": {"application/json": {"example": {"detail": "회원을 찾을 수 없습니다."}}}
                   }
               }})
async def delete_user(user_id: int,
                      request: Request,
                      # response: Response,
                      _user_service: UserService = Depends(get_user_service)):

    _user = await _user_service.get_user_by_id(user_id)
    if _user is False:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="회원을 찾을 수 없습니다."
        )

    # article(게시글)의 썸네일, quill 내용의 이미지/동영상 삭제
    # article(게시글)의 내용 자체는 모델에서 삭제되도록 ORM정의해놓음 """cascade="all, delete-orphan","""
    article_thumb_dir = f'{ARTICLE_THUMBNAIL_UPLOAD_DIR}\\{user_id}'
    content_img_dir = f'{ARTICLE_QUILLS_USER_IMG_UPLOAD_DIR}\\{user_id}'
    content_video_dir = f'{ARTICLE_QUILLS_USER_VIDEO_UPLOAD_DIR}\\{user_id}'
    await remove_dir_with_files(article_thumb_dir)
    await remove_dir_with_files(content_img_dir)
    await remove_dir_with_files(content_video_dir)

    user_thumb_dir = f'{PROFILE_IMAGE_UPLOAD_DIR}\\{user_id}'
    await remove_dir_with_files(user_thumb_dir)
    """프로필 이미지는 삭제한다. 하지만, 
    게시글의 author_id는 남겨두고, 해당 회원이 작성했던 게시글은 비활성화 하는 것으로 처리하자."""
    print("delete_user user_id:", user_id)
    await _user_service.delete_user(user_id)

    #############################
    access_token = request.cookies.get(ACCESS_COOKIE_NAME)
    refresh_token = request.cookies.get(REFRESH_COOKIE_NAME)

    resp = JSONResponse(
        status_code=200,
        content={"detail": "회원의 탈퇴가 성공적으로 이루어졌습니다."}
    )
    domain = request.url.hostname

    resp.delete_cookie(
        key=ACCESS_COOKIE_NAME,
        path="/",
        domain=domain,  # 필요 시 명시적으로 지정
        httponly=True
    )
    resp.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path="/",
        domain=domain,
        httponly=True
    )

    if access_token:
        access_exp = get_token_expiry(access_token)
        await AsyncTokenService.blacklist_token(access_token, access_exp)
    if refresh_token:
        refresh_exp = get_token_expiry(refresh_token)
        await AsyncTokenService.blacklist_token(refresh_token, refresh_exp)
        # 만약 Redis에 별도 키로 저장했다면 삭제:
        await redis_client.delete(f"{REFRESH_TOKEN_PREFIX}{user_id}")

    request.state.skip_set_cookie = True
    print("Final headers:", resp.headers.getlist("set-cookie"))

    print("쿠키 삭제 확인 request.cookies.get(ACCESS_COOKIE_NAME): ", request.cookies.get(ACCESS_COOKIE_NAME))
    print("쿠키 삭제 확인 request.cookies.get(REFRESH_COOKIE_NAME): ", request.cookies.get(REFRESH_COOKIE_NAME))
    print("response.raw_headers: ", resp.raw_headers)

    return resp
