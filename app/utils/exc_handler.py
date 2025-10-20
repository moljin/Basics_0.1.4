import asyncio
import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.requests import Request
from fastapi import status, HTTPException, Response, Depends

from app.core.database import get_db
from app.core.settings import templates, ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME
from app.dependencies.auth import get_optional_current_user

"""
400 == 410: Bad Request Error
401 == 411: Unauthorized Error
402 == 412: Payment Required Error
403 == 413: Forbidden Error
404 == 414: Not Found Error
405 == 415: Method Not Allowed Error
406 == 416: Not Acceptable Error
407 == 417: Proxy Authentication Required Error
408 == 418: Request Timeout Error
409 == 499: Existed Conflict Error
421 == 431: Misdirected Request Error
422 == 432: Unprocessable Entity Error
423 == 433: Locked Error 
429 == 439: Too Many Requests Error

500 == 600: Internal Server Error
"""

class CustomErrorException(HTTPException):
    def __init__(self, status_code: int, detail: str, headers: dict = None):
        super().__init__(status_code=status_code, detail=detail, headers=headers)


async def custom_http_exception_handler(request: Request, exc: Exception):
    '''
    if exc.status_code == 401 and exc.detail == "refresh 실패":
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )'''

    # 필요하다면 내부에서 Response 인스턴스 생성
    response = Response()

    if isinstance(exc, StarletteHTTPException):
        '''
        FastAPI에서 `isinstance()`는 특정 객체가 지정된 클래스 또는 타입의 인스턴스인지 확인하는 데 사용되는 파이썬 내장 함수입니다. 
        FastAPI에서는 주로 데이터 유효성 검증, 요청 데이터 처리, 또는 로직 분기 등을 위해 사용됩니다. 
        '''
        status_code = exc.status_code
        detail = exc.detail
    else:
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        detail = "Internal Server Error"

    '''아래처럼 if 문으로 등록하면, 상태코드는 200으로 바뀌면서 json을 반환하게 된다. 
    js 단에서 잡아내서 errorTag.innerHTML하기 위해서...'''
    if status_code in (410, 411, 413, 415, 432, 439, 499, 600):
        return JSONResponse({"detail": f'{detail}'})

    if (status_code in (400, 401, 403)) and (getattr(exc, "detail", None) == "refresh 실패"):
        print("커스텀 exception handler refresh 실패", (getattr(exc, "detail", None)))
        current_user = None
        try:
            async for db in get_db():
                maybe_user = get_optional_current_user(request, response, db)
                # 의존성 함수가 동기일 수도 있으므로 안전하게 처리
                if asyncio.iscoroutine(maybe_user):
                    current_user = await maybe_user
                else:
                    current_user = maybe_user
                break
        except Exception as e:
            print("Error: ", e)
            current_user = None

        now_time_utc = datetime.datetime.now(datetime.timezone.utc)
        now_time = datetime.datetime.now()
        access_token = request.cookies.get(ACCESS_COOKIE_NAME)
        refresh_token = request.cookies.get(REFRESH_COOKIE_NAME)

        template = "common/index.html"
        context = {
            "request": request,
            "title": "Hello World!!!",
            "now_time_utc": now_time_utc,
            "now_time": now_time,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "current_user": current_user,
        }
        return templates.TemplateResponse(template, context, status_code=status.HTTP_200_OK)

    print("NOT REFRESH: 400 or 401 or 403: ", status_code)
    return templates.TemplateResponse(
            request = request,
            name="common/exceptions/http_error.html",
            context={
                "status_code": status_code,
                "title_message": "불편을 드려 죄송합니다.",
                "detail": detail
            },
            status_code = status_code
        )