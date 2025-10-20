import datetime
import os
from typing import Optional

from dns.edns import COOKIE
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi import APIRouter, Request, Depends

from app.core.settings import templates, ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME, ADMINS
from app.dependencies.auth import get_optional_current_user
from app.models import User

router = APIRouter()


@router.get("/", response_class=HTMLResponse,
            summary="시작 페이지", description="여기는 Root 페이지입니다.")
async def get_root(request: Request):
    return RedirectResponse(url="/articles")

@router.get("/index", response_class=HTMLResponse,
            summary="참고 페이지", description="여기는 참고 index 페이지입니다.")
async def get_index(request: Request,
                   current_user: Optional[User] = Depends(get_optional_current_user)):
    now_time_utc = datetime.datetime.now(datetime.timezone.utc)
    now_time = datetime.datetime.now()
    access_token = request.cookies.get(ACCESS_COOKIE_NAME)
    print("get_root access_token:", access_token)
    csrf_token = request.cookies.get("csrf_token")
    print("get_root csrf_token:", csrf_token)
    refresh_token = request.cookies.get(REFRESH_COOKIE_NAME)
    print("get_root refresh_token:", refresh_token)

    admin = False
    if current_user.username in ADMINS:
        admin = True

    template = "common/index.html"
    context = {'request': request,
               "title": "Hello World!!!",
               "now_time_utc": now_time_utc,
               "now_time": now_time,
               "access_token": access_token,
               "refresh_token": refresh_token,
               "csrf_token": csrf_token,
               'current_user': current_user,
               'admin': admin}
    return templates.TemplateResponse(template, context)


@router.get("/server", response_class=HTMLResponse,
            summary="서버 개발 페이지", description="여기는 서버 셋팅관련 페이지입니다.")
async def related_server(request: Request,
                   current_user: Optional[User] = Depends(get_optional_current_user)):

    template = "common/server.html"
    context = {'request': request,
               'current_user': current_user}
    return templates.TemplateResponse(template, context)


@router.get("/docker", response_class=HTMLResponse,
            summary="도커 개발 페이지", description="여기는 우분투 서버에 도커 셋팅관련 페이지입니다.")
async def related_server(request: Request,
                   current_user: Optional[User] = Depends(get_optional_current_user)):

    template = "common/docker.html"
    context = {'request': request,
               'current_user': current_user}
    return templates.TemplateResponse(template, context)


SWAGGER_JS = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"
SWAGGER_CSS = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"
SWAGGER_FAV = "https://fastapi.tiangolo.com/img/favicon.png"
COOKIE_NAME = "csrf_token"
HEADER_NAME = "X-CSRF-Token"


@router.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """
    csrf_token을 header에 추가하는 커스텀 Swagger UI 페이지를 반환합니다.
    """
    from main import app
    openapi_url = app.openapi_url or "/openapi.json"
    html = f"""<!doctype html>
                <html>
                <head>
                  <meta charset="utf-8" />
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <title>Docs - Swagger Custom UI</title>
                  <link rel="stylesheet" href="{SWAGGER_CSS}" />
                  <link rel="icon" type="image/png" href="{SWAGGER_FAV}" />
                  <style>
                    html {{ box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }}
                    *, *:before, *:after {{ box-sizing: inherit; }}
                    body {{ margin:0; background: #fafafa; }}
                  </style>
                </head>
                <body>
                  <div id="swagger-ui"></div>
                
                  <script src="{SWAGGER_JS}"></script>
                  <script>
                  window.onload = function() {{
                    // 쿠키에서 값 읽는 유틸 (안정적인 방법)
                    function getCookie(name) {{
                      const m = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
                      return m ? decodeURIComponent(m[2]) : null;
                    }}
                
                    // Swagger UI 초기화
                    const ui = SwaggerUIBundle({{
                      url: "{openapi_url}",
                      dom_id: '#swagger-ui',
                      deepLinking: true,
                      presets: [SwaggerUIBundle.presets.apis],
                      layout: "BaseLayout",
                
                      // requestInterceptor - 모든 요청이 전송되기 전에 호출됩니다.
                      requestInterceptor: function (req) {{
                        try {{
                          // 안전한 메서드에는 CSRF를 추가하지 않습니다.
                          const safeMethods = ['GET','HEAD','OPTIONS','TRACE'];
                          if (!safeMethods.includes((req.method || '').toUpperCase())) {{
                            const csrf = getCookie("{COOKIE_NAME}");
                            if (csrf) {{
                              // 헤더 추가 (대소문자 무관)
                              req.headers["{HEADER_NAME}"] = csrf;
                            }}
                            // 쿠키 전송이 필요하면 credentials 설정 (CORS 허용 필요)
                            // 'include' 는 cross-site에서도 쿠키를 전송합니다. same-origin이면 'same-origin' 사용 가능.
                            req.credentials = 'include';
                          }}
                        }} catch (e) {{
                          console.warn('requestInterceptor error:', e);
                        }}
                        return req;
                      }},
                    }});
                
                    window.ui = ui;
                  }};
                  </script>
                </body>
                </html>"""
    return HTMLResponse(html)
