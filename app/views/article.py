import math
from typing import Optional

from fastapi import Request, APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import HTMLResponse, Response,JSONResponse

from app.core.settings import templates, ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME
from app.dependencies.auth import get_current_user, get_optional_current_user
from app.models import User
from app.services.article_service import get_article_service, ArticleService, KeysetDirection

router = APIRouter()

DEEP_PAGE_THRESHOLD = 100  # 얕은 범위까지만 오프셋, 이후는 커서 모드 권장

@router.get("")
async def get_all_articles(
    request: Request,
    article_service: ArticleService = Depends(get_article_service),
    current_user: Optional[User] = Depends(get_optional_current_user),
    # 오프셋용
    page: int = Query(1, ge=1, description="현재 페이지 (1부터 시작)"),
    size: int = Query(10, ge=1, le=100, description="페이지 당 항목 수"),
    # 커서용
    mode: str = Query("auto", pattern="^(auto|offset|cursor)$"),
    cursor: Optional[str] = Query(None, description="커서 토큰"),
    _dir: str = Query("next", pattern="^(next|prev)$"),
    approx_page: Optional[int] = Query(None, description="커서 모드에서의 대략적 페이지"),
):
    # 공통: 전체 개수
    total_count = await article_service.count_articles()
    if total_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="등록된 게시물이 없습니다."
        )
    total_pages = max(1, math.ceil(total_count / size))

    # 전략 결정
    # using_cursor = False
    direction = KeysetDirection.NEXT if _dir == "next" else KeysetDirection.PREV

    if mode == "cursor" or (mode == "auto" and cursor is not None):
        using_cursor = True
    elif mode == "offset":
        using_cursor = False
    else:
        # auto: cursor가 없고, 얕은 페이지면 offset, 깊으면 offset이지만 다음 링크에서 cursor 전환
        using_cursor = False

    # 1) 커서 모드
    if using_cursor:
        # approx_page가 없으면 임계 지점 또는 1로 초기화
        if approx_page is None:
            # 임계 이상에서 커서 시작했다고 가정
            approx_page = min(max(page, 1), total_pages)
            if approx_page < DEEP_PAGE_THRESHOLD:
                approx_page = DEEP_PAGE_THRESHOLD

        cpage = await article_service.list_articles_keyset(
            size=size, cursor=cursor, direction=direction
        )

        all_articles = cpage.items

        # Prev/Next 링크 구성
        # - 커서 모드에서 Prev를 누를 때 approx_page-1
        # - approx_page-1이 임계 이하가 되면 Prev를 오프셋 링크로 복귀
        has_prev = cpage.has_prev
        has_next = cpage.has_next

        prev_href = None
        next_href = None

        # Prev
        if has_prev:
            prev_approx = max(1, approx_page - 1)
            if prev_approx < DEEP_PAGE_THRESHOLD:
                # 오프셋으로 복귀
                prev_href = f"?page={DEEP_PAGE_THRESHOLD - 1}&size={size}&mode=offset"
            else:
                prev_href = (
                    f"?mode=cursor&size={size}&cursor={cpage.prev_cursor}"
                    f"&dir=prev&approx_page={prev_approx}"
                )

        # Next
        if has_next:
            next_approx = min(total_pages, approx_page + 1)
            next_href = (
                f"?mode=cursor&size={size}&cursor={cpage.next_cursor}"
                f"&dir=next&approx_page={next_approx}"
            )

        # 페이지네이션 컨텍스트(커서 모드)
        pagination = {
            "mode": "cursor",
            "size": size,
            "total_count": total_count,
            "total_pages": total_pages,
            "approx_page": approx_page,
            "has_prev": has_prev,
            "has_next": has_next,
            "prev_href": prev_href,
            "next_href": next_href,
        }

        context = {
            "all_articles": all_articles,
            "current_user": current_user,
            "pagination": pagination,
        }

        return templates.TemplateResponse(
            request=request, name="articles/articles.html", context=context
        )

    # 2) 오프셋 모드
    # 페이지 보정
    if page > total_pages:
        page = total_pages
    if page < 1:
        page = 1

    items, _ = await article_service.list_articles_offset(page=page, size=size)
    if not items:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="등록된 게시물이 없습니다."
        )

    # 기존 스타일의 숫자 페이지
    has_prev = page > 1
    has_next = page < total_pages

    # 임계 페이지에서 다음 클릭 시 커서 모드로 다리 놓기
    # 현재 페이지의 마지막 아이템으로 next_cursor 생성해서 next 링크로 사용
    next_href = None
    prev_href = None

    if has_prev:
        prev_href = f"?page={page - 1}&size={size}&mode=offset"

    if has_next:
        if page >= DEEP_PAGE_THRESHOLD:
            # 커서 모드로 전환: 현재 페이지 마지막 아이템 기준 next_cursor 생성
            # list_articles_offset에서 이미 items를 가져왔으므로 마지막으로 커서 생성
            from app.services.article_service import _row_to_cursor  # 내부 헬퍼 재사용
            bridge_cursor = _row_to_cursor(items[-1])
            next_href = (
                f"?mode=cursor&size={size}&cursor={bridge_cursor}"
                f"&dir=next&approx_page={min(total_pages, page + 1)}"
            )
        else:
            next_href = f"?page={page + 1}&size={size}&mode=offset"

    # 현재 페이지 기준 좌우 2개씩 번호 노출
    page_range = list(range(max(1, page - 2), min(total_pages, page + 2) + 1))

    pagination = {
        "mode": "offset",
        "page": page,
        "size": size,
        "total_count": total_count,
        "total_pages": total_pages,
        "has_prev": has_prev,
        "has_next": has_next,
        "prev_page": page - 1 if has_prev else None,
        "next_page": page + 1 if has_next else None,
        "prev_href": prev_href,
        "next_href": next_href,
        "page_range": page_range,
        "deep_page_threshold": DEEP_PAGE_THRESHOLD,
    }

    context = {
        "all_articles": items,
        "current_user": current_user,
        "pagination": pagination,
    }

    return templates.TemplateResponse(
        request=request, name="articles/articles.html", context=context
    )


'''
@router.get("/")
async def get_all_articles(request: Request,
                           article_service: ArticleService = Depends(get_article_service),
                           current_user: Optional[User] = Depends(get_optional_current_user),
                           page: int = Query(1, ge=1, description="현재 페이지 (1부터 시작)"),
                           size: int = Query(10, ge=1, le=100, description="페이지 당 항목 수"),
                           ):
    all_articles = await article_service.get_articles()
    total_count = len(all_articles) if all_articles else 0
    if total_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="등록된 게시물이 없습니다."
        )

    total_pages = max(1, math.ceil(total_count / size))
    if page > total_pages:
        page = total_pages  # 범위를 넘어가면 마지막 페이지로 보정

    start = (page - 1) * size
    end = start + size
    paged_articles = all_articles[start:end]

    context = {
        "all_articles": paged_articles,
        "current_user": current_user,
        "pagination": {
            "page": page,
            "size": size,
            "total_count": total_count,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1 if page > 1 else None,
            "next_page": page + 1 if page < total_pages else None,
            # 현재 페이지 기준 좌우 2개씩 번호 노출
            "page_range": list(range(max(1, page - 2), min(total_pages, page + 2) + 1)),
        },
    }

    return templates.TemplateResponse(
            request=request,
            name="articles/articles.html",
            context=context
        )
'''

@router.get("/article/create") # @router.get("/article/{article_id}"이것보다 위로 와야 한다. 라우트의 혼선 예방하기 위해...
async def create_article_ui(request: Request,
                            article_service: ArticleService = Depends(get_article_service),
                            current_user: Optional[User] = Depends(get_optional_current_user)):
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated: 로그인하지 않았습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    articles_all = await article_service.get_articles()

    context = {"current_user": current_user,
               "mark_id": 0} # mark_id 이미지 undo에서 사용된다.

    return templates.TemplateResponse(
        request=request,
        name="articles/update.html", # update.html 파일에 js와 form tag에 필요한 부분들 분기해서 적용
        context=context
    )


@router.get("/article/{article_id}", response_class=HTMLResponse,
            summary="게시글 상세 페이지 HTMLResponse", description="게시글 상세 페이지 templates.TemplateResponse")
async def get_article_by_id(request: Request, article_id: int,
                            article_service: ArticleService = Depends(get_article_service),
                            current_user: Optional[User] = Depends(get_optional_current_user)):
    # article_id = request.path_params['article_id']
    article = await article_service.get_article(article_id)
    if article is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="해당 게시글을 찾을 수 없습니다."
        )

    template = "articles/detail.html"
    context = {'request': request,
               "article": article,
               "current_user": current_user}
    return templates.TemplateResponse(template, context)


@router.get("/article/update/{article_id}", response_class=HTMLResponse,
            summary="게시글 수정 페이지 HTMLResponse", description="게시글 수정 페이지 templates.TemplateResponse")
async def article_update_ui(request: Request, response: Response,
                            article_id: int,
                            article_service: ArticleService = Depends(get_article_service),
                            current_user: User = Depends(get_current_user)):

    article = await article_service.get_article(article_id)
    if article is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="게시글을 찾을 수 없습니다."
        )
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated: 로그인하지 않았습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        user_id = current_user.id
        if user_id != article.author_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized: 접근 권한이 없습니다."
            )

    template = "articles/update.html"  # update.html 파일에 js와 form tag에 필요한 부분들 분기해서 적용
    context = {'request': request,
               "current_user": current_user,
               "article": article,
               "mark_id": 0}  # mark_id 이미지 undo에서 사용된다.
    return templates.TemplateResponse(template, context)
