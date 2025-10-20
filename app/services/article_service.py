from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Dict, List, Optional, Tuple, Literal, Sequence

from fastapi import Depends, HTTPException, status
from sqlalchemy import and_, func, select, tuple_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models import User, Article
from app.schemas.article import ArticleIn, ArticleUpdate


class KeysetDirection(StrEnum):
    NEXT = "next"
    PREV = "prev"


@dataclass
class CursorPage:
    items: list[Article]
    has_next: bool
    has_prev: bool
    next_cursor: Optional[str]
    prev_cursor: Optional[str]


def _encode_cursor(ts_iso: str, id_: int) -> str:
    payload = {"ts": ts_iso, "id": id_}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(token: str) -> Tuple[str, int]:
    # URL-safe base64 패딩 보정
    padding = "=" * ((4 - len(token) % 4) % 4)
    raw = base64.urlsafe_b64decode((token + padding).encode("ascii"))
    obj = json.loads(raw.decode("utf-8"))
    return obj["ts"], int(obj["id"])


def _row_to_cursor(row: Article) -> Optional[str]:
    if not row:
        return None
    # created_at은 UTC ISO 문자열로 저장
    ts_iso = row.created_at.isoformat()
    return _encode_cursor(ts_iso, row.id)


class ArticleService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_article(self, article_in: ArticleIn, user: User, img_path: str = None):
        create_article = Article(**article_in.model_dump())
        author_id = user.id
        create_article.author_id = author_id
        create_article.img_path = img_path

        self.db.add(create_article)
        await self.db.commit()
        await self.db.refresh(create_article)

        return create_article


    async def get_articles(self):
        query = (select(Article).order_by(Article.created_at.desc()))
        result = await self.db.execute(query)
        created_desc_articles = result.scalars().all()
        return created_desc_articles


    async def get_article(self, article_id: int):
        query = (select(Article).where(Article.id == article_id))
        result = await self.db.execute(query)
        article = result.scalar_one_or_none()
        return article


    async def update_article(self, article_id: int, article_update: ArticleUpdate, user: User, img_path: str = None):
        article = await self.get_article(article_id)
        if article is None:
            return None
        if article.author_id != user.id:
            return False

        if img_path is not None:
            article.img_path = img_path
        if article_update.title is not None:
            article.title = article_update.title
        if article_update.content is not None:
            article.content = article_update.content

        await self.db.commit()
        await self.db.refresh(article)
        return article


    async def delete_article(self, article_id: int, user: User):
        article = await self.get_article(article_id)
        if article is None:
            return None
        if article.author_id != user.id:
            return False
        await self.db.delete(article)
        await self.db.commit()
        return True

    # Pagination
    async def count_articles(self) -> int:
        q = select(func.count(Article.id))
        total = await self.db.scalar(q)
        return int(total or 0)

    async def list_articles_offset(
            self, page: int, size: int
    ) -> tuple[list[Article], int]:
        total = await self.count_articles()
        if total == 0:
            return [], 0

        start = (page - 1) * size
        q = (
            select(Article)
            .options(
                # author 관계가 있다면 미리 로드
                selectinload(getattr(Article, "author", None))  # 관계 없으면 무시
            )
            .order_by(Article.created_at.desc(), Article.id.desc())
            .offset(start)
            .limit(size)
        )
        result = await self.db.execute(q)
        items: Sequence[Article] = result.scalars().all()
        return list(items), total

    async def list_articles_keyset(
            self,
            size: int,
            cursor: Optional[str] = None,
            direction: KeysetDirection = KeysetDirection.NEXT,
    ) -> CursorPage:
        # 기본 정렬: created_at DESC, id DESC
        order_main = [Article.created_at.desc(), Article.id.desc()]
        limit = size + 1  # 다음/이전 페이지 존재 확인용

        cond = None
        if cursor:
            ts_iso, cid = _decode_cursor(cursor)
            # 문자열 ISO를 DB에서 바로 비교해도 되지만, 보통 DateTime 컬럼이면 파싱은 DB가 수행
            # created_at == ts AND id < cid  (NEXT, 내림차순 탐색)
            if direction == KeysetDirection.NEXT:
                cond = or_(
                    Article.created_at < ts_iso,
                    and_(Article.created_at == ts_iso, Article.id < cid),
                )
                q = (
                    select(Article)
                    .options(selectinload(getattr(Article, "author", None)))
                    .where(cond)
                    .order_by(*order_main)
                    .limit(limit)
                )
            else:
                # PREV: (created_at > ts) OR (created_at == ts AND id > cid)
                cond = or_(
                    Article.created_at > ts_iso,
                    and_(Article.created_at == ts_iso, Article.id > cid),
                )
                # 이전 페이지는 오름차순으로 가져온 다음 메모리에서 뒤집으면 안정적
                q = (
                    select(Article)
                    .options(selectinload(getattr(Article, "author", None)))
                    .where(cond)
                    .order_by(Article.created_at.asc(), Article.id.asc())
                    .limit(limit)
                )
        else:
            # 커서가 없으면 최초 페이지(NEXT)로 가정
            if direction == KeysetDirection.NEXT:
                q = (
                    select(Article)
                    .options(selectinload(getattr(Article, "author", None)))
                    .order_by(*order_main)
                    .limit(limit)
                )
            else:
                # PREV인데 커서 없음: 데이터 가장 뒤에서부터 시작하고 싶다면 별도 정책 필요
                # 여기서는 NEXT 시작과 동일 취급
                q = (
                    select(Article)
                    .options(selectinload(getattr(Article, "author", None)))
                    .order_by(*order_main)
                    .limit(limit)
                )

        result = await self.db.execute(q)
        rows: list[Article] = list(result.scalars().all())

        reversed_for_prev = False
        if direction == KeysetDirection.PREV and rows:
            # PREV의 경우 오름차순으로 뽑았으니 화면 출력용으로 다시 내림차순 정렬
            rows.reverse()
            reversed_for_prev = True

        # has_next/has_prev 판별
        has_more = len(rows) > size
        if has_more:
            # 오버패치 제거
            if direction == KeysetDirection.NEXT:
                rows = rows[:size]
            else:
                # PREV: 뒤집기 전/후 관계에 따라 동일하게 first N개 취함
                rows = rows[:size]

        # 커서 계산
        first_row = rows[0] if rows else None
        last_row = rows[-1] if rows else None

        next_cursor = _row_to_cursor(last_row) if rows else None
        prev_cursor = _row_to_cursor(first_row) if rows else None

        # PREV 탐색에서 has_next/has_prev의 의미를 화면 기준으로 매핑
        # 화면 기준: 내림차순으로 볼 때 왼쪽(Prev)은 더 최신, 오른쪽(Next)은 더 과거
        if direction == KeysetDirection.NEXT:
            has_next = has_more
            has_prev = cursor is not None  # 커서가 있으면 되돌아갈 여지 있음
        else:
            # PREV로 읽어온 경우: 이전(좌)로 더 갈 수 있나?
            has_prev = has_more
            has_next = cursor is not None

        return CursorPage(
            items=rows,
            has_next=bool(has_next),
            has_prev=bool(has_prev),
            next_cursor=next_cursor,
            prev_cursor=prev_cursor,
        )


def get_article_service(db: AsyncSession = Depends(get_db)) -> 'ArticleService':
    return ArticleService(db)