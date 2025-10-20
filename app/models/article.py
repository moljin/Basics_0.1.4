from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, func, Text
from sqlalchemy.orm import relationship, Mapped, mapped_column, backref

from app.core.database import Base


class Article(Base):
    __tablename__ = "articles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(100), index=True)
    img_path: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # 외래키를 사용할 때, 제약 조건에 name을 ForeignKey 안에 ForeignKey("users.id", name="fk_author_id") 이렇게 넣어라.
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", name="fk_author_id", ondelete='CASCADE'), nullable=False)
    # author_id가 nullable=True 이므로 Optional["User"]가 일관됩니다.
    author: Mapped["User"] = relationship("User", backref=backref("article_user_set",
                                                                  lazy="selectin",
                                                                  cascade="all, delete-orphan",
                                                                  passive_deletes=True), lazy="selectin")


def __repr__(self):
        return f"<Article(id={self.id}, title='{self.title}', author_id={self.author_id}, created_at={self.created_at})>"

"""
현재 템플릿 단에서 `<div class="uk-text-right">{{ article.author }}</div>` 여기에서
sqlalchemy.exc.StatementError: (sqlalchemy.exc.MissingGreenlet) greenlet_spawn has not been called; can't call await_only() here. Was IO attempted in an unexpected place?
[SQL: SELECT users.id AS users_id, users.username AS users_username, users.email AS users_email, users.password AS users_password, users.created_at AS users_created_at
FROM users
WHERE users.id = %s]
[parameters: [{'pk_1': 21}]]
에러가 발생한다. 해결방법은? AI Chat

해당 에러는 템플릿에서 article.author에 접근하는 순간, SQLAlchemy가 “지연 로딩(lazy load)”을 수행하려고 하며, 
비동기 드라이버(aiomysql)를 쓰는 환경에서 Jinja2의 동기 렌더링 컨텍스트와 충돌해서 발생합니다. 
즉, 템플릿 렌더링 중에 DB I/O가 필요해져서 MissingGreenlet가 납니다.

1. (선택) 모델 관계 기본 전략을 selectin으로 설정
- 매 쿼리마다 options를 달기 어렵다면, 관계 정의에서 lazy="selectin"으로 설정해 지연 로딩 대신 배치 로딩을 기본으로 사용합니다.
class Article(Base):
    # ...
    author = relationship("User", back_populates="articles", lazy="selectin")

"""