from typing import Optional

from sqlalchemy import Integer, String, DateTime, func, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

STATUS = ('old', 'latest')


class LottoNum(Base):
    __tablename__ = 'lottos'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(20), unique=True, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=STATUS[1], nullable=False)
    latest_round_num: Mapped[str] = mapped_column(String(100), nullable=False)
    extract_num: Mapped[str] = mapped_column(String(100), nullable=False)
    lotto_num_list: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<LottoNum(id={self.id}, email='{self.title}')>"