from datetime import datetime

from fastapi import APIRouter, HTTPException, status
from fastapi.params import Depends

from pydantic import BaseModel, Field, EmailStr, ConfigDict
from sqlalchemy import Integer, String, DateTime, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column


from app.core.database import Base, get_db


class TestItemBase(BaseModel):
    name: str = Field(..., pattern=r".+", min_length=2)

class TestItemIn(TestItemBase):
    email: EmailStr = Field(...,  examples=["string@example.com"])

class TestItemOut(TestItemBase):
    id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class TestItem(Base):
    __tablename__ = "test_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(20), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now())


router = APIRouter()

@router.post("/",response_model=TestItemOut,
             summary="테스트 POST", description="테스트 등록",
             responses={ 409: {
                 "description": "중복된 이메일로 등록 시도",
                 "content": {"application/json": {"example": {"detail": "이미 존재하는 이메일입니다."}}}
             }})
async def test(item_in: TestItemIn, db: AsyncSession = Depends(get_db)):
    name = item_in.name
    query = (select(TestItem).where(TestItem.name == name))
    result = await db.execute(query)  # await 추가
    item = result.scalar_one_or_none()
    if item:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="이미 존재하는 사용자 이름입니다."
        )

    email = item_in.email
    query = (select(TestItem).where(TestItem.email == email))
    _result = await db.execute(query)  # await 추가
    _item = _result.scalar_one_or_none()
    if _item:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="이미 존재하는 이메일입니다."
        )

    db_item = TestItem(
        name=item_in.name,
        email=str(item_in.email)
    )

    db.add(db_item)
    await db.commit()
    await db.refresh(db_item)

    return db_item

