from pydantic import EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

from app.core.database import get_db
from app.models.user import User
from app.schemas.user import UserIn, UserUpdate, UserPasswordUpdate
from app.utils.user import get_password_hash


class UserService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_user(self, user_in: UserIn, img_path: str = None):
        # CPU 바운드 해시는 스레드풀에서 실행하여 이벤트 루프 블로킹 방지: AI Chat
        hashed_password = await get_password_hash(user_in.password)
        # hashed_password = await run_in_threadpool(get_password_hash, user_in.password)
        db_user = User(
            email=str(user_in.email),
            username=user_in.username,
            password=hashed_password,
            img_path=img_path
        )

        self.db.add(db_user)
        await self.db.commit()
        await self.db.refresh(db_user)

        return db_user

    async def get_user_by_email(self, email: str):
        query = (select(User).where(User.email == email))
        result = await self.db.execute(query)  # await 추가
        return result.scalar_one_or_none()

    async def get_user_by_username(self, username: str):
        query = (select(User).where(User.username == username))
        result = await self.db.execute(query)  # await 추가
        return result.scalar_one_or_none()

    async def get_users(self):
        query = (select(User).order_by(User.created_at.desc()))
        result = await self.db.execute(query)
        users = result.scalars().all()
        return users

    async def get_user_by_id(self, user_id: int):
        query = (select(User).where(User.id == user_id))
        result = await self.db.execute(query)
        user = result.scalar_one_or_none()
        return user

    async def update_user(self, user_id: int, user_update: UserUpdate):
        user = await self.get_user_by_id(user_id)
        if user is None:
            return None
        if user_update.username is not None:
            user.username = user_update.username
        if user_update.email is not None:
            user.email = str(user_update.email)
        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def update_email(self, old_email: EmailStr, email: EmailStr):
        user = await self.get_user_by_email(str(old_email))
        print("user", user)
        if user is None:
            return None
        user.email = str(email)
        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def update_password(self, user_id: int, password_update: UserPasswordUpdate):
        user = await self.get_user_by_id(user_id)
        if user is None:
            return None
        hashed_password = await get_password_hash(password_update.password)
        user.password = hashed_password
        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def user_image_update(self, user_id: int, img_path: str):
        user = await self.get_user_by_id(user_id)
        if user is None:
            return None
        user.img_path = img_path
        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def delete_user(self, user_id: int):
        user = await self.get_user_by_id(user_id)
        if user is None:
            return False
        await self.db.delete(user)
        await self.db.commit()
        return True

def get_user_service(db: AsyncSession = Depends(get_db)) -> 'UserService':
    return UserService(db)