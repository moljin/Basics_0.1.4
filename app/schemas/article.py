from datetime import datetime
from pydantic import BaseModel, ConfigDict


class ArticleIn(BaseModel):
    title: str
    content: str

class ArticleUpdate(BaseModel):
    title: str | None = None
    content: str | None = None

class ArticleOut(BaseModel):
    id: int
    author_id: int
    title: str | None
    content: str | None
    img_path: str | None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)