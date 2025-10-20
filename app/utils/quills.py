import re
from typing import Set
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis_config import redis_client
from app.core.settings import APP_DIR
from app.models import Article
from app.utils.commons import remove_file_path, remove_empty_dir


# Quills 유틸: HTML에서 이미지 src 추출
IMG_SRC_PATTERN = re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
def extract_img_srcs(html: str) -> Set[str]:
    print("extract_IMG_srcs:::html:::", html)
    if not html:
        return set()
    print("set(IMG_SRC_PATTERN.findall(html)", set(IMG_SRC_PATTERN.findall(html)))
    return set(IMG_SRC_PATTERN.findall(html))


VIDEO_SRC_PATTERN = re.compile(
    r'<(?:source|video|iframe)\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL
)
def extract_video_srcs(html: str) -> Set[str]:
    print("extract_video_srcs:::html:::", html)
    if not html:
        return set()
    print("set(VIDEO_SRC_PATTERN.findall(html)", set(VIDEO_SRC_PATTERN.findall(html)))
    return set(VIDEO_SRC_PATTERN.findall(html))


async def redis_add(srcs: list, key: str):
    # 안전 처리: None/빈 문자열 제거 + 문자열로 캐스팅
    members = [str(src) for src in srcs if src]
    if not members:
        return {"marked": [], "added": 0}
    added_count = await redis_client.sadd(key, *members)
    print("marked: ", srcs, "added_count:::", added_count)
    return added_count


async def redis_rem(srcs: list, key: str):
    # 안전 처리: None/빈 문자열 제거 + 문자열로 캐스팅
    members = [str(src) for src in srcs if src]
    if not members:
        return {"marked": [], "added": 0}
    removed_count = await redis_client.srem(key, *members)
    print("marked: ", srcs, "removed_count:::", removed_count)
    return removed_count


async def redis_delete_candidates(temp_key: str, real_key: str):
    if await redis_client.exists(temp_key):
        print("redis_client.exists(temp_img_key) 이미지가 있으면 여기로 들어온다.",
              await redis_client.exists(temp_key))
        for url in await redis_client.smembers(temp_key):
            await redis_client.sadd(real_key, url)
        await redis_client.delete(temp_key)


# --- Helpers ---
###############################################################################################################
async def remove_delete_candidates(delete_candidates: set, _id: int, currents: set, db: AsyncSession, key: str) -> None:
    for url in delete_candidates:
        print("delete_candidates url: ", url)
        if url not in currents and not await is_media_used_elsewhere(_id, url, db):
            quill_path = f'{APP_DIR}{url}'  # \\없어도 된다. url 맨 앞에 \\ 있다.
            await remove_file_path(quill_path)
            await redis_client.srem(key, *url)


async def cleanup_unused_images(article_id: int, current_content: str, db: AsyncSession) -> None:
    """저장 시, Redis 후보 중 더 이상 쓰이지 않는 이미지를 삭제"""
    current_imgs = extract_img_srcs(current_content)
    print("current_imgs: ", current_imgs)
    key = f"delete_image_candidates:{article_id}"
    print('key=f"delete_image_candidates:{article_id}": ', key)
    delete_candidates = await redis_client.smembers(key)
    print("delete_image_candidates: ", delete_candidates)

    await remove_delete_candidates(delete_candidates, article_id, current_imgs, db, key)
    # for url in delete_candidates:
    #     print("delete_image_candidates url: ", url)
    #     if url not in current_imgs and not await is_image_used_elsewhere(article_id, url, db):
    #         quill_img_path = f'{APP_DIR}{url}'  # \\없어도 된다. url 맨 앞에 \\ 있다.
    #         await remove_file_path(quill_img_path)
    #         await redis_client.srem(key, *url)


###############################################################################################################
async def cleanup_unused_videos(article_id: int, current_content: str, db: AsyncSession) -> None:
    """저장 시, Redis 후보 중 더 이상 쓰이지 않는 이미지를 삭제"""
    current_videos = extract_video_srcs(current_content)
    print("current_videos: ", current_videos)
    key = f"delete_video_candidates:{article_id}"
    print('key=f"delete_video_candidates:{article_id}": ', key)
    delete_candidates = await redis_client.smembers(key)
    print("delete_video_candidates: ", delete_candidates)

    await remove_delete_candidates(delete_candidates, article_id, current_videos, db, key)
    # for url in delete_candidates:
    #     print("delete_video_candidates url: ", url)
    #     if url not in current_videos and not await is_image_used_elsewhere(article_id, url, db):
    #         quill_video_path = f'{APP_DIR}{url}'  # \\없어도 된다. url 맨 앞에 \\ 있다.
    #         await remove_file_path(quill_video_path)
    #         await redis_client.srem(key, *url)


async def remove_content_medias(content_medias: set, _id: int, _dir: str, current_user_id: int, db: AsyncSession, key: str) -> None:
    candidate_medias = set(await redis_client.smembers(key))

    all_medias = content_medias | candidate_medias  # 합쳐서 삭제 후보

    for src in all_medias:  # 실제 삭제 여부 확인
        if not await is_media_used_elsewhere(_id, src, db):
            quill_path = f'{APP_DIR}{src}'  # \\없어도 된다. src 맨 앞에 \\ 있다.
            await remove_file_path(quill_path)

    media_dir = f'{_dir}\\{current_user_id}'
    await remove_empty_dir(media_dir)  # 삭제후 폴더가 비어 있으면 폴더도 삭제


async def object_delete_with_image_or_video(_id: int, html: str, _dir: str, current_user_id: int, db: AsyncSession, key: str) -> None:
    """object를 삭제할 때, quill editor의 content중에서 이미지와 동영상 파일을 삭제 및 정리"""
    if key == f"delete_image_candidates:{_id}":
        content_imgs = extract_img_srcs(html)
        if content_imgs:
            await remove_content_medias(content_imgs, _id, _dir, current_user_id, db, key)
    elif key == f"delete_video_candidates:{_id}":
        content_videos = extract_video_srcs(html)
        if content_videos:
            await remove_content_medias(content_videos, _id, _dir, current_user_id, db, key)
    else:
        raise ValueError("Invalid key: %s" % key)


async def is_media_used_elsewhere(article_id: int, src: str, db: AsyncSession) -> bool:
    """해당 post_id 외 다른 글에서 src 이미지가 사용 중인지 검사"""
    result = await db.execute(select(Article).where(Article.id != article_id))
    other_articles = result.scalars().all()

    for article in other_articles:
        if src in article.content:
            return True
    return False


content_text = "default"
"""이미지만 업로드 할때 내용이 있는것으로 체크되게 하기 위해 값을 주었다.
여기를 빈값으로 해버리면, 이미지업로드하고, if len(img_tags) == 0:를 bypass 해서 지나갈때, 빈값으로 인식되어 버린다."""

def editor_empty_check(content):
    print(content)
    global content_text
    import lxml.html
    html = lxml.html.fromstring(content)
    img_tags = html.xpath("//img")
    print("editor_empty_check:::len(img_tags):::", len(img_tags))
    if len(img_tags) == 0:
        """아무것도 입력하지 않거나, 텍스트만 입력하면 여기를 지나가서 텍스트 유무를 가려낸다.
        이미지만 올리면 여기를 bypass 해서, 지나가지 않는다."""
        html_tag_cleaner = re.compile('<.*?>|&([a-z0-9]+|#[0-9]{1,6}|#x[0-9a-f]{1,6});')
        content_text = re.sub(html_tag_cleaner, '', content)
        # html string 에서 태그 제거 content text::: https://calssess.tistory.com/88
    return content_text
    # content_text 글로벌 변수를 빈값 ""로 하지 않고, "default"라고 할당했음에 유의