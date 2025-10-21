from fastapi import status, UploadFile, Depends, APIRouter, Body, File, HTTPException

from typing import List

from app.core.settings import ARTICLE_QUILLS_USER_IMG_UPLOAD_DIR, ARTICLE_QUILLS_USER_VIDEO_UPLOAD_DIR
from app.dependencies.auth import get_current_user
from app.models import User
from app.utils.commons import file_write_return_url
from app.utils.quills import redis_rem, redis_add

router = APIRouter()

@router.post("/upload_image")
async def quill_upload_image(quillsimage: UploadFile,
                             current_user: User = Depends(get_current_user)):
    try:
        upload_dir = f'{ARTICLE_QUILLS_USER_IMG_UPLOAD_DIR}'+'/'+f'{current_user.id}'+'/'
        url = await file_write_return_url(upload_dir, current_user, quillsimage, "app",_type="image")
        return {"url": url}

    except Exception as e:
        print("upload_image error:::", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Quill 이미지 파일이 제대로 Upload되지 않았습니다. ")

###############################################################################################################
@router.post("/upload_video")
async def quill_upload_video(quillsvideo: UploadFile = File(...),
                             current_user: User = Depends(get_current_user)):
    try:
        upload_dir = f'{ARTICLE_QUILLS_USER_VIDEO_UPLOAD_DIR}'+'/'+f'{current_user.id}'+'/'
        url = await file_write_return_url(upload_dir, current_user, quillsvideo, "app", _type="video")
        return {"url": url}
    except Exception as e:
        print("upload_video error:::", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Quill 동영상 파일이 제대로 Upload되지 않았습니다. ")


#############################################################################################################
@router.post("/mark_delete_images/{mark_id}")
async def mark_delete_images(mark_id: int, srcs: List[str] = Body(...)):
    print("mark_delete_images:::mark_id:::", mark_id)
    key = f"delete_image_candidates:{mark_id}"
    added_count = await redis_add(srcs, key)
    return {"marked": srcs, "added": added_count}


@router.post("/unmark_delete_images/{mark_id}")
async def unmark_delete_images(mark_id: int, srcs: List[str]):
    print("unmark_delete_images:::mark_id:::", mark_id)
    key = f"delete_image_candidates:{mark_id}"
    removed_count = await redis_rem(srcs, key)
    return {"unmarked": srcs, "removed": removed_count}

###############################################################################################################
@router.post("/mark_delete_videos/{mark_id}")
async def mark_delete_videos(mark_id: int, srcs: List[str] = Body(...)):
    print("mark_delete_videos:::mark_id:::", mark_id)
    key = f"delete_video_candidates:{mark_id}"
    added_count = await redis_add(srcs, key)

    return {"marked": srcs, "added": added_count}


@router.post("/unmark_delete_videos/{mark_id}")
async def unmark_delete_videos(mark_id: int, srcs: List[str]):
    print("unmark_delete_videos:::mark_id:::", mark_id)
    key = f"delete_video_candidates:{mark_id}"
    removed_count = await redis_rem(srcs, key)

    return {"unmarked": srcs, "removed": removed_count}


