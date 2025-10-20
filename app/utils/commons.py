import datetime
import random
import shutil
import uuid

from email_validator import validate_email, EmailNotValidError
from fastapi import status, UploadFile, HTTPException
import os
import aiofiles as aio
from starlette.concurrency import run_in_threadpool

from app.core.settings import STATIC_DIR
from app.models import User

async def random_string(length:int, _type:str):
    if _type == "full":
        string_pool = "0za1qw2sc3de4rf5vb6gt7yh8nm9juiklop"
    elif _type == "string":
        string_pool = "abcdefghijklmnopqrstuvwxyz"
    else:
        string_pool = "0123456789"
    result = random.choices(string_pool, k=length)
    seperator = ""
    return seperator.join(result)

async def file_renaming(username:str, ext:str):
    date = datetime.datetime.now().strftime("%Y%m%d_%H%M_%S%f")
    random_str = await random_string(8, "full")
    new_filename = f"{username}_{date}{random_str}"
    return f"{new_filename}{ext}"

async def upload_single_image(path:str, user: User, imagefile: UploadFile = None):
    try:
        print("upload_single_image path: ", path)
        upload_dir = f"{path}\\{user.id}\\"
        url = await file_write_return_url(upload_dir, user, imagefile, "static", _type="image")
        return url

    except Exception as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="이미지 파일이 제대로 Upload되지 않았습니다. ")


async def file_write_return_url(upload_dir: str, user: User, file: UploadFile, _dir: str, _type: str):
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)

    filename_only, ext = os.path.splitext(file.filename)
    if len(file.filename.strip()) > 0 and len(filename_only) > 0:
        upload_filename = await file_renaming(user.username, ext)
        file_path = upload_dir + upload_filename

        async with aio.open(file_path, "wb") as outfile:
            if _type == "image":
                _CHUNK = 1024 * 1024
                while True:
                    chunk = await file.read(_CHUNK)
                    if not chunk:
                        break
                    await outfile.write(chunk)
            elif _type == "video":
                # await outfile.write(await file.read())
                # 대용량 업로드: 청크 단위로 읽어서 바로 쓰기 (메모리 사용 최소화)
                _CHUNK = 8 * 1024 * 1024  # 8MB
                while True:
                    chunk = await file.read(_CHUNK)
                    if not chunk:
                        break
                    await outfile.write(chunk)
                await outfile.flush()

        url = file_path.split(_dir)[1]
        return url
    else:
        return None


"""# 존재 체크-후-삭제 사이에 경쟁 상태가 생길 수 있슴, 
권장: 존재 여부 체크 없이 바로 삭제 시도 (경쟁 상태 방지)"""
async def remove_file_path(path:str): # 파일 삭제
    try:
        await run_in_threadpool(os.remove, path)
    except FileNotFoundError:
        pass  # 이미 없으면 무시


async def remove_empty_dir(_dir:str): # 빈 폴더 삭제
    try:
        await run_in_threadpool(os.rmdir, _dir)  # 비어 있을 때만 성공
    except FileNotFoundError:
        pass  # 이미 사라졌다면 무시
    except OSError as e:
        print("비어있지 않거나 잠겨 있는 경우: ", e)
        pass  # 비어있지 않거나 잠겨 있으면 무시(필요 시 로깅)


async def remove_dir_with_files(_dir:str): # 파일을 포함하여 폴더 삭제
    try:
        await run_in_threadpool(shutil.rmtree, _dir)
        # 이미지 저장 디렉토리 및 파일을 삭제, ignore_errors, onerror 파라미터 넣지 않아도 작동한다.
    except FileNotFoundError:
        pass


async def old_image_remove(filename:str, path:str):
    try:
        filename_only, ext = os.path.splitext(filename)
        if len(filename.strip()) > 0 and len(filename_only) > 0 and path is not None:
            # old_image_path = f'{APP_DIR}{path}' # \\없어도 된다. url 맨 앞에 \\ 있다.
            old_image_path = f'{STATIC_DIR}\\{path}'
            await remove_file_path(old_image_path)

    except Exception as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="이미지 파일이 제대로 Upload되지 않았습니다. ")


# ----------------- 유틸: 이메일 유효성 체크 -----------------
def is_valid_email(email: str) -> bool:
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False


def create_orm_id(objs_all, user):
    """비동기 함수로 바꿔야 하나???"""
    try:
        unique_num = str(objs_all[0].id + 1)  # 고유해지지만, model.id와 일치하지는 않는다. 삭제된 놈들이 있으면...
        print("unique_num:::::::::::::: ", unique_num,)
    except Exception as e:
        print("c_orm_id Exception error::::::::: 임의로 1로... 할당  ", e)
        unique_num = str(1) # obj가 첫번째 것인 경우: 임의로 1로... 할당
    _random_string = str(uuid.uuid4())
    username = user.username
    orm_id = unique_num + ":" + username + "_" + _random_string
    return orm_id


