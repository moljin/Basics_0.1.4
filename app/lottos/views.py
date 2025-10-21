import os
from typing import Optional
from urllib.parse import urlparse

from fastapi import Request, APIRouter, Depends, Form, HTTPException, status
from fastapi.responses import RedirectResponse
import random
import ast
import numpy as np
import pandas as pd

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.settings import templates, ADMINS
from app.dependencies.auth import get_optional_current_user, get_current_user, allow_usernames
from app.lottos.models import LottoNum, STATUS
from app.lottos.utils import extract_latest_round, extract_first_win_num, latest_lotto, extract_frequent_num, excell2lotto_list
from app.models import User
from app.utils.exc_handler import CustomErrorException
from app.utils.user import is_admin

router = APIRouter()


""" # 아래와 결과가 같다.
@router.get("/random")
async def random_lotto(request: Request,
                       num: str = None,
                       db: AsyncSession = Depends(get_db),
                       current_user: Optional[User] = Depends(get_optional_current_user)):

    old_latest = await latest_lotto(db)
    admin = False
    if current_user.username in ADMINS:
        admin = True
    context = {'current_user': current_user,
               'admin': admin}
    if old_latest:
        latest_round_num = old_latest.latest_round_num
        if num:
            if int(num) < 6:
                message = f"6이상의 숫자를 입력하세요! 우선 빈도에 관계없이 무작위로 추출했어요!"
                context_add = {"variable": sorted(random.sample(range(1, 46), 6)), 
                               "latest": int(latest_round_num), 
                               "message": message}
                context |= (context_add or {})
            elif int(num) >= 45:
                message = f"45이상은 빈도에 관계없이 무작위로 추출하는 것과 같아요!"
                context_add = {"variable": sorted(random.sample(range(1, 46), 6)), 
                               "latest": int(latest_round_num), 
                               "message": message }
                context |= (context_add or {})
            else:
                lotto_num_list = ast.literal_eval(old_latest.lotto_num_list)
                wanted_top_list, lotto_random_num = await extract_frequent_num(lotto_num_list, int(num))
                message = f"당첨 빈도가 높은 번호 {num}개중 6개를 무작위로 추출"
                context_add = {"input_num": num, 
                               "variable": lotto_random_num, 
                               "latest": int(latest_round_num), 
                               "message": message }
                context |= (context_add or {})
        if num:
            if int(num) < 6:
                return templates.TemplateResponse(
                    request=request,
                    name="lottos/lotto.html",
                    context=context
                )
            elif int(num) >= 45:
                return templates.TemplateResponse(
                    request=request,
                    name="lottos/lotto.html",
                    context=context
                )
            else:
                return templates.TemplateResponse(
                    request=request,
                    name="lottos/lotto.html",
                    context=context
                )

        message = f"당첨 빈도에 관계없이 6개의 숫자를 무작위로 추출"
        context_add = {"variable": sorted(random.sample(range(1, 46), 6)), 
                       "latest": int(latest_round_num), 
                       "message": message }
        context |= (context_add or {})
        return templates.TemplateResponse(
            request=request,
            name="lottos/lotto.html",
            context=context
        )
    else:
        message = f"당첨 빈도에 관계없이 6개의 숫자를 무작위로 추출"
        context_add = {"variable": sorted(random.sample(range(1, 46), 6)), 
                       "latest": "0000", 
                       "message": message }
        context |= (context_add or {})
        return templates.TemplateResponse(
            request=request,
            name="lottos/lotto.html",
            context=context
        )
"""


@router.get("/random")
async def random_lotto(request: Request,
                       num: str = None,
                       db: AsyncSession = Depends(get_db),
                       current_user: Optional[User] = Depends(get_optional_current_user)):

    old_latest = await latest_lotto(db)

    if old_latest:
        latest_round_num = old_latest.latest_round_num
        if num:
            if int(num) < 6:
                message = f"6이상의 숫자를 입력하세요! 우선 빈도에 관계없이 무작위로 추출했어요!"
                context = {"variable": sorted(random.sample(range(1, 46), 6)),
                           "latest": int(latest_round_num),
                           "message": message,
                           'current_user': current_user,
                           'admin': is_admin(current_user)}
                return templates.TemplateResponse(
                    request=request,
                    name="lottos/lotto.html",
                    context=context
                )
            elif int(num) >= 45:
                message = f"45이상은 빈도에 관계없이 무작위로 추출하는 것과 같아요!"
                context = {"variable": sorted(random.sample(range(1, 46), 6)),
                           "latest": int(latest_round_num),
                           "message": message,
                           'current_user': current_user,
                           'admin': is_admin(current_user)}
                return templates.TemplateResponse(
                    request=request,
                    name="lottos/lotto.html",
                    context=context
                )
            else:
                lotto_num_list = ast.literal_eval(old_latest.lotto_num_list)
                wanted_top_list, lotto_random_num = await extract_frequent_num(lotto_num_list, int(num))
                message = f"당첨 빈도가 높은 번호 {num}개중 6개를 무작위로 추출"
                context = {"input_num": num,
                           "variable": lotto_random_num,
                           "latest": int(latest_round_num),
                           "message": message,
                           'current_user': current_user,
                           'admin': is_admin(current_user)}
                return templates.TemplateResponse(
                    request=request,
                    name="lottos/lotto.html",
                    context=context
                )

        message = f"당첨 빈도에 관계없이 6개의 숫자를 무작위로 추출"
        context = {"variable": sorted(random.sample(range(1, 46), 6)),
                   "latest": latest_round_num,
                   "message": message,
                   'current_user': current_user,
                   'admin': is_admin(current_user)}
        return templates.TemplateResponse(
            request=request,
            name="lottos/lotto.html",
            context=context
        )
    else:
        message = f"당첨 빈도에 관계없이 6개의 숫자를 무작위로 추출"
        context = {"variable": sorted(random.sample(range(1, 46), 6)),
                   "latest": "0000",
                   "message": message,
                   'current_user': current_user,
                   'admin': is_admin(current_user)}
        return templates.TemplateResponse(
            request=request,
            name="lottos/lotto.html",
            context=context
        )


""" 
''' 랜덤 로또를 렌더링 할 때, 
    DB를 점검하여 가장 최근 lastest data가 업데이트 되어 있지 않으면, 
    업데이트 진행하고 렌더링 할 수 있도록 로직을 변경했지만, 여러 위험들이 있어 실 사용은 하지 않았다. '''
@router.get("/random")
async def random_lotto(request: Request,
                       num: str = None,
                       db: AsyncSession = Depends(get_db),
                       current_user: Optional[User] = Depends(get_optional_current_user)):

    latest_page = await extract_latest_round()
    old_latest = await latest_lotto(db)
    
    if old_latest:
        if latest_page == old_latest.latest_round_num:
            if num:
                lotto_num_list = ast.literal_eval(old_latest.lotto_num_list)
                latest_round_num = old_latest.latest_round_num
                wanted_top_list, lotto_random_num = await extract_frequent_num(lotto_num_list, int(num))
                admin_1 = os.getenv("ADMIN_1")
                admin_2 = os.getenv("ADMIN_2")
                message = f"당첨 빈도가 높은 번호 {num}개중 6개를 무작위로 추출"
                context = {"input_num": num,
                           "variable": lotto_random_num,
                           "latest": int(latest_round_num),
                           "message": message,
                           'current_user': current_user,
                           'admin_1': admin_1,
                           'admin_2': admin_2}
                return templates.TemplateResponse(
                    request=request,
                    name="lottos/lotto.html",
                    context=context
                )
            else:
                latest_round_num = old_latest.latest_round_num
                lotto_random_num = sorted(random.sample(range(1, 46), 6))
                print("2. lotto_random_num:", lotto_random_num)
                admin_1 = os.getenv("ADMIN_1")
                admin_2 = os.getenv("ADMIN_2")
                message = f"당첨 빈도에 관계없이 6개의 숫자를 무작위로 추출"
                context = {"variable": lotto_random_num,
                           "latest": int(latest_round_num),
                           "message": message,
                           'current_user': current_user,
                           'admin_1': admin_1,
                           'admin_2': admin_2}
                return templates.TemplateResponse(
                    request=request,
                    name="lottos/lotto.html",
                    context=context
                )
        else:
            lotto_num_list, top10_list = await extract_first_win_num(db)
            # excell file update
            '''excell update 굳이 할 필요가 있을려나?'''

            # db update
            await old_latest_update(old_latest, db)
            await new_lotto_num_save(latest_page, top10_list, lotto_num_list, db)

            lotto_random_num = sorted(random.sample(range(1, 46), 6))
            print("latest_page != old_latest.latest_round_num")
            print("new.lotto_num_list:", lotto_num_list)
            print("len(new.lotto_num_list):", len(lotto_num_list))
            print("lotto_random_num:", lotto_random_num)
            admin_1 = os.getenv("ADMIN_1")
            admin_2 = os.getenv("ADMIN_2")
            message = f"당첨 빈도에 관계없이 6개의 숫자를 무작위로 추출"
            context = {"variable": lotto_random_num,
                       "latest": int(latest_page),
                       "message": message,
                       'current_user': current_user,
                       'admin_1': admin_1,
                       'admin_2': admin_2}
            return templates.TemplateResponse(
                request=request,
                name="lottos/lotto.html",
                context=context
            )
    else:
        lotto_num_list = await excell2lotto_list()
        lotto_random_num = sorted(random.sample(range(1, 46), 6))
        print("!old_latest")
        print("new_lotto_num_list:", lotto_num_list)
        print("len(lotto_num_list):", len(lotto_num_list))
        top10_list, lotto10_random_num = await extract_frequent_num(lotto_num_list, 10)

        await new_lotto_num_save(latest_page, top10_list, lotto_num_list, db)

        admin_1 = os.getenv("ADMIN_1")
        admin_2 = os.getenv("ADMIN_2")
        message = f"당첨 빈도에 관계없이 6개의 숫자를 무작위로 추출"
        context = {"variable": lotto_random_num,
                   "latest": int(latest_page),
                   "message": message,
                   'current_user': current_user,
                   'admin_1': admin_1,
                   'admin_2': admin_2}
        return templates.TemplateResponse(
            request=request,
            name="lottos/lotto.html",
            context=context
        )
"""


"""# TOP10으로 로또번호를 추출하는 함수"""
@router.get("/top10")
async def top10_lotto(request: Request,
                      num: str = None,
                      db: AsyncSession = Depends(get_db),
                      current_user: Optional[User] = Depends(get_optional_current_user)):
    old_latest = await latest_lotto(db)
    if num:
        print("num: ", num)
        lotto_num_list = ast.literal_eval(old_latest.lotto_num_list)
        latest_round_num = old_latest.latest_round_num
        wanted_top_list, lotto_random_num = await extract_frequent_num(lotto_num_list, int(num))
        message = f"당첨 빈도가 높은 번호 {num}개중 6개를 무작위로 추출"
        context = {"variable": lotto_random_num,
                   "latest": int(latest_round_num),
                   "message": message,
                   'current_user': current_user}
        return templates.TemplateResponse(
            request=request,
            name="lottos/lotto.html",
            context=context
        )
    if old_latest:
        latest_round_num = old_latest.latest_round_num
        """string 로 저장된 최다빈도 번호를 integer list 로 다시 변환하고, 번호 6개 무작위 추출"""
        lotto_top10 = ast.literal_eval(old_latest.extract_num)
        lotto_random_num = sorted(random.sample(lotto_top10, 6))
    else:
        latest_round_num = 1193
        lotto_top10 = [34, 12, 13, 18, 27, 14, 40, 45, 33, 37]
        lotto_random_num = sorted(random.sample(lotto_top10, 6))
    message = f"당첨 빈도가 높은 번호 10개중 6개를 무작위로 추출"
    context = {"variable": lotto_random_num,
               "latest": int(latest_round_num),
               "message": message,
               'current_user': current_user}
    return templates.TemplateResponse(
        request=request,
        name="lottos/lotto.html",
        context=context
    )


@router.get("/win/extract")
async def win_extract_lotto(request: Request,
                            db: AsyncSession = Depends(get_db),
                            admin_user = Depends(allow_usernames(ADMINS))
                            ):
    old_latest = await latest_lotto(db)
    if old_latest:
        '''string 로 저장된 최다빈도 번호를 integer list 로 다시 변환'''
        full_int_list = ast.literal_eval(old_latest.extract_num)
    else:
        full_int_list = []

    context = {"old_extract": old_latest,
               "old_extract_num": full_int_list,
               'current_user': admin_user}
    return templates.TemplateResponse(
        request=request,
        name="lottos/extract.html",
        context=context
    )


@router.post("/win/top10/post")
async def lotto_top10_post(request: Request,
                           latest_round: str = Form(...),
                           db: AsyncSession = Depends(get_db),
                           admin_user = Depends(allow_usernames(ADMINS))
                           ):
    old_latest = await latest_lotto(db) # db에 저장된 것
    latest_page = await extract_latest_round() # 로또사이트의 마지막 회차
    if old_latest:
        if old_latest.latest_round_num == latest_page:
            if latest_round == latest_page:
                raise CustomErrorException(status_code=499, detail="Conflict")
            elif int(latest_round) > int(old_latest.latest_round_num):
                raise CustomErrorException(status_code=499, detail="No Event")

    if int(latest_round) == int(latest_page):
        lotto_num_list, top10_list = await extract_first_win_num(db)
        if old_latest:
            old_latest.status = STATUS[0]
            db.add(old_latest)
            await db.commit()
            await db.refresh(old_latest)

        new = LottoNum()
        new.title = latest_page + "회차"
        new.latest_round_num = latest_page
        new.extract_num = str(top10_list)  # map_str_extract_num
        new.lotto_num_list = str(lotto_num_list)
        db.add(new)
        await db.commit()
        await db.refresh(new)

        """string 로 저장된 최다빈도 번호를 integer list 로 다시 변환"""
        from typing import cast
        extract_num = cast(str, new.extract_num)
        print("extract_num: ", type(extract_num)) # str
        new_extract_num = ast.literal_eval(extract_num)
        print("new_extract_num: ", type(new_extract_num)) # list

        return {"latest": latest_page + "회차", "top10_list": str(top10_list), 'current_user': admin_user}
    else:
        print("입력하신 회차는 마지막 회차가 아니에요...")
        raise CustomErrorException(status_code=415, detail="Not Last")