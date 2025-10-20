import os
import random
from lxml import etree
import requests
from bs4 import BeautifulSoup
import ast
import numpy as np
import pandas as pd
from sqlalchemy import select

from app.core.settings import LOTTO_FILEPATH, LOTTO_LATEST_URL
from app.lottos.models import LottoNum, STATUS


async def old_latest_update(old_latest: LottoNum, db):
    old_latest.status = STATUS[0]
    db.add(old_latest)
    await db.commit()
    await db.refresh(old_latest)


async def new_lotto_num_save(latest_page, top10_list, lotto_num_list, db):
    new = LottoNum()
    new.title = latest_page + "회차"
    new.latest_round_num = latest_page
    new.extract_num = str(top10_list)  # map_str_extract_num
    new.lotto_num_list = str(lotto_num_list)
    db.add(new)
    await db.commit()
    await db.refresh(new)


async def excell2lotto_list():
    df = pd.read_excel(LOTTO_FILEPATH, sheet_name='lotto')
    # 'ColumnName' 열을 리스트로 변환하기
    column_list = df['list'].tolist()
    """ # column list안의 요소들이 문자열이다. 이것을 nested list로 아래 처럼 한번 바꿔줘야 한다."""
    result_list = [ast.literal_eval(s) for s in column_list]
    return result_list


async def latest_win_num():
    html = requests.get(LOTTO_LATEST_URL).text
    soup = BeautifulSoup(html, 'lxml')

    soup_lottos = soup.select("span.ball_645")[:6]
    lotto_nums = [int(soup_lotto.get_text()) for soup_lotto in soup_lottos]
    return lotto_nums


async def latest_lotto(db):
    query = select(LottoNum).where(LottoNum.status == STATUS[1])
    result = await db.execute(query)
    _latest_lotto = result.scalar_one_or_none()
    return _latest_lotto


async def extract_latest_round():
    latest_html = requests.get(LOTTO_LATEST_URL).text
    soup = BeautifulSoup(latest_html, 'lxml')
    list_select = soup.find("select", id="dwrNoList")

    selected_soup = BeautifulSoup(f"""{list_select}""", 'lxml')
    latest_round = selected_soup.find_all('option', selected=True)[0].get_text()
    print("마지막 회차:: ", int(latest_round))

    select_html = etree.HTML(f"""{list_select}""")
    selected = select_html.xpath('//option[@selected]')
    # print(selected)  # 여기서 selected value 만 가져오는 방법을 못찾겠다.

    return latest_round


async def extract_frequent_num(_list: list, num: int):
    # 다차원 배열을 1차원 배열로 만들기 (개수를 세기 위해서)
    lotto_countlist = np.ravel(_list, order='C').tolist()

    # 1~45까지 카운트한 횟수를 넣는 리스트
    lotto_count_value = []
    for i in range(1, 46):
        lotto_count_value.append(lotto_countlist.count(i))

    # 카운트한 값을 데이터프레임으로 만들기
    data = np.array(lotto_count_value)
    index_num = [i for i in range(1, 46)]
    columns_list = ["count"]
    df_lotto_count = pd.DataFrame(data, index=index_num, columns=columns_list)

    # num이 전체 후보 개수(45)를 넘으면 45로 캡핑. 빈도수 높은 숫자가 46개이상은 나올 수가 없다.
    total_candidates = len(df_lotto_count)  # == 45
    k = min(int(num), total_candidates)

    # 가장 많이 나온 로또 번호 num개 추출
    wanted_top = df_lotto_count.nlargest(k, 'count')
    
    # num개 추출한 것 리스트로 만들기
    wanted_top_list = wanted_top.index.tolist()
    print("wanted_top_list:", wanted_top_list)
    print("len(wanted_top_list):", len(wanted_top_list))

    # random.sample 표본 크기도 안전하게 제한 (최대 6)
    sample_size = min(6, len(wanted_top_list))
    lotto_random_num = sorted(random.sample(wanted_top_list, sample_size))
    print("lotto_random_num:", lotto_random_num)

    return wanted_top_list, lotto_random_num



async def extract_first_win_num(db, num: int = 10):
    old_latest = await latest_lotto(db)
    """1등번호 10개 추출하기"""
    if old_latest: # 역대 로또 번호를 저장하는 리스트에 추가한다.
        lotto_num_list = ast.literal_eval(old_latest.lotto_num_list)
        latest_lotto_num = await latest_win_num()
        lotto_num_list.append(latest_lotto_num)
    else: # 최초 데이터 저장시에는 엑셀파일에서 총 로또 번호를 뽑아내서 저장한다.
        lotto_num_list = await excell2lotto_list()

    top10_list, lotto_random_num = await extract_frequent_num(lotto_num_list, num)

    return lotto_num_list, top10_list