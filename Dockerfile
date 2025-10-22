# Dockerfile

# 1. 베이스 이미지 설정 (FROM) # 시작 환경 지정. Python 3.13.5-slim 사용.
FROM python:3.13.5-slim

# 캐시를 없애기 위해서 의미없는 RUN 을 한번 해줘야 한다.
RUN echo "testing3"

# 패키지 목록을 업데이트하고 git을 설치합니다.
RUN apt-get update && apt-get install -y git

# 2. 작업 디렉토리 설정 (WORKDIR) # 컨테이너 내 명령 실행 기본 경로 설정.
# github에서 내려받는 작업: 내려받으면 Basics_0.1.4 폴더가 만들어진다.
WORKDIR /home/moljin
RUN git clone https://github.com/moljin/Basics_0.1.4.git

# 만들어진 Basics_0.1.4 폴더에서 작업
WORKDIR /home/moljin/Basics_0.1.4
RUN python -m pip install --upgrade pip

# 4. 의존성 설치 (RUN)
# pip로 requirements.txt의 라이브러리 설치.
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# 6. 포트 노출 (EXPOSE)
# 컨테이너 사용 포트 명시 (문서화 및 네트워킹 기능).
EXPOSE 8000

# 만들어진 Basics_0.1.4 폴더에서 작업
WORKDIR /home/moljin/Basics_0.1.4
# 7. 실행 명령 설정 (CMD)
# 컨테이너 시작 시 실행될 기본 명령어. Uvicorn 서버 실행.
# --host 0.0.0.0 : 컨테이너 외부에서의 접속을 허용하기 위해 필수!
#CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

# gunicorn -w 9 uvicorn.workers.UvicornWorker main:app
# gunicorn --bind unix:/tmp/myapi.sock main:app --worker-class uvicorn.workers.UvicornWorker
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-w", "9", "--bind", "unix:/tmp/myapi.sock", "-b", "0.0.0.0:8000", "main:app"]
