FROM python:3.7

EXPOSE 8888

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r requirements.txt -i https://mirrors.ustc.edu.cn/pypi/web/simple 

COPY . .

ENTRYPOINT ["python3", "main.py"]