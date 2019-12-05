FROM python:3.8

EXPOSE 8888

RUN mkdir -p /usr/src/ap7p
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r requirements.txt -i https://mirrors.ustc.edu.cn/pypi/web/simple 

COPY . .

RUN sed -i 's/localhost/fluentd/' main.py

ENTRYPOINT ["python3", "main.py"]