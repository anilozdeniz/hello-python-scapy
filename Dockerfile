FROM python:3.11.3

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY capture.pcap ./
COPY main.py ./

CMD [ "python", "./main.py", "./capture.pcap" ]