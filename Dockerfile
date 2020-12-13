FROM python:3.7

COPY . /home
WORKDIR /home
VOLUME /home/logic

RUN pip install -r requirements.txt

CMD ["bash"]