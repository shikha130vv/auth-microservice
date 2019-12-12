FROM python:3.8.0-alpine
# set work directory
WORKDIR /auth-microservice/

RUN pip install --upgrade pip


COPY ./requirements.txt /auth-microservice/requirements.txt
COPY ./main.py /auth-microservice/main.py
RUN apk update && apk add gcc python3-dev musl-dev libffi-dev
RUN pip install -r requirements.txt

RUN mkdir /auth-microservice/project
COPY project /auth-microservice/project/
COPY config /auth-microservice/config/

EXPOSE 80

ENV PYTHONPATH /auth-microservice
ENV FLASK_APP main.py
#ENTRYPOINT ["python3"]
CMD python -m flask db init;python -m flask db migrate;python -m flask db upgrade;python -m flask run --host=0.0.0.0 --port=80
