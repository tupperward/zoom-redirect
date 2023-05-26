FROM python:3.10-alpine

RUN mkdir /redirect

WORKDIR /redirect

COPY . /redirect

RUN chown daemon /redirect
RUN chmod 705 /redirect 
RUN pip install -r requirements.txt

EXPOSE 8000
USER daemon
ENTRYPOINT [ "sh", "./startup.sh" ]