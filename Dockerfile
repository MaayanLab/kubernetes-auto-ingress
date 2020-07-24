FROM python:3

ADD requirements.txt /requirements.txt
RUN pip3 install -Ir /requirements.txt && rm /requirements.txt

ADD auto-ingress.py /usr/local/bin/auto-ingress
RUN chmod +x /usr/local/bin/auto-ingress

CMD [ "auto-ingress" ]