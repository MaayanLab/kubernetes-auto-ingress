FROM python:3

ADD requirements.txt /requirements.txt
RUN pip3 install -Ir /requirements.txt && rm /requirements.txt

ADD kubernetes-auto-ingress.py /usr/local/bin/kubernetes-auto-ingress
RUN chmod +x /usr/local/bin/kubernetes-auto-ingress

CMD [ "kubernetes-auto-ingress" ]