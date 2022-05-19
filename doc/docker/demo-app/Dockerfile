FROM python:3.7-slim
MAINTAINER TeskaLabs Ltd (support@teskalabs.com)

RUN set -ex \
	&& apt-get -y update \
	&& apt-get -y upgrade

RUN apt-get -y install \
	git \
	gcc \
	g++ \
	libsnappy-dev

RUN pip3 install -U git+https://github.com/TeskaLabs/asab.git


FROM python:3.7-slim
MAINTAINER TeskaLabs Ltd (support@teskalabs.com)

COPY --from=0 /usr/local/lib/python3.7/site-packages /usr/local/lib/python3.7/site-packages

COPY ./demoapp.py /app/demo/demoapp.py

WORKDIR /app/demo

CMD ["python3", "demoapp.py", "-c", "/conf/demoapp.conf"]
