FROM teskalabs/bspump-dependencies:master-alpine3.8
MAINTAINER TeskaLabs Ltd (support@teskalabs.com)

# http://bugs.python.org/issue19846
# > At the moment, setting "LANG=C" on a Linux system *fundamentally breaks Python 3*, and that's not OK.
ENV LANG C.UTF-8

RUN set -ex \
        && pip install git+https://github.com/TeskaLabs/asab.git

RUN set -ex \
        && pip install git+https://github.com/LibertyAces/BitSwanPump.git --no-deps


RUN set -ex \
        && pip install vininfo \
        && pip install requests

RUN set -ex \
        mkdir /opt/microservice

COPY ./test_microservice.py /opt/microservice/test.py

CMD ["python3", "/opt/microservice/test.py", "-w"]
