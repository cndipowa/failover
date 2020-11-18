FROM centos:7
MAINTAINER nih.gov
RUN yum update -y && yum install -y python3-pip python3-dev
COPY ./requirements.txt /requirements.txt
WORKDIR /
RUN pip3 install -r requirements.txt
COPY . /
ENTRYPOINT [ "python3" ]
CMD [ "failover.pyz" ]
