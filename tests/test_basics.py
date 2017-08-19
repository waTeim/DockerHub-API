import os

from dockerhub_api import *
from dockerhub_api.dockerhub_api import parse_url


def test_parse_url():
    assert parse_url("https://hub.docker.com/v2/repositories/mumblepins/docker-on-debian-circleci?thing=test&test1=1") \
           == \
           ('https://hub.docker.com/v2/repositories/mumblepins/docker-on-debian-circleci',
            {'test1': ['1'], 'thing': ['test']})

    assert parse_url("https://hub.docker.com/v2/repositories/mumblepins/docker-on-debian-circleci/") \
           == \
           ('https://hub.docker.com/v2/repositories/mumblepins/docker-on-debian-circleci/', {})

    assert parse_url(
            "https://hub.docker.com/v2/repositories/mumblepins/docker-on-debian-circleci?thing=test&test1=1&thing=test2") \
           == \
           ('https://hub.docker.com/v2/repositories/mumblepins/docker-on-debian-circleci',
            {'test1': ['1'], 'thing': ['test', 'test2']})


def test_login_userpass():
    dh = DockerHub()
    dh.login(username=os.environ.get('DOCKER_USER'), password=os.environ.get('DOCKER_PASS'))
    assert dh.logged_in is True
    assert dh.logged_in_user()['username'] == os.environ.get('DOCKER_USER')


def test_login_token():
    dh = DockerHub()
    dh.login(token=os.environ.get('DOCKER_TOKEN'))
    assert dh.logged_in is True
    assert dh.logged_in_user()['username'] == os.environ.get('DOCKER_USER')
