import inspect

from dockerhub_api import *


def test_comments():
    # also serves as iterator vs lists return
    dh = DockerHub()
    assert inspect.isgenerator(dh.comments("_", "nginx"))
    dh.return_lists = True
    comments = dh.comments("_", "nginx")
    assert isinstance(comments, list)
    assert 'id' in comments[0]
    assert 'comment' in comments[0]


def test_repository():
    dh = DockerHub(return_lists=True)
    for u, n, fu in zip(['_', 'library', 'JwiLder'], ['nginx', 'nginx', 'nginx-proxy'],
                        ['library', 'library', 'jwilder']):
        r = dh.repository(u, n)
        assert r['user'] == fu and r['name'] == n


def test_repositories():
    # TODO
    assert True


def test_repositories_starred():
    # TODO
    assert True


def test_tags():
    # TODO
    assert True


def test_user():
    # TODO
    assert True
