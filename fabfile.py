from __future__ import with_statement
from fabric.api import *
from fabric.contrib.console import confirm

env.hosts=['cbreg@54.248.86.233'] # cbreg 0.1 (small)

@with_settings(warn_only=True)

def create_folder():
    local ('mkdir -p logs')
    local ('chmod -Rf 777 logs')
    local ('mkdir -p test_web_root')

def coverage():
    create_folder()
    local ("coverage xml --include='cb_lan/*'")

def ci_test():
    create_folder()
    local ('nosetests --with-xunit --all-modules --traverse-namespace '
           '--with-coverage --cover-package=cb_lan --cover-inclusive '
           'test_srv.py test_cb.py test_srv_bug.py')
    coverage()

def test():
    create_folder()
    with settings(warn_only=True):
        result = local('python ./test_srv.py', capture=True)
    if result.failed and not confirm("Tests failed. Continue anyway?"):
        abort("Aborting at user request.")

def commit():
    local("git add -p && git commit")

def push():
    local("git pull --rebase; git push")

def deploy():
    proj_dir = '/home/cbreg/prj/regioh'
    with settings(warn_only=True):
        if run("test -d %s" % proj_dir).failed:
            run("git clone git@github.com:circlelychen/regioh.git %s" % proj_dir)
    with cd(proj_dir):
        run("git pull --rebase")
    #run("touch uwsgi.reload")

