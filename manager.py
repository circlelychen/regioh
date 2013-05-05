#!/usr/bin/env python
#-*- coding: utf-8 -*-
from flask.ext.script import Manager

from regioh import app

manager = Manager(app)

@manager.command
def reset():
    pass

if __name__ == "__main__":
    manager.run()
