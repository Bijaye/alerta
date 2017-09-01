
import os

from importlib import import_module


class Base(object):
    pass

# http://stackoverflow.com/questions/8544983/dynamically-mixin-a-base-class-to-an-instance-in-python


class Database(Base):

    def __init__(self, app=None):
        self.app = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        backend = os.environ.get('DATABASE_ENGINE', None) or app.config['DATABASE_ENGINE']
        cls = load_backend(backend)
        self.__class__ = type('DatabaseImpl', (cls.Backend, Database), {})

        self.app = app
        if backend not in app.extensions:
            app.extensions[backend] = {}
        app.extensions[backend] = self.connect(app.config)

    def connect(self, config):
        raise NotImplementedError('database engine has no connect() method')

    def close(self):
        raise NotImplementedError('database engine has no close() method')

    def destroy(self):
        raise NotImplementedError('database engine has no destroy() method')

    def build_query(self, params):
        raise NotImplementedError('database engine has no build_query() method')


def load_backend(backend):
    try:
        return import_module('alerta.app.database.backends.%s' % backend)
    except:
        raise ImportError('Failed to load %s database backend' % backend)
