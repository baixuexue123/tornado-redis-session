#!/usr/bin/env python3
import os.path
import pickle
import concurrent.futures
from uuid import uuid4

import tornado.escape
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
from tornado import gen
from tornado.options import define, options

import bcrypt
import torndb
import redis


define("port", default=8000, help="run on the given port", type=int)

# A thread pool to be used for password hashing with bcrypt.
executor = concurrent.futures.ThreadPoolExecutor(2)


class Session:

    def __init__(self, handler):
        """
        Expects a tornado.web.RequestHandler
        """

        self.handler = handler
        self.settings = handler.settings
        self.secret_key = handler.settings['cookie_secret']
        session_settings = handler.settings['session']
        self.engine = session_settings['engine']
        self.cache_key_prefix = session_settings['cache_key_prefix']
        self.expire_seconds = session_settings['expire_seconds']
        self.session_id_name = session_settings['session_id_name']

    def set(self, name, value):
        """
        Sets a value for "name". It may be any pickable (see "pickle" module
        documentation) object.
        """

        def change(session):
            session[name] = value
        self.__change_session(change)

    def get(self, name, default=None):
        """
        Gets the object for "name", or None if there's no such object. If
        "default" is provided, return it if no object is found.
        """

        session = self.__get_session_from_db()
        return session.get(name, default)

    def delete(self, *names):
        """
        Deletes the object with "name" from the session, if exists.
        """

        def change(session):
            keys = session.keys()
            names_in_common = [name for name in names if name in keys]
            for name in names_in_common:
                del session[name]
        self.__change_session(change)
    __delitem__ = delete

    def clear(self):
        session_id = self.__get_session_id()
        self.engine.delete(session_id)
        self.handler.clear_cookie(self.session_id_name)

    def keys(self):
        session = self.__get_session_from_db()
        return session.keys()

    def iterkeys(self):
        session = self.__get_session_from_db()
        return iter(session)
    __iter__ = iterkeys

    def __getitem__(self, key):
        value = self.get(key)
        if value is None:
            raise KeyError('%s not found in session' % key)
        return value

    def __setitem__(self, key, value):
        self.set(key, value)

    def __contains__(self, key):
        session = self.__get_session_from_db()
        return key in session

    def __set_session_in_db(self, session_data):
        session_id = self.__get_session_id()
        pickled_session = pickle.dumps(session_data)
        self.engine.set(session_id, pickled_session, self.expire_seconds)

    def __get_session_from_db(self):
        session_id = self.__get_session_id()
        session_data = self.engine.get(session_id)
        if session_data is None:
            return {}
        else:
            return pickle.loads(session_data)

    def __get_session_id(self):
        session_id = self.handler.get_secure_cookie(self.session_id_name)
        if session_id is None:
            session_id = self.__create_session_id()
        return session_id

    def __create_session_id(self):
        session_id = str(uuid4())
        self.handler.set_secure_cookie(self.session_id_name, session_id,
                                       **self.__cookie_settings())
        return session_id

    def __change_session(self, callback):
        session = self.__get_session_from_db()

        callback(session)
        self.__set_session_in_db(session)

    def __cookie_settings(self):
        cookie_settings = self.settings.get('cookies', {})
        cookie_settings.setdefault('expires', None)
        cookie_settings.setdefault('expires_days', None)
        return cookie_settings


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/auth/create", AuthCreateHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
        ]
        settings = dict(
            title="Tornado demo",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
            cookie_secret="32oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
            login_url="/auth/login",
            debug=True,
        )
        settings['database'] = dict(
            name='demo',
            user='demo',
            password='demo',
            host='127.0.0.1',
            port=6379,
        )
        settings['session'] = dict(
            session_id_name='_sessionid',
            expire_seconds=60 * 60 * 1,
            cache_key_prefix='session-',
            engine=redis.StrictRedis(host='127.0.0.1', port=6379, db=0),
        )
        super(Application, self).__init__(handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    _db_conn = None

    def _setup_db_conn(self):
        database = self.settings['database']
        self._db_conn = torndb.Connection(
            host=database['host'], database=database['name'],
            user=database['user'], password=database['password']
        )

    @property
    def db(self):
        if self._db_conn is None:
            self._setup_db_conn()
        return self._db_conn

    @property
    def session(self):
        """
        Returns a SessionManager instance
        """
        if not hasattr(self, '__session_manager'):
            setattr(self, '__session_manager', Session(self))
        return getattr(self, '__session_manager')

    def get_current_user(self):
        user_id = self.session.get('user_id')
        if not user_id:
            return None
        return self.db.get("SELECT * FROM authors WHERE id = %s", int(user_id))


class HomeHandler(BaseHandler):
    def get(self):
        entries = self.db.query("SELECT * FROM entries ORDER BY published "
                                "DESC LIMIT 5")
        if not entries:
            self.redirect("/compose")
            return
        self.render("home.html", entries=entries)


class AuthCreateHandler(BaseHandler):
    def get(self):
        self.render("create_author.html")

    @gen.coroutine
    def post(self):
        hashed_password = yield executor.submit(
            bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
            bcrypt.gensalt())
        author_id = self.db.execute(
            "INSERT INTO authors (email, name, hashed_password) "
            "VALUES (%s, %s, %s)",
            self.get_argument("email"), self.get_argument("name"),
            hashed_password)
        self.set_secure_cookie("blogdemo_user", str(author_id))
        self.redirect(self.get_argument("next", "/"))


class AuthLoginHandler(BaseHandler):
    def get(self):
        self.render("login.html", error=None)

    @gen.coroutine
    def post(self):
        author = self.db.get("SELECT * FROM authors WHERE email = %s",
                             self.get_argument("email"))
        if not author:
            self.render("login.html", error="email not found")
            return
        hashed_password = yield executor.submit(
            bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
            tornado.escape.utf8(author.hashed_password)
        )
        if hashed_password == author.hashed_password:
            self.session["user_id"] = str(author.id)
            self.redirect(self.get_argument("next", "/"))
        else:
            self.render("login.html", error="incorrect password")


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.session.clear()
        self.redirect(self.get_argument("next", "/"))


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
