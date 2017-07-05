#!/usr/bin/env python3
import os.path
import concurrent.futures

import tornado.escape
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
from tornado import gen
from tornado.options import define, options

import bcrypt
import redis
from tornado_mysql import pools

from .session import Session

define("port", default=8000, help="run on the given port", type=int)

# A thread pool to be used for password hashing with bcrypt.
executor = concurrent.futures.ThreadPoolExecutor(2)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/auth/create", AuthCreateHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
        ]
        settings = dict(
            title="Tornado blog",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
            cookie_secret="32oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
            login_url="/auth/login",
            debug=True,
        )
        settings['session'] = dict(
            session_id_name='_sessionid',
            expire_seconds=60 * 60 * 2,
            backend=redis.StrictRedis(host='127.0.0.1', port=6379, db=0),
        )
        super(Application, self).__init__(handlers, **settings)
        self.pool = pools.Pool(
            dict(host='127.0.0.1', port=3306, user='blog', passwd='blog', db='blog'),
            max_idle_connections=1,
            max_recycle_sec=3
        )


class BaseHandler(tornado.web.RequestHandler):

    @property
    def db(self):
        return self.application.pool

    @property
    def session(self):
        """ Returns a Session instance """
        if not hasattr(self, '__session_manager'):
            setattr(self, '__session_manager', Session(self))
        return getattr(self, '__session_manager')

    def get_current_user(self):
        user_json = self.session.get('user')
        return tornado.escape.json_decode(user_json)


class HomeHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        entries = self.db.query("SELECT * FROM entries ORDER BY published DESC LIMIT 5")
        self.render("home.html", entries=entries)


class AuthCreateHandler(BaseHandler):
    def get(self):
        self.render("create_user.html")

    @gen.coroutine
    def post(self):
        hashed_password = yield executor.submit(
            bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
            bcrypt.gensalt()
        )
        yield self.db.execute(
            "INSERT INTO authors (email, name, hashed_password) VALUES (%s, %s, %s)",
            self.get_argument("email"), self.get_argument("name"), hashed_password
        )
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
    @tornado.web.authenticated
    def get(self):
        self.session.flush()
        self.redirect(self.get_argument("next", "/"))


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
