import abc
import copy
import pickle
from uuid import uuid4


class Driver(metaclass=abc.ABCMeta):

    _client = None

    def _create_client(self):
        raise NotImplementedError('subclasses of Driver must provide a _create_client() method')

    def _setup_client(self):
        if self._client is None:
            self._create_client()

    def get(self, session_id):
        self._setup_client()
        raw_session = self._client.get(session_id)
        return self._to_dict(raw_session)

    def _to_dict(self, raw_session):
        if raw_session is None:
            return {}
        else:
            return pickle.loads(raw_session)

    def _set_and_expire(self, session_id, pickled_session):
        raise NotImplementedError('subclasses of Driver must provide a _set_and_expire() method')

    def set(self, session_id, session):
        pickled_session = pickle.dumps(session)
        self._setup_client()
        self._set_and_expire(session_id, pickled_session)


class RedisDriver(Driver):
    EXPIRE_SECONDS = 2 * 60 * 60
    DEFAULT_STORAGE_IDENTIFIERS = {
        'db_sessions': 0,
        'db_notifications': 1,
    }

    def __init__(self, settings):
        self.settings = settings

    def _set_and_expire(self, session_id, pickled_session):
        self.client.set(session_id, pickled_session, self.EXPIRE_SECONDS)

    def _create_client(self):
        import redis
        if 'max_connections' in self.settings:
            connection_pool = redis.ConnectionPool(**self.settings)
            settings = copy.copy(self.settings)
            del settings['max_connections']
            settings['connection_pool'] = connection_pool
        else:
            settings = self.settings
        self.client = redis.StrictRedis(**settings)


class Session:

    def __init__(self, handler):
        """
        Expects a tornado.web.RequestHandler
        """

        self.handler = handler
        self.settings = handler.settings['session']
        self.engine = self.settings['engine']

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

    def __set_session_in_db(self, session):
        session_id = self.__get_session_id()
        self.driver.set(session_id, session)

    def __get_session_from_db(self):
        session_id = self.__get_session_id()
        return self.driver.get(session_id)

    def __get_session_id(self):
        session_id = self.handler.get_secure_cookie(self.SESSION_ID_NAME)
        if session_id is None:
            session_id = self.__create_session_id()
        return session_id

    def __create_session_id(self):
        session_id = str(uuid4())
        self.handler.set_secure_cookie(self.SESSION_ID_NAME, session_id,
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


class SessionMixin:
    """
    This mixin must be included in the request handler inheritance list, so that
    the handler can support sessions.

    Example:
    >>> class MyHandler(tornado.web.RequestHandler, SessionMixin):
    ...    def get(self):
    ...        print type(self.session) # SessionManager

    Refer to SessionManager documentation in order to know which methods are
    available.
    """

    @property
    def session(self):
        """
        Returns a SessionManager instance
        """

        return create_mixin(self, '__session_manager', SessionManager)


class ConfigurationError(Exception):
    pass


def create_mixin(context, manager_property, manager_class):
    if not hasattr(context, manager_property):
        setattr(context, manager_property, manager_class(context))
    return getattr(context, manager_property)
