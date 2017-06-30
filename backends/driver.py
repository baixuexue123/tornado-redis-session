"""
This module is for internal use, only. It contains datastore drivers to be used
with the session and notification managers.
"""
import abc
import copy
import pickle


class Driver(metaclass=abc.ABCMeta):

    EXPIRE_SECONDS = 2 * 60 * 60

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


class DriverFactory(object):
    STORAGE_CATEGORIES = ('db_sessions', 'db_notifications')

    def create(self, name, storage_settings, storage_category):
        method = getattr(self, '_create_%s' % name, None)
        if method is None:
            raise ValueError('Engine "%s" is not supported' % name)
        return method(storage_settings, storage_category)

    def _create_redis(self, storage_settings, storage_category):
        storage_settings = copy.copy(storage_settings)
        default_storage_identifier = RedisDriver.DEFAULT_STORAGE_IDENTIFIERS[storage_category]
        storage_settings['db'] = storage_settings.get(storage_category, default_storage_identifier)
        for storage_category in self.STORAGE_CATEGORIES:
            if storage_category in storage_settings.keys():
                del storage_settings[storage_category]

        return RedisDriver(storage_settings)

    def _create_memcached(self, storage_settings, storage_category):
        return MemcachedDriver(storage_settings)
