# aiozabbix - Asynchronous Zabbix API Python Library
#
# Original Ruby Library is Copyright (C) 2009 Andrew Nelson nelsonab(at)red-tux(dot)net
# Original Python Library is Copyright (C) 2009 Brett Lentz brett.lentz(at)gmail(dot)com
#
# Copyright (C) 2011-2018 Luke Cyca me(at)lukecyca(dot)com
# Copyright (C) 2018-2019 Modio AB
#
# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA
#
# patch: ADD logout method

import aiohttp
import app_config

class ZabbixAPIException(Exception):
    pass


class ZabbixAPI:
    DEFAULT_HEADERS = {'Content-Type': 'application/json-rpc'}

    LOGIN_METHODS = ('user.login', 'user.authenticate')
    UNAUTHENTICATED_METHODS = ('apiinfo.version',) + LOGIN_METHODS
    AUTH_ERROR_FRAGMENTS = (
        'authori',                   # From CLocalApiClient::authenticate
        'permission',                # From CUser::checkAuthentication
        're-login',                  # From many places
    )

    def __init__(self,
                 server='http://localhost/zabbix',
                 *,
                 timeout=None,
                 client_session=None,
                 headers=None):

        self.url = server + '/api_jsonrpc.php'

        if client_session is None:
            self.client_session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=app_config.VERIFY_SSL))
        else:
            self.client_session = client_session

        self.timeout = timeout

        self.auth = ''
        self.shared_state = {'next_jsonrpc_id': 0}
        self.do_login = None

        self.headers = self.DEFAULT_HEADERS.copy()
        if headers is not None:
            self.headers.update(headers)

    def with_headers(self, headers):
        """Make a copy of the ZabbixAPI object which sets extra HTTP headers.

        """
        result = ZabbixAPI.__new__(ZabbixAPI)
        result.url = self.url
        result.client_session = self.client_session
        result.timeout = self.timeout
        result.auth = self.auth
        result.shared_state = self.shared_state
        result.do_login = self.do_login
        result.headers = self.headers.copy()
        result.headers.update(headers)
        return result

    async def do_request(self, method, params=None, auth_retries=1):
        request_json = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params or {},
            'id': self.shared_state['next_jsonrpc_id'],
        }
        self.shared_state['next_jsonrpc_id'] += 1

        if method in self.UNAUTHENTICATED_METHODS:
            return await self.post_request(request_json)

        request_json['auth'] = self.auth

        try:
            return await self.post_request(request_json)
        except ZabbixAPIException as exc:
            if auth_retries > 0 and self.do_login and self.is_auth_error(exc):
                await self.do_login(self)
                return await self.do_request(method, params, auth_retries=auth_retries - 1)
            raise

    async def post_request(self, request_json):
        response = await self.client_session.post(self.url,
                                                  json=request_json,
                                                  headers=self.headers,
                                                  timeout=self.timeout)
        response.raise_for_status()

        try:
            response_json = await response.json()
        except ValueError as exc:
            raise ZabbixAPIException(f'Unable to parse JSON: {response.text()}') from exc

        if 'error' in response_json:
            # Workaround for ZBX-9340, some errors don't contain 'data':
            if 'data' not in response_json['error']:
                response_json['error']['data'] = 'ZBX-9340: No data'

            err = response_json['error']
            msg = f"Error {err['code']}: {err['message']}, {err['data']}"
            raise ZabbixAPIException(msg, err['code'])

        return response_json

    @classmethod
    def method_needs_auth(cls, method):
        return method not in cls.UNAUTHENTICATED_METHODS

    @classmethod
    def is_auth_error(cls, exc):
        """Determine if an error is an authorization error.

        This makes a best effort attempt to recognize authentication
        or authorization errors. Unfortunately the general JSON-RPC
        error code -32602 (Invalid params) and the generic Zabbix
        error -32500 are used for these types of errors.

        The error messages may also be localized which could make this
        check fail.
        """

        err = str(exc).lower()
        return any(x in err for x in cls.AUTH_ERROR_FRAGMENTS)

    async def login(self, user='', password=''):
        async def do_login(self):
            # Provide the self argument explicitly instead of taking
            # it from the surrounding closure. The self from the
            # closure will not be correct if this do_login is called
            # from a copy of the ZabbixAPI object created by the
            # with_headers method.
            self.auth = ''
            self.auth = await self.user.login(user=user, password=password)

        self.do_login = do_login
        await self.do_login(self)

    async def confimport(self, confformat='', source='', rules=''):
        return await self.configuration.import_(format=confformat, source=source, rules=rules)

    def __getattr__(self, attr):
        return ZabbixAPIObjectClass(name=attr, parent=self)

    async def logout(self):
        await self.user.logout()
        await self.client_session.close()


class ZabbixAPIObjectClass:
    def __init__(self, *, name, parent):
        self.name = name
        self.parent = parent

    def __getattr__(self, attr):
        if attr == 'import_':
            attr = 'import'

        async def method(*args, **kwargs):
            if args and kwargs:
                raise TypeError(
                    'Method may be called with positional arguments or '
                    'keyword arguments, but not both at the same time'
                )

            response = await self.parent.do_request(f'{self.name}.{attr}', args or kwargs)
            return response['result']

        return method
