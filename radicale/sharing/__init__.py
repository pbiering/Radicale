# This file is part of Radicale Server - Calendar Server
# Copyright © 2026-2026 Peter Bieringer <pb@bieringer.de>
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Radicale.  If not, see <http://www.gnu.org/licenses/>.

import io
import json
import re

from csv import DictWriter
from http import client
from urllib.parse import parse_qs

from radicale import (httputils, utils)
from radicale.log import logger

INTERNAL_TYPES: Sequence[str] = ("csv", "sqlite", "mock", "none")

DB_FIELDS = ['type', 'path_token', 'path_mapped', 'owner', 'user', 'permissions', 'enabled', 'hidden', 'created', 'last_updated']

def load(configuration: "config.Configuration") -> "BaseSharing":
    """Load the sharing module chosen in configuration."""
    return utils.load_plugin(INTERNAL_TYPES, "sharing", "Sharing", BaseSharing, configuration)



class BaseSharing:

    configuration: "config.Configuration"

    def __init__(self, configuration: "config.Configuration") -> None:
        """Initialize Sharing.

        ``configuration`` see ``radicale.config`` module.
        The ``configuration`` must not change during the lifetime of
        this object, it is kept as an internal reference.

        """
        self.configuration = configuration
        # Sharing
        self.sharing_collection_by_map = configuration.get("sharing", "collection_by_map")
        self.sharing_collection_by_token = configuration.get("sharing", "collection_by_token")
        logger.info("sharing.collection_by_map  : %s", self.sharing_collection_by_map)
        logger.info("sharing.collection_by_token: %s", self.sharing_collection_by_token)
        self.sharing_db_type = configuration.get("sharing", "type")
        logger.info("sharing.db_type: %s", self.sharing_db_type)
        # database tasks
        try:
            if self.init_database() is False:
                exit(1)
        except Exception as e:
            exit(1)
        database_info = self.get_database_info()
        if database_info:
            logger.info("sharing database info: %r", database_info)
        else:
            logger.info("sharing database info: (not provided)")

    ## overloadable functions
    def init_database(self) -> bool:
        """ initialize database """
        return None

    def get_database_info(self) -> [ dict | None]:
        """ retrieve database information """
        return None

    def get_sharing_collection_by_token(self, token: str) -> [dict | None]:
        """ retrieve target and attributes by token """
        return None

    def get_sharing_collection_by_map(self, path: str) -> [dict | None]:
        """ retrieve target and attributes by map """
        return None

    def get_sharing_list_by_type_user(self, share_type, user) -> [dict | None]:
        """ retrieve sharing list by type and user """
        return None

    ## static sharing functions
    def sharing_collection_resolver(self, path) -> [dict | None]:
        if self.sharing_collection_by_token:
            result = self.sharing_collection_by_token_resolver(path)
            if result is None:
                return result
            elif result["mapped"]:
                return result
        else:
            logger.debug("TRACE/sharing_by_token: not active")

        if self.sharing_collection_by_map:
            result = self.sharing_collection_by_map_resolver(path)
            if result is None:
                return result
            elif result["mapped"]:
                return result
        else:
            logger.debug("TRACE/sharing_by_map: not active")

        # final
        return {"mapped": False}

    def sharing_collection_by_token_resolver(self, path) -> [dict | None]:
        """ returning dict with mapped-flag, path, user, rights or None if invalid"""
        if self.sharing_collection_by_token:
            logger.debug("TRACE/sharing_by_token: check path: %r", path)
            if path.startswith("/.token/"):
                pattern = re.compile('^/\\.token/v(\\d+)/([a-zA-z0-9]+)')
                match = pattern.match(path)
                if not match:
                    logger.debug("TRACE/sharing_by_token: unsupported token: %r", path)
                    return None
                else:
                    # TODO add token validity checks
                    logger.debug("TRACE/sharing_by_token: supported token found in path: %r (version=%s token=%r)", path, match[1], match[2])
                    return self.get_sharing_collection_by_token("v" + match[1] + "/" + match[2])
            else:
                logger.debug("TRACE/sharing_by_token: no supported prefix found in path: %r", path)
                return {"mapped": False}
        else:
            logger.debug("TRACE/sharing_by_token: not active")
            return {"mapped": False}

    def sharing_collection_by_map_resolver(self, path) -> [dict | None]:
        """ returning dict with mapped-flag, path, user, rights or None if invalid"""
        if self.sharing_collection_by_map:
            logger.debug("TRACE/sharing_by_map: check path: %r", path)
            return self.get_sharing_collection_by_map(path)
        else:
            logger.debug("TRACE/sharing_by_map: not active")
            return {"mapped": False}

    ## POST API
    def post(self, environ: types.WSGIEnviron, base_prefix: str, path: str, user: str) -> types.WSGIResponse:
        """POST request.

        ``base_prefix`` is sanitized and never ends with "/".

        ``path`` is sanitized and always starts with "/.sharing"

        ``user`` is empty for anonymous users.

        """
        if user == "":
            # anonymous users are not allowed
            return httputils.NOT_ALLOWED

        logger.debug("TRACE/sharing/API: called by authenticated user: %r", user)
        # read POST data
        try:
            request_body = httputils.read_request_body(self.configuration, environ)
        except RuntimeError as e:
            logger.warning("Bad POST request on %r (read_request_body): %s", path, e, exc_info=True)
            return httputils.BAD_REQUEST
        except socket.timeout:
            logger.debug("Client timed out", exc_info=True)
            return httputils.REQUEST_TIMEOUT

        # parse body according to content-type
        content_type = environ.get("CONTENT_TYPE", "")
        if 'application/json' in content_type:
            try:
                request_data = json.loads(request_body)
            except json.JSONDecodeError:
                return httputils.BAD_REQUEST
            logger.debug("TRACE/sharing/API/POST (json): %r", f"{request_data}")
        elif 'application/x-www-form-urlencoded' in content_type:
            request_data = parse_qs(request_body)
            logger.debug("TRACE/sharing/API/POST (form): %r", f"{request_data}")
        else:
            return httputils.BAD_REQUEST

        ## action dispatcher
        if not 'action' in request_data:
            # mandatory
            return httputils.BAD_REQUEST


        if request_data['action'][0] == "list":
            logger.debug("TRACE/sharing/API/POST/action: list")
            if not 'format' in request_data:
                output_format = "csv"
            else:
                output_format = request_data['format'][0]

            if not 'type' in request_data:
                share_type = "*" # any
            else:
                share_type = request_data['type'][0]

            result = self.get_sharing_list_by_type_user(share_type, user)

            logger.debug("TRACE/sharing/API/POST output format: %r", output_format)
            if output_format == "csv":
                answer = io.StringIO()
                writer = DictWriter(answer, fieldnames=DB_FIELDS)
                writer.writeheader()
                for entry in result:
                    writer.writerow(entry)
                headers = {
                    "Content-Type": "text/csv"
                }
                return client.OK, headers, answer.getvalue(), None
            elif output_format == "json":
                answer = json.dumps(result)
                headers = {
                    "Content-Type": "text/json"
                }
                return client.OK, headers, answer, None
            else:
                return httputils.BAD_REQUEST

        else:
            # default
            return httputils.BAD_REQUEST

        return httputils.METHOD_NOT_ALLOWED
