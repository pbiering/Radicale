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

import base64
import io
import json
import re
import socket
import uuid

from csv import DictWriter
from datetime import datetime
from http import client
from urllib.parse import parse_qs

from radicale import config, httputils, rights, utils
from radicale.app.base import Access
from radicale.log import logger

INTERNAL_TYPES: Sequence[str] = ("csv", "sqlite", "mock", "none")

DB_FIELDS: Sequence[str] = ('Type', 'PathOrToken', 'PathMapped', 'Owner', 'User', 'Permissions', 'EnabledByOwner', 'EnabledByUser', 'HiddenByOwner', 'HiddenByUser', 'TimestampCreated', 'TimestampUpdated')

SHARE_TYPES: Sequence[str] = ('token', 'map')

OUTPUT_TYPES: Sequence[str] = ('csv', 'json', 'txt')

API_HOOKS_V1: Sequence[str] = ('list', 'create', 'delete', 'update', 'hide', 'unhide', 'enable', 'disable')

API_SHARE_TOGGLES_V1: Sequence[str] = ('hide', 'unhide', 'enable', 'disable')

TOKEN_PATTERN_V1: str = "([a-zA-Z0-9_=\\-]{44})"


def load(configuration: "config.Configuration") -> "BaseSharing":
    """Load the sharing module chosen in configuration."""
    return utils.load_plugin(INTERNAL_TYPES, "sharing", "Sharing", BaseSharing, configuration)



class BaseSharing:

    configuration: "config.Configuration"
    _rights: rights.BaseRights

    def __init__(self, configuration: "config.Configuration") -> None:
        """Initialize Sharing.

        ``configuration`` see ``radicale.config`` module.
        The ``configuration`` must not change during the lifetime of
        this object, it is kept as an internal reference.

        """
        self.configuration = configuration
        self._rights = rights.load(configuration)
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

    def get_sharing_collection_by_map(self, path: str, user: str) -> [dict | None]:
        """ retrieve target and attributes by map """
        return None

    def get_sharing_list_by_type_user(self, share_type, user, path_token = None) -> [dict | None]:
        """ retrieve sharing list by type and user (path_token optional)"""
        return None

    def create_sharing_by_token(self, user: str, token: str, path_mapped: str, timestamp: int, permissions: str = "r", enabled: bool = True) -> bool:
        """ create sharing by token """
        return None

    def create_sharing_by_map(self, user: str, path_share: str, path_mapped: str, user_share: str, timestamp: int, permissions: str = "r", enabled: bool = True) -> bool:
        """ create sharing by token """
        return None

    def delete_sharing_by_token(self, user: str, token: str) -> [dict | None]:
        """ delete sharing by token """
        return None

    def delete_sharing_by_map(self, user: str, path_share: str, path_mapped: str, user_share: str) -> [dict | None]:
        """ delete sharing by token """
        return None

    def toggle_sharing_by_token(self, user: str, token: str, toggle: str, timestamp: int) -> [dict | None]:
        """ toggle sharing by token """
        return None

    def toggle_sharing_by_map(self, user: str, path_share: str, path_mapped: str, user_share: str, toggle: str, timestamp: int) -> [dict | None]:
        """ toggle sharing by map """
        return None


    ## static sharing functions
    def sharing_collection_resolver(self, path:str, user: str) -> [dict | None]:
        if self.sharing_collection_by_token:
            result = self.sharing_collection_by_token_resolver(path)
            if result is None:
                return result
            elif result["mapped"]:
                return result
        else:
            logger.debug("TRACE/sharing_by_token: not active")

        if self.sharing_collection_by_map:
            result = self.sharing_collection_by_map_resolver(path, user)
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
                pattern = re.compile('^/\\.token/v(\\d+)/' + TOKEN_PATTERN_V1 + '$')
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

    def sharing_collection_by_map_resolver(self, path: str, user: str) -> [dict | None]:
        """ returning dict with mapped-flag, path, user, rights or None if invalid"""
        if self.sharing_collection_by_map:
            logger.debug("TRACE/sharing_by_map: check path: %r", path)
            return self.get_sharing_collection_by_map(path, user)
        else:
            logger.debug("TRACE/sharing_by_map: not active")
            return {"mapped": False}

    ## POST API
    def post(self, environ: types.WSGIEnviron, base_prefix: str, path: str, user: str) -> types.WSGIResponse:
        """POST request.

        ``base_prefix`` is sanitized and never ends with "/".

        ``path`` is sanitized and always starts with "/.sharing"

        ``user`` is empty for anonymous users.

        Request:
            action: (token|map/list
                PathOrToken: <path|token> (optional for filter)

            action: (token|map)/create
                PathMapped: <path> (mandatory)
                Permissions: <permissions> (default: r)

                token -> returns <token>

                map
                    PathOrToken: <path> (mandatory)
                    User: <target_user> (mandatory)

            action: (token|map)/(delete|disable|enable|hide|unhide)
                PathOrToken: <path|token> (mandatory)

                token

                map
                    PathMapped: <path> (mandator)
                    User: <target_user>

        Response: output format depending on ACCEPT header
            action: list
                by user-owned filtered sharing list in CSV/JSON

            actions: (other)
                Status

        """
        if not self.sharing_collection_by_map and not self.sharing_collection_by_token:
            # API is not enabled
            return httputils.NOT_FOUND

        if user == "":
            # anonymous users are not allowed
            return httputils.NOT_ALLOWED

        # supported API version check
        if not path.startswith("/.sharing/v1/"):
            return httputils.NOT_FOUND

        # split into sharetype and action
        sharetype_action = path.removeprefix("/.sharing/v1/")
        match = re.search('([a-z]+)/([a-z]+)$', sharetype_action)
        if not match:
            logger.debug("TRACE/sharing/API: sharetype/action not extractable: %r", sharetype_action)
            return httputils.NOT_FOUND

        sharetype = match.group(1)
        action = match.group(2)

        # check for valid sharetypes
        if sharetype:
            if not sharetype in SHARE_TYPES:
                logger.debug("TRACE/sharing/API: sharetype not whitelisted: %r", sharetype)
                return httputils.NOT_FOUND

        # check for enabled sharetypes
        if not self.sharing_collection_by_map and sharetype == "map":
            # API is not enabled
            return httputils.NOT_FOUND

        if not self.sharing_collection_by_token and sharetype == "token":
            # API is not enabled
            return httputils.NOT_FOUND

        # check for valid API hooks
        if not action in API_HOOKS_V1:
            logger.debug("TRACE/sharing/API: action not whitelisted: %r", action)
            return httputils.NOT_FOUND

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

        api_info = "sharing/API/POST/" + sharetype + "/" + action

        # parse body according to content-type
        content_type = environ.get("CONTENT_TYPE", "")
        if 'application/json' in content_type:
            try:
                request_data = json.loads(request_body)
            except json.JSONDecodeError:
                return httputils.BAD_REQUEST
            logger.debug("TRACE/" + api_info + " (json): %r", f"{request_data}")
        elif 'application/x-www-form-urlencoded' in content_type:
            request_parsed = parse_qs(request_body)
            # convert arrays into single value
            request_data = {}
            for key in request_parsed:
                request_data[key] = request_parsed[key][0]
            logger.debug("TRACE/" + api_info + " (form): %r", f"{request_data}")
        else:
            logger.debug("TRACE/" + api_info + ": no supported content data")
            return httputils.BAD_REQUEST

        ## sanity checks
        for key in request_data:
            if key == "permissions":
                if not re.search('^[a-zA-Z]+$', request_data[key]):
                    return httputils.BAD_REQUEST
            if key == "token":
                if not re.search('^' + TOKEN_PATTERN_V1 + '$', request_data[key]):
                    return httputils.BAD_REQUEST

        ## check for requested output type
        accept = environ.get("ACCEPT", "")
        if 'application/json' in accept:
            output_format = "json"
        elif 'text/csv' in accept:
            output_format = "csv"
        else:
            output_format = "txt"

        if output_format == "csv":
            if not action == "list":
                return httputils.BAD_REQUEST
        elif output_format == "json":
            pass
        elif output_format == "txt":
            pass
        else:
            return httputils.BAD_REQUEST

        answer: dict = {}
        timestamp = int((datetime.now() - datetime(1970, 1, 1)).total_seconds())

        ## action: list
        if action == "list":
            logger.debug("TRACE/" + api_info + ": start")
            path_token_filter = None
            if 'PathOrToken' in request_data:
                path_token_filter = request_data['PathOrToken']
                logger.debug("TRACE/" + api_info + ": filter: %r", path_token_filter)
            result = self.get_sharing_list_by_type_user(sharetype, user, path_token_filter)
            if not result:
                answer['Lines'] = 0
                answer['Status'] = "not-found"
            else:
                answer['Lines'] = len(result)
                answer['Status'] = "success"
            answer['Content'] = result

        ## action: create
        elif action == "create":
            logger.debug("TRACE/" + api_info + ": start")
            if not 'PathMapped' in request_data:
                logger.warning(api_info + ": missing PathMapped")
                return httputils.BAD_REQUEST
            else:
                path_mapped = request_data['PathMapped']

            if not 'Permissions' in request_data:
                permissions = "r"
            else:
                permissions = request_data['Permissions']

            if not 'EnabledByOwner' in request_data:
                enabled = True
            else:
                enabled = config._convert_to_bool(request_data['EnabledByOwner'])

            if sharetype == "token":
                # check access permissions
                access = Access(self._rights, user, path_mapped)
                if not access.check("r") and "i" not in access.permissions:
                    logger.info("Add sharing-by-token: access to %r not allowed for user %r", path_mapped, user)
                    return httputils.NOT_ALLOWED

                ## v1: create uuid token with 2x 32 bytes = 256 bit
                token = "v1/" + str(base64.urlsafe_b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes), 'utf-8')

                logger.debug("TRACE/" + api_info + ": %r (permissions=%r token=%r)", path_mapped, permissions, token)

                if not self.create_sharing_by_token(user, token, path_mapped, timestamp, permissions, enabled):
                    logger.info("Add sharing-by-token: %r by user %s not successful", path_mapped, user)
                    return httputils.BAD_REQUEST

                logger.info(api_info + "(success): %r (permissions=%r token=%r)", path_mapped, permissions, token)

                answer['Status'] = "success"
                answer['PathOrToken'] = token

            elif sharetype == "map":
                if 'User' not in request_data:
                    logger.warning(api_info + ": missing User")
                    return httputils.BAD_REQUEST
                else:
                    user_share = request_data['User']

                if 'PathOrToken' not in request_data:
                    logger.warning(api_info + ": missing PathOrToken")
                    return httputils.BAD_REQUEST
                else:
                    path_share = request_data['PathOrToken']

                # check access permissions
                access = Access(self._rights, user, path_mapped)
                if not access.check("r") and "i" not in access.permissions:
                    logger.info("Add sharing-by-map: access to %r not allowed for user %r", path_mapped, user)
                    return httputils.NOT_ALLOWED

                logger.debug("TRACE/" + api_info + ": %r (permissions=%r path_share=%r user=%r)", path_mapped, permissions, path_share, user_share)
                if not self.create_sharing_by_map(user, path_share, path_mapped, user_share, timestamp, permissions, enabled):
                    logger.info("Add sharing-by-token: %r by user %s not successful", path_mapped, user)
                    return httputils.BAD_REQUEST

                answer['Status'] = "success"

        ## action: delete
        elif action == "delete":
            logger.debug("TRACE/" + api_info + ": start")

            if not 'PathOrToken' in request_data:
                logger.warning(api_info + ": missing PathOrToken")
                return httputils.BAD_REQUEST

            if sharetype == "token":
                result = self.delete_sharing_by_token(user, request_data['PathOrToken'])

            elif sharetype == "map":
                if not 'User' in request_data:
                    logger.warning(api_info + ": missing User")
                    return httputils.BAD_REQUEST

                if not 'PathOrToken' in request_data:
                    logger.warning(api_info + ": missing PathOrToken")
                    return httputils.BAD_REQUEST

                result = self.delete_sharing_by_map(user, request_data['PathOrToken'], request_data['PathMapped'], request_data['User'])

            ## result handling
            if result['status'] == "not-found":
                return httputils.NOT_FOUND
            elif result['status'] == "permission-denied":
                return httputils.NOT_ALLOWED
            elif result['status'] == "success":
                answer['Status'] = "success"
                pass
            else:
                if sharetype == "token":
                    logger.info("Delete sharing-by-token: %r of user %r not successful", token, user)
                elif sharetype == "map":
                    logger.info("Delete sharing-by-map: %r of user %r not successful", request_data['PathOrToken'], request_data['User'])
                return httputils.BAD_REQUEST

        ## action: TOGGLE
        elif action in API_SHARE_TOGGLES_V1:
            logger.debug("TRACE/sharing/API/POST/" + action)

            if sharetype == "token":
                if not 'PathOrToken' in request_data:
                    logger.warning(api_info + ": missing PathOrToken")
                    return httputils.BAD_REQUEST

                result = self.toggle_sharing_by_token(user, request_data['PathOrToken'], action, timestamp)

            elif sharetype == "map":
                if 'User' not in request_data:
                    logger.warning(api_info + ": missing User")
                    return httputils.BAD_REQUEST

                if 'PathOrToken' not in request_data:
                    logger.warning(api_info + ": missing PathOrToken")
                    return httputils.BAD_REQUEST

                result = self.toggle_sharing_by_map(user, request_data['PathOrToken'], request_data['PathMapped'], request_data['User'], action, timestamp)

            if result:
                if result['status'] == "not-found":
                    return httputils.NOT_FOUND
                if result['status'] == "permission-denied":
                    return httputils.NOT_ALLOWED
                elif result['status'] == "success":
                    answer['Status'] = "success"
                    pass
            else:
                if sharetype == "token":
                    logger.info("Delete sharing-by-token: %r of user %s not successful", request_data['PathOrToken'], user)
                elif sharetype == "map":
                    logger.info("Delete sharing-by-map: %r of user %s not successful", request_data['PathOrToken'], user)
                return httputils.BAD_REQUEST

        else:
            # default
            return httputils.BAD_REQUEST

        # output handler
        logger.debug("TRACE/sharing/API/POST output format: %r", output_format)
        if output_format == "csv" or output_format == "txt":
            answer_array = []
            for key in answer:
                if key != 'Content':
                    answer_array.append('# ' + key + '=' + str(answer[key]))
            if 'Content' in answer and answer['Content'] is not None:
                csv = io.StringIO()
                writer = DictWriter(csv, fieldnames=DB_FIELDS)
                if output_format == "csv":
                    writer.writeheader()
                for entry in answer['Content']:
                    writer.writerow(entry)
                answer_array.append(csv.getvalue())
            headers = {
                "Content-Type": "text/csv"
            }
            return client.OK, headers, "\n".join(answer_array), None
        elif output_format == "json":
            answer = json.dumps(answer)
            headers = {
                "Content-Type": "text/json"
            }
            return client.OK, headers, answer, None
        else:
            # should not be reached
            return httputils.BAD_REQUEST

        return httputils.METHOD_NOT_ALLOWED
