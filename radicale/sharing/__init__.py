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
import posixpath
import re
import socket
import uuid
from csv import DictWriter
from datetime import datetime
from http import client
from typing import Sequence, Union
from urllib.parse import parse_qs

from radicale import config, httputils, pathutils, rights, types, utils
from radicale.log import logger

INTERNAL_TYPES: Sequence[str] = ("csv", "sqlite", "none")

DB_FIELDS_V1: Sequence[str] = ('ShareType', 'PathOrToken', 'PathMapped', 'Owner', 'User', 'Permissions', 'EnabledByOwner', 'EnabledByUser', 'HiddenByOwner', 'HiddenByUser', 'TimestampCreated', 'TimestampUpdated')
# ShareType:        <token|map>
# PathOrToken:      <path|token> [PrimaryKey]
# PathMapped:       <path>
# Owner:            <owner> (creator of database entry)
# User:             <user> (user of database entry)
# Permissions:      <radicale permission string>
# EnabledByOwner:   True|False (share status "invite/grant")
# EnabledByUser:    True|False (share status "accept") - check skipped of Owner==User
# HiddenByOwner:    True|False (share exposure controlled by owner)
# HiddenByUser:     True|False (share exposure controlled by user) - check skipped if Owner==User
# TimestampCreated: <unixtime> (when created)
# TimestampUpdated: <unixtime> (last update)

SHARE_TYPES: Sequence[str] = ('token', 'map', 'all')
# token: share by secret token (does not require authentication)
# map  : share by mapping collection of one user to another as virtual
# all  : only supported for "list" and "info"

OUTPUT_TYPES: Sequence[str] = ('csv', 'json', 'txt')

API_HOOKS_V1: Sequence[str] = ('list', 'create', 'delete', 'update', 'hide', 'unhide', 'enable', 'disable', 'info')
# list  : list sharings (optional filtered)
# create : create share by token or map
# delete : delete share
# update : update share
# hide   : hide share (by user or owner)
# unhide : unhide share (by user or owner)
# enable : hide share (by user or owner)
# disable: unhide share (by user or owner)
# info   : display support status and permissions

API_SHARE_TOGGLES_V1: Sequence[str] = ('hide', 'unhide', 'enable', 'disable')

TOKEN_PATTERN_V1: str = "(v1/[a-zA-Z0-9_=\\-]{44})"

PATH_PATTERN: str = "([a-zA-Z0-9/.\\-]+)"  # TODO: extend or find better source

USER_PATTERN: str = "([a-zA-Z0-9@]+)"  # TODO: extend or find better source


def load(configuration: "config.Configuration") -> "BaseSharing":
    """Load the sharing database module chosen in configuration."""
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
            logger.error("sharing database cannot be initialized: %r", e)
            exit(1)
        database_info = self.get_database_info()
        if database_info:
            logger.info("sharing database info: %r", database_info)
        else:
            logger.info("sharing database info: (not provided)")

    # overloadable functions
    def init_database(self) -> bool:
        """ initialize database """
        return False

    def get_database_info(self) -> Union[dict, None]:
        """ retrieve database information """
        return None

    def list_sharing(self,
                     ShareType: Union[str | None] = None,
                     PathOrToken: Union[str | None] = None,
                     PathMapped: Union[str | None] = None,
                     Owner: Union[str | None] = None,
                     User: Union[str | None] = None,
                     EnabledByOwner: Union[bool | None] = None,
                     EnabledByUser: Union[bool | None] = None,
                     HiddenByOwner: Union[bool | None] = None,
                     HiddenByUser:  Union[bool | None] = None) -> list[dict]:
        """ retrieve sharing """
        return []

    def get_sharing(self,
                    ShareType: str,
                    PathOrToken: str,
                    User: Union[str | None] = None) -> Union[dict | None]:
        """ retrieve sharing target and attributes by map """
        return {"status": "not-implemented"}

    def create_sharing(self,
                       ShareType: str,
                       PathOrToken: str, PathMapped: str,
                       Owner: str, User: str,
                       Permissions: str = "r",
                       EnabledByOwner: bool = False, EnabledByUser: bool = False,
                       HiddenByOwner:  bool = True, HiddenByUser:  bool = True,
                       Timestamp: int = 0) -> dict:
        """ create sharing """
        return {"status": "not-implemented"}

    def update_sharing(self,
                       ShareType: str,
                       PathOrToken: str,
                       Owner: str,
                       User: Union[str | None] = None,
                       PathMapped: Union[str | None] = None,
                       Permissions: Union[str | None] = None,
                       EnabledByOwner: Union[bool | None] = None,
                       HiddenByOwner:  Union[bool | None] = None,
                       Timestamp: int = 0) -> dict:
        """ update sharing """
        return {"status": "not-implemented"}

    def delete_sharing(self,
                       ShareType: str,
                       PathOrToken: str,
                       Owner: str,
                       PathMapped: Union[str | None] = None) -> dict:
        """ delete sharing """
        return {"status": "not-implemented"}

    def toggle_sharing(self,
                       ShareType: str,
                       PathOrToken: str,
                       OwnerOrUser: str,
                       Action: str,
                       PathMapped: Union[str | None] = None,
                       User: Union[str | None] = None,
                       Timestamp: int = 0) -> dict:
        """ toggle sharing """
        return {"status": "not-implemented"}

    # sharing functions called by request methods
    def sharing_collection_resolver(self, path: str, user: str) -> Union[dict | None]:
        """ returning dict with mapped-flag, PathMapped, Owner, Permissions or None if invalid"""
        if self.sharing_collection_by_token:
            result = self.sharing_collection_by_token_resolver(path)
            if result is None:
                return result
            elif result["mapped"]:
                return result
        else:
            logger.debug("TRACE/sharing_by_token: not active")
            return None

        if self.sharing_collection_by_map:
            result = self.sharing_collection_by_map_resolver(path, user)
            if result is None:
                return result
            elif result["mapped"]:
                return result
        else:
            logger.debug("TRACE/sharing_by_map: not active")
            return None

        # final
        return None

    # list active sharings of type "map"
    def sharing_collection_map_list(self, user: str) -> Union[dict | None]:
        """ returning dict with shared collections (enabled and unhidden) or None if invalid"""
        if not self.sharing_collection_by_map:
            logger.debug("TRACE/sharing_by_map: not active")
            return None

        # retrieve collections which are enabled and not hidden by owner+user
        shared_collection_list = self.list_sharing(
                ShareType="map",
                User=user,
                EnabledByOwner=True,
                EnabledByUser=True,
                HiddenByOwner=False,
                HiddenByUser=False)

        # final
        return shared_collection_list

    # internal sharing functions
    def sharing_collection_by_token_resolver(self, path) -> Union[dict | None]:
        """ returning dict with mapped-flag, PathMapped, Owner, Permissions or None if invalid"""
        if self.sharing_collection_by_token:
            logger.debug("TRACE/sharing_by_token: check path: %r", path)
            if path.startswith("/.token/"):
                pattern = re.compile('^/\\.token/' + TOKEN_PATTERN_V1 + '$')
                match = pattern.match(path)
                if not match:
                    logger.debug("TRACE/sharing_by_token: unsupported token: %r", path)
                    return None
                else:
                    # TODO add token validity checks
                    logger.debug("TRACE/sharing_by_token: supported token found in path: %r (token=%r)", path, match[1])
                    return self.get_sharing(
                            ShareType="token",
                            PathOrToken=match[1])
            else:
                logger.debug("TRACE/sharing_by_token: no supported prefix found in path: %r", path)
                return {"mapped": False}
        else:
            logger.debug("TRACE/sharing_by_token: not active")
            return {"mapped": False}

    def sharing_collection_by_map_resolver(self, path: str, user: str) -> Union[dict | None]:
        """ returning dict with mapped-flag, PathMapped, Owner, Permissions or None if invalid"""
        if self.sharing_collection_by_map:
            logger.debug("TRACE/sharing/resolver/map: check path: %r", path)
            result = self.get_sharing(
                    ShareType="map",
                    PathOrToken=path,
                    User=user)
            if result:
                return result
            else:
                # fallback to parent path
                parent_path = pathutils.parent_path(path)
                logger.debug("TRACE/sharing/resolver/map: check parent path: %r", parent_path)
                result = self.get_sharing(
                        ShareType="map",
                        PathOrToken=parent_path,
                        User=user)
                if result:
                    result['PathMapped'] = path.replace(parent_path, result['PathMapped'])
                    logger.debug("TRACE/sharing/resolver/map: PathMapped=%r Permissions=%r by parent_path=%r", result['PathMapped'], result['Permissions'], parent_path)
                    return result
                else:
                    logger.debug("TRACE/sharing_by_map: not found")
                    return {"mapped": False}
        else:
            logger.debug("TRACE/sharing_by_map: not active")
            return {"mapped": False}

    # POST API
    def post(self, environ: types.WSGIEnviron, base_prefix: str, path: str, user: str) -> types.WSGIResponse:
        #Late import to avoid circular dependency in config
        from radicale.app.base import Access
        
        """POST request.

        ``base_prefix`` is sanitized and never ends with "/".

        ``path`` is sanitized and always starts with "/.sharing"

        ``user`` is empty for anonymous users.

        Request:
            action: (token|map/list
                PathOrToken: <path|token> (optional for filter)

            action: (token|map)/create
                PathMapped: <path> (mandatory)
                Permissions: <Permissions> (default: r)

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
                by user-owned filtered sharing list in CSV/JSON/TEXT

            actions: (other)
                Status in JSON/TEXT (TEXT can be parsed by shell)

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

        # split into ShareType and action or "info"
        ShareType_action = path.removeprefix("/.sharing/v1/")
        match = re.search('([a-z]+)/([a-z]+)$', ShareType_action)
        if not match:
            logger.debug("TRACE/sharing/API: ShareType/action not extractable: %r", ShareType_action)
            return httputils.NOT_FOUND
        else:
            ShareType = match.group(1)
            action = match.group(2)

        # check for valid ShareTypes
        if ShareType:
            if ShareType not in SHARE_TYPES:
                logger.debug("TRACE/sharing/API: ShareType not whitelisted: %r", ShareType)
                return httputils.NOT_FOUND

        # check for enabled ShareTypes
        if not self.sharing_collection_by_map and ShareType == "map":
            # API "map" is not enabled
            return httputils.NOT_FOUND

        if not self.sharing_collection_by_token and ShareType == "token":
            # API "token" is not enabled
            return httputils.NOT_FOUND

        # check for valid API hooks
        if action not in API_HOOKS_V1:
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

        api_info = "sharing/API/POST/" + ShareType + "/" + action

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

        # check for requested output type
        accept = environ.get("HTTP_ACCEPT", "")
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

        # parameters default
        PathOrToken: Union[str | None] = None
        PathMapped: str
        Owner: str = user
        User: Union[str | None] = None
        Permissions: Union[str | None] = None  # no permissions by default
        EnabledByOwner: Union[bool | None] = None
        HiddenByOwner:  Union[bool | None] = None
        EnabledByUser:  Union[bool | None] = None
        HiddenByUser:   Union[bool | None] = None

        # parameters sanity check
        for key in request_data:
            if key == "Permissions":
                if not re.search('^[a-zA-Z]+$', request_data[key]):
                    return httputils.BAD_REQUEST
            elif key == "PathOrToken":
                if ShareType == "token":
                    if not re.search('^' + TOKEN_PATTERN_V1 + '$', request_data[key]):
                        logger.error(api_info + ": unsupported " + key)
                        return httputils.BAD_REQUEST
                elif ShareType == "map":
                    if not re.search('^' + PATH_PATTERN + '$', request_data[key]):
                        logger.error(api_info + ": unsupported " + key)
                        return httputils.BAD_REQUEST
            elif key == "PathMapped":
                if not re.search('^' + PATH_PATTERN + '$', request_data[key]):
                    logger.error(api_info + ": unsupported " + key)
                    return httputils.BAD_REQUEST
            elif key == "Enabled" or key == "Hidden":
                if not re.search('^(False|True)$', request_data[key]):
                    logger.error(api_info + ": unsupported " + key)
                    return httputils.BAD_REQUEST
            elif key == "User":
                if not re.search('^' + USER_PATTERN + '$', request_data[key]):
                    logger.error(api_info + ": unsupported " + key)
                    return httputils.BAD_REQUEST

        # check for mandatory parameters
        if 'PathMapped' not in request_data:
            if action == 'info':
                # ignored
                pass
            elif action =="list":
                # optional
                pass
            else:
                if ShareType == "token" and action != 'create':
                    # optional
                    pass
                else:
                    logger.error(api_info + ": missing PathMapped")
                    return httputils.BAD_REQUEST
        else:
            PathMapped = request_data['PathMapped']

        if 'PathOrToken' not in request_data:
            if action == 'info':
                # ignored
                pass
            elif action not in ['list', 'create']:
                logger.error(api_info + ": missing PathOrToken")
                return httputils.BAD_REQUEST
            else:
                # PathOrToken is optional
                pass
        else:
            if action == "create" and ShareType == "token":
                # not supported
                logger.error(api_info + ": PathOrToken found but not supported")
                return httputils.BAD_REQUEST
            PathOrToken = request_data['PathOrToken']

        if 'Permissions' in request_data:
            Permissions = request_data['Permissions']

        if ShareType == "map":
            if action == 'info':
                # ignored
                pass
            else:
                if 'User' not in request_data:
                    if action not in ['list', 'delete', 'update']:
                        logger.warning(api_info + ": missing User")
                        return httputils.BAD_REQUEST
                    else:
                        # optional
                        pass
                else:
                    User = request_data['User']

        answer: dict = {}
        result: dict = {}
        result_array: list[dict]
        answer['ApiVersion'] = "1"
        Timestamp = int((datetime.now() - datetime(1970, 1, 1)).total_seconds())

        # action: list
        if action == "list":
            logger.debug("TRACE/" + api_info + ": start")
            if 'PathOrToken' in request_data:
                PathOrToken = request_data['PathOrToken']
                logger.debug("TRACE/" + api_info + ": filter: %r", PathOrToken)

            if ShareType != "all":
                result_array = self.list_sharing(
                        ShareType=ShareType,
                        Owner=Owner,
                        PathOrToken=PathOrToken)
            else:
                result_array = self.list_sharing(
                        Owner=Owner,
                        PathOrToken=PathOrToken)

            answer['Lines'] = len(result_array)
            if len(result_array) == 0:
                answer['Status'] = "not-found"
            else:
                answer['Status'] = "success"
            answer['Content'] = result_array

        # action: create
        elif action == "create":
            logger.debug("TRACE/" + api_info + ": start")
            if 'Permissions' not in request_data:
                Permissions = "r"

            if 'Enabled' in request_data:
                EnabledByOwner = config._convert_to_bool(request_data['Enabled'])
            else:
                EnabledByOwner = False # security by default

            if 'Hidden' in request_data:
                HiddenByOwner = config._convert_to_bool(request_data['Hidden'])
            else:
                HiddenByOwner = True # security by default

            EnabledByUser = False # security by default
            HiddenByUser = True # security by default

            if ShareType == "token":
                # check access Permissions
                access = Access(self._rights, user, PathMapped)
                if not access.check("r") and "i" not in access.permissions:
                    logger.info("Add sharing-by-token: access to %r not allowed for user %r", PathMapped, user)
                    return httputils.NOT_ALLOWED

                # v1: create uuid token with 2x 32 bytes = 256 bit
                token = "v1/" + str(base64.urlsafe_b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes), 'utf-8')

                logger.debug("TRACE/" + api_info + ": %r (Permissions=%r token=%r)", PathMapped, Permissions, token)

                result = self.create_sharing(
                        ShareType=ShareType,
                        PathOrToken=token, PathMapped=PathMapped,
                        Owner=Owner, User=Owner,
                        Permissions=Permissions,
                        EnabledByOwner=EnabledByOwner, HiddenByOwner=HiddenByOwner,
                        Timestamp=Timestamp)
                logger.debug("TRACE/" + api_info + ": result=%r", result)

            elif ShareType == "map":
                # check preconditions
                if PathOrToken is None:
                    return httputils.BAD_REQUEST
                else:
                    PathOrToken = str(PathOrToken)

                if User is None:
                    return httputils.BAD_REQUEST
                else:
                    User = str(User)

                # check access Permissions
                access = Access(self._rights, Owner, PathMapped)
                if not access.check("r") and "i" not in access.permissions:
                    logger.info("Add sharing-by-map: access to path(mapped) %r not allowed for owner %r", PathMapped, Owner)
                    return httputils.NOT_ALLOWED

                access = Access(self._rights, str(User), str(PathOrToken))
                if not access.check("r") and "i" not in access.permissions:
                    logger.info("Add sharing-by-map: access to path %r not allowed for user %r", PathOrToken, user)
                    return httputils.NOT_ALLOWED

                logger.debug("TRACE/" + api_info + ": %r (Permissions=%r PathOrToken=%r user=%r)", PathMapped, Permissions, PathOrToken, User)
                result = self.create_sharing(
                        ShareType=ShareType,
                        PathOrToken=PathOrToken,  # verification above that it is not None
                        PathMapped=PathMapped,
                        Owner=Owner,
                        User=User,  # verification above that it is not None
                        Permissions=Permissions,
                        EnabledByOwner=EnabledByOwner, HiddenByOwner=HiddenByOwner,
                        EnabledByUser=EnabledByUser, HiddenByUser=HiddenByUser,
                        Timestamp=Timestamp)

            else:
                logger.error(api_info + ": unsupported for ShareType=%r", ShareType)
                return httputils.BAD_REQUEST

            logger.debug("TRACE/" + api_info + ": result=%r", result)
            # result handling
            if result['status'] == "conflict":
                return httputils.CONFLICT
            elif result['status'] == "error":
                return httputils.INTERNAL_SERVER_ERROR
            elif result['status'] == "success":
                answer['Status'] = "success"
            else:
                return httputils.BAD_REQUEST

            if ShareType == "token":
                logger.info(api_info + "(success): %r (Permissions=%r token=%r)", PathMapped, Permissions, token)
                answer['PathOrToken'] = token

        # action: update 
        elif action == "update":
            logger.debug("TRACE/" + api_info + ": start")

            if PathOrToken is None:
                return httputils.BAD_REQUEST

            if ShareType == "token":
                result = self.update_sharing(
                       ShareType=ShareType,
                       PathMapped=PathMapped,
                       Permissions=Permissions,
                       EnabledByOwner=EnabledByOwner,
                       HiddenByOwner=HiddenByOwner,
                       PathOrToken=str(PathOrToken),  # verification above that it is not None
                       Owner=Owner)

            elif ShareType == "map":
                result = self.update_sharing(
                       ShareType=ShareType,
                       PathMapped=PathMapped,
                       Permissions=Permissions,
                       EnabledByOwner=EnabledByOwner,
                       HiddenByOwner=HiddenByOwner,
                       PathOrToken=str(PathOrToken),  # verification above that it is not None
                       Owner=Owner)

            else:
                logger.error(api_info + ": unsupported for ShareType=%r", ShareType)
                return httputils.BAD_REQUEST

            # result handling
            if result['status'] == "not-found":
                return httputils.NOT_FOUND
            elif result['status'] == "permission-denied":
                return httputils.NOT_ALLOWED
            elif result['status'] == "success":
                answer['Status'] = "success"
                pass
            else:
                if ShareType == "token":
                    logger.info("Update of sharing-by-token: %r not successful", request_data['PathOrToken'])
                elif ShareType == "map":
                    logger.info("Update of sharing-by-map: %r not successful", request_data['PathOrToken'])
                return httputils.BAD_REQUEST

        # action: delete
        elif action == "delete":
            logger.debug("TRACE/" + api_info + ": start")

            if PathOrToken is None:
                return httputils.BAD_REQUEST

            if ShareType == "token":
                result = self.delete_sharing(
                       ShareType=ShareType,
                       PathOrToken=str(PathOrToken),  # verification above that it is not None
                       Owner=Owner)

            elif ShareType == "map":
                result = self.delete_sharing(
                       ShareType=ShareType,
                       PathOrToken=str(PathOrToken),  # verification above that it is not None
                       PathMapped=PathMapped,
                       Owner=Owner)

            else:
                logger.error(api_info + ": unsupported for ShareType=%r", ShareType)
                return httputils.BAD_REQUEST

            # result handling
            if result['status'] == "not-found":
                return httputils.NOT_FOUND
            elif result['status'] == "permission-denied":
                return httputils.NOT_ALLOWED
            elif result['status'] == "success":
                answer['Status'] = "success"
                pass
            else:
                if ShareType == "token":
                    logger.info("Delete sharing-by-token: %r of user %r not successful", request_data['PathOrToken'], request_data['User'])
                elif ShareType == "map":
                    logger.info("Delete sharing-by-map: %r of user %r not successful", request_data['PathOrToken'], request_data['User'])
                return httputils.BAD_REQUEST

        # action: info
        elif action == "info":
            answer['Status'] = "success"
            if ShareType in ["all", "map"]:
                answer['FeatureEnabledCollectionByMap'] = self.sharing_collection_by_map;
                answer['PermittedCreateCollectionByMap'] = True # TODO toggle per permission, default?
            if ShareType in ["all", "token"]:
                answer['FeatureEnabledCollectionByToken'] = self.sharing_collection_by_token;
                answer['PermittedCreateCollectionByToken'] = True # TODO toggle per permission, default?

        # action: TOGGLE
        elif action in API_SHARE_TOGGLES_V1:
            logger.debug("TRACE/sharing/API/POST/" + action)

            if ShareType in ["token", "map"]:
                if PathOrToken is None:
                    return httputils.BAD_REQUEST

                result = self.toggle_sharing(
                       ShareType=ShareType,
                       PathOrToken=str(PathOrToken),  # verification above that it is not None
                       OwnerOrUser=user,  # authenticated user
                       User=User,         # provided user for selection
                       Action=action,
                       Timestamp=Timestamp)

                if result:
                    if result['status'] == "not-found":
                        return httputils.NOT_FOUND
                    if result['status'] == "permission-denied":
                        return httputils.NOT_ALLOWED
                    elif result['status'] == "success":
                        answer['Status'] = "success"
                        pass
                else:
                    logger.error("Toggle sharing: %r of user %s not successful", request_data['PathOrToken'], user)
                    return httputils.BAD_REQUEST

            else:
                logger.error(api_info + ": unsupported for ShareType=%r", ShareType)
                return httputils.BAD_REQUEST

        else:
            # default
            logger.error(api_info + ": unsupported action=%r", action)
            return httputils.BAD_REQUEST

        # output handler
        logger.debug("TRACE/sharing/API/POST output format: %r", output_format)
        logger.debug("TRACE/sharing/API/POST answer: %r", answer)
        if output_format == "csv" or output_format == "txt":
            answer_array = []
            if output_format == "txt":
                for key in answer:
                    if key != 'Content':
                        answer_array.append(key + '=' + str(answer[key]))
            if 'Content' in answer and answer['Content'] is not None:
                csv = io.StringIO()
                writer = DictWriter(csv, fieldnames=DB_FIELDS_V1)
                if output_format == "csv":
                    writer.writeheader()
                for entry in answer['Content']:
                    writer.writerow(entry)
                if output_format == "csv":
                    answer_array.append(csv.getvalue())
                else:
                    index = 0
                    for line in csv.getvalue().splitlines():
                        # create a shell array with content lines
                        answer_array.append('Content[' + str(index) + ']="' + line + '"')
                        index += 1
            headers = {
                "Content-Type": "text/csv"
            }
            return client.OK, headers, "\n".join(answer_array), None
        elif output_format == "json":
            answer_raw = json.dumps(answer)
            headers = {
                "Content-Type": "text/json"
            }
            return client.OK, headers, answer_raw, None
        else:
            # should not be reached
            return httputils.BAD_REQUEST

        return httputils.METHOD_NOT_ALLOWED
