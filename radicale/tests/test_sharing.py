# This file is part of Radicale - CalDAV and CardDAV server
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

"""
Radicale tests related to sharing.

"""

import json
import logging
import os
import re
from typing import Sequence, Union

from radicale import sharing
from radicale.tests import BaseTest
from radicale.tests.helpers import get_file_content


class TestSharingApiSanity(BaseTest):
    """Tests with sharing."""

    htpasswd_file_path: str

    # Setup
    def setup_method(self) -> None:
        BaseTest.setup_method(self)
        self.htpasswd_file_path = os.path.join(self.colpath, ".htpasswd")
        encoding: str = self.configuration.get("encoding", "stock")
        htpasswd_content = "owner:ownerpw\nuser:userpw"
        with open(self.htpasswd_file_path, "w", encoding=encoding) as f:
            f.write(htpasswd_content)

    # Helper functions
    def _sharing_api(self, sharing_type: str, action: str, check: int, login: Union[str | None], data: str, content_type: str, accept_type: Union[str | None]):
        path_base = "/.sharing/v1/" + sharing_type + "/"
        _, headers, answer = self.request("POST", path_base + action, check=check, login=login, data=data, content_type=content_type, accept=accept_type)
        logging.debug("received answer:\n%s", "\n".join(answer.splitlines()))
        return _, headers, answer

    def _sharing_api_form(self, sharing_type: str, action: str, check: int, login: Union[str | None], form_array: Sequence[str], accept_type: Union[str | None] = None):
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        if accept_type is None:
            accept_type = "text/plain"
        _, headers, answer = self._sharing_api(sharing_type, action, check, login, data, content_type, accept_type)
        return _, headers, answer

    def _sharing_api_json(self, sharing_type: str, action: str, check: int, login: Union[str | None], json_dict: dict, accept_type: Union[str | None] = None):
        data = json.dumps(json_dict)
        content_type = "application/json"
        if accept_type is None:
            accept_type = "application/json"
        _, headers, answer = self._sharing_api(sharing_type, action, check, login, data, content_type, accept_type)
        if check == 200 and accept_type == "application/json":
            answer = json.loads(answer)
        return _, headers, answer

    # Test functions
    def test_sharing_api_base_no_auth(self) -> None:
        """POST request at '/.sharing' without authentication."""
        # disabled
        for path in ["/.sharing", "/.sharing/"]:
            _, headers, _ = self.request("POST", path, check=404)
        # enabled (permutations)
        self.configure({"sharing": {
                                    "collection_by_map": "True",
                                    "collection_by_token": "False"}
                        })
        path = "/.sharing/"
        _, headers, _ = self.request("POST", path, check=401)
        self.configure({"sharing": {
                                    "collection_by_map": "False",
                                    "collection_by_token": "True"}
                        })
        path = "/.sharing/"
        _, headers, _ = self.request("POST", path, check=401)
        self.configure({"sharing": {
                                    "collection_by_map": "True",
                                    "collection_by_token": "True"}
                        })
        path = "/.sharing/"
        _, headers, _ = self.request("POST", path, check=401)

    def test_sharing_api_base_with_auth(self) -> None:
        """POST request at '/.sharing' with authentication."""
        self.configure({"auth": {"type": "htpasswd",
                                 "htpasswd_filename": self.htpasswd_file_path,
                                 "htpasswd_encryption": "plain"},
                        "sharing": {
                                    "collection_by_map": "True",
                                    "collection_by_token": "True"},
                        "rights": {"type": "owner_only"}})

        # path with no valid API hook
        for path in ["/.sharing/", "/.sharing/v9/"]:
            _, headers, _ = self.request("POST", path, check=404, login="%s:%s" % ("owner", "ownerpw"))
        # path with valid API but no hook
        for path in ["/.sharing/v1/"]:
            _, headers, _ = self.request("POST", path, check=404, login="%s:%s" % ("owner", "ownerpw"))
        # path with valid API and hook but not enabled "map"
        self.configure({"sharing": {
                                    "collection_by_map": "False",
                                    "collection_by_token": "True"}
                        })
        sharetype = "map"
        for action in sharing.API_HOOKS_V1:
            path = "/.sharing/v1/" + sharetype + "/" + action
            _, headers, _ = self.request("POST", path, check=404, login="%s:%s" % ("owner", "ownerpw"))
        # path with valid API and hook but not enabled "token"
        self.configure({"sharing": {
                                    "collection_by_map": "True",
                                    "collection_by_token": "False"}
                        })
        sharetype = "token"
        for action in sharing.API_HOOKS_V1:
            path = "/.sharing/v1/" + sharetype + "/" + action
            _, headers, _ = self.request("POST", path, check=404, login="%s:%s" % ("owner", "ownerpw"))
        # path with valid API and hook and all enabled
        self.configure({"sharing": {
                                    "collection_by_map": "True",
                                    "collection_by_token": "True"}
                        })
        for sharetype in sharing.SHARE_TYPES:
            path = "/.sharing/v1/" + sharetype + "/" + action
            # invalid API
            _, headers, _ = self.request("POST", path + "NA", check=404, login="%s:%s" % ("owner", "ownerpw"))
            #  valid API
            _, headers, _ = self.request("POST", path, check=400, login="%s:%s" % ("owner", "ownerpw"))

    def test_sharing_api_list_with_auth(self) -> None:
        """POST/list with authentication."""
        self.configure({"auth": {"type": "htpasswd",
                                 "htpasswd_filename": self.htpasswd_file_path,
                                 "htpasswd_encryption": "plain"},
                        "sharing": {
                                    "collection_by_map": "True",
                                    "collection_by_token": "True"},
                        "logging": {"request_header_on_debug": "true"},
                        "rights": {"type": "owner_only"}})

        form_array: Sequence[str]
        json_dict: dict

        action = "list"
        for sharing_type in sharing.SHARE_TYPES:
            logging.debug("*** list (without form) -> should fail")
            path = "/.sharing/v1/" + sharing_type + "/" + action
            _, headers, _ = self.request("POST", path, check=400, login="%s:%s" % ("owner", "ownerpw"))

            logging.debug("*** list (form->csv)")
            form_array = []
            _, headers, answer = self._sharing_api_form(sharing_type, "list", 200, "owner:ownerpw", form_array)
            assert "Status=not-found" in answer
            assert "Lines=0" in answer

            logging.debug("*** list (json->text)")
            json_dict = {}
            _, headers, answer = self._sharing_api_json(sharing_type, "list", 200, "owner:ownerpw", json_dict, "text/plain")
            logging.debug("received answer %r", answer)
            assert "Status=not-found" in answer
            assert "Lines=0" in answer

            logging.debug("*** list (json->json)")
            json_dict = {}
            _, headers, answer = self._sharing_api_json(sharing_type, "list", 200, "owner:ownerpw", json_dict)
            assert answer['Status'] == "not-found"
            assert answer['Lines'] == 0
            assert answer['Content'] is None

    def test_sharing_api_token_basic(self) -> None:
        """share-by-token API tests."""
        self.configure({"auth": {"type": "htpasswd",
                                 "htpasswd_filename": self.htpasswd_file_path,
                                 "htpasswd_encryption": "plain"},
                        "sharing": {
                                    "type": "csv",
                                    "collection_by_map": "True",
                                    "collection_by_token": "True"},
                        "logging": {"request_header_on_debug": "False",
                                    "request_content_on_debug": "True"},
                        "rights": {"type": "owner_only"}})

        form_array: Sequence[str]
        json_dict: dict

        logging.debug("*** create token without PathMapped (form) -> should fail")
        form_array = []
        _, headers, answer = self._sharing_api_form("token", "create", 400, "owner:ownerpw", form_array)

        logging.debug("*** create token without PathMapped (json) -> should fail")
        json_dict = {}
        _, headers, answer = self._sharing_api_json("token", "create", 400, "owner:ownerpw", json_dict)

        logging.debug("*** create token#1 (form->text)")
        form_array = ["PathMapped=/owner/collection1"]
        _, headers, answer = self._sharing_api_form("token", "create", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "PathOrToken=" in answer
        # extract token
        match = re.search('PathOrToken=(.+)', answer)
        if match:
            token1 = match.group(1)
            logging.debug("received token %r", token1)
        else:
            assert False

        logging.debug("*** create token#2 (json->text)")
        json_dict = {'PathMapped': "/owner/collection2"}
        _, headers, answer = self._sharing_api_json("token", "create", 200, "owner:ownerpw", json_dict, "text/plain")
        assert "Status=success" in answer
        assert "Token=" in answer
        # extract token
        match = re.search('Token=(.+)', answer)
        if match:
            token2 = match.group(1)
            logging.debug("received token %r", token2)
        else:
            assert False

        logging.debug("*** lookup token#1 (form->text)")
        form_array = ["PathOrToken=" + token1]
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "Lines=1" in answer
        assert "/owner/collection1" in answer

        logging.debug("*** lookup token#2 (json->text")
        json_dict = {'PathOrToken': token2}
        _, headers, answer = self._sharing_api_json("token", "list", 200, "owner:ownerpw", json_dict, "text/plain")
        assert "Status=success" in answer
        assert "Lines=1" in answer
        assert "/owner/collection2" in answer

        logging.debug("*** lookup token#2 (json->json)")
        json_dict = {'PathOrToken': token2}
        _, headers, answer = self._sharing_api_json("token", "list", 200, "owner:ownerpw", json_dict)
        assert "success" in answer['Status']
        assert answer['Lines'] == 1
        assert "/owner/collection2" in answer['Content'][0]['PathMapped']

        logging.debug("*** lookup tokens (form->text)")
        form_array = []
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "Lines=2" in answer
        assert "/owner/collection1" in answer
        assert "/owner/collection2" in answer

        logging.debug("*** lookup tokens (form->csv)")
        form_array = []
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array, "text/csv")
        assert "Status=success" not in answer
        assert "Lines=2" not in answer
        assert ",".join(sharing.DB_FIELDS_V1) in answer
        assert "/owner/collection1" in answer
        assert "/owner/collection2" in answer

        logging.debug("*** delete token#1 (form->text)")
        form_array = ["PathOrToken=" + token1]
        _, headers, answer = self._sharing_api_form("token", "delete", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer

        logging.debug("*** lookup token#1 (form->text) -> should not be there anymore")
        form_array = ["PathOrToken=" + token1]
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array)
        assert "Status=not-found" in answer
        assert "Lines=0" in answer

        logging.debug("*** lookup tokens (form->text) -> still one should be there")
        form_array = []
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "Lines=1" in answer

        logging.debug("*** disable token#2 (form->text)")
        form_array = ["PathOrToken=" + token2]
        _, headers, answer = self._sharing_api_form("token", "disable", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer

        logging.debug("*** lookup token#2 (json->json) -> check for not enabled")
        json_dict = {'PathOrToken': token2}
        _, headers, answer = self._sharing_api_json("token", "list", 200, "owner:ownerpw", json_dict)
        assert answer['Status'] == "success"
        assert answer['Lines'] == 1
        assert answer['Content'][0]['EnabledByOwner'] == str(False)

        logging.debug("*** enable token#2 (json->json)")
        json_dict = {}
        json_dict['PathOrToken'] = token2
        _, headers, answer = self._sharing_api_json("token", "enable", 200, "owner:ownerpw", json_dict)
        assert answer['Status'] == "success"

        logging.debug("*** lookup token#2 (form->text) -> check for enabled")
        form_array = []
        form_array.append("PathOrToken=" + token2)
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "Lines=1" in answer
        assert "True,True,True,True" in answer

        logging.debug("*** hide token#2 (form->text)")
        form_array = []
        form_array.append("PathOrToken=" + token2)
        _, headers, answer = self._sharing_api_form("token", "hide", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer

        logging.debug("*** lookup token#2 (form->text) -> check for hidden")
        form_array = []
        form_array.append("PathOrToken=" + token2)
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "Lines=1" in answer
        assert "True,True,True,True" in answer

        logging.debug("*** unhide token#2 (json->json)")
        json_dict = {}
        json_dict['PathOrToken'] = token2
        _, headers, answer = self._sharing_api_json("token", "unhide", 200, "owner:ownerpw", json_dict)
        assert answer['Status'] == "success"

        logging.debug("*** lookup token#2 (json->json) -> check for not hidden")
        json_dict = {}
        json_dict['PathOrToken'] = token2
        _, headers, answer = self._sharing_api_json("token", "list", 200, "owner:ownerpw", json_dict)
        assert answer['Status'] == "success"
        assert answer['Lines'] == 1
        assert answer['Content'][0]['HiddenByOwner'] == str(False)

        logging.debug("*** delete token#2 (json->json)")
        json_dict = {}
        json_dict['PathOrToken'] = token2
        _, headers, answer = self._sharing_api_json("token", "delete", 200, "owner:ownerpw", json_dict)
        assert answer['Status'] == "success"

        logging.debug("*** lookup token#2 (json->json) -> should not be there anymore")
        json_dict = {}
        json_dict['PathOrToken'] = token2
        _, headers, answer = self._sharing_api_json("token", "list", 200, "owner:ownerpw", json_dict)
        assert answer['Status'] == "not-found"
        assert answer['Lines'] == 0

    def test_sharing_api_token_usage(self) -> None:
        """share-by-token API tests - real usage."""
        self.configure({"auth": {"type": "htpasswd",
                                 "htpasswd_filename": self.htpasswd_file_path,
                                 "htpasswd_encryption": "plain"},
                        "sharing": {
                                    "type": "csv",
                                    "collection_by_map": "True",
                                    "collection_by_token": "True"},
                        "logging": {"request_header_on_debug": "False",
                                    "request_content_on_debug": "True"},
                        "rights": {"type": "owner_only"}})

        form_array: Sequence[str]
        json_dict: dict

        path_token = "/.token/"

        logging.debug("*** prepare and test access")
        self.mkcalendar("/owner/calendar.ics/", login="%s:%s" % ("owner", "ownerpw"))
        event = get_file_content("event1.ics")
        path = "/owner/calendar.ics/event1.ics"
        self.put(path, event, login="%s:%s" % ("owner", "ownerpw"))
        _, headers, answer = self.request("GET", path, check=200, login="%s:%s" % ("owner", "ownerpw"))

        logging.debug("*** create token")
        form_array = []
        form_array.append("PathMapped=/owner/calendar.ics")
        _, headers, answer = self._sharing_api_form("token", "create", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "PathOrToken=" in answer
        # extract token
        match = re.search('PathOrToken=(.+)', answer)
        if match:
            token = match.group(1)
            logging.debug("received token %r", token)
        else:
            assert False

        logging.debug("*** enable token (form->text)")
        form_array = ["PathOrToken=" + token]
        _, headers, answer = self._sharing_api_form("token", "enable", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer

        logging.debug("*** fetch collection using invalid token (without credentials)")
        _, headers, answer = self.request("GET", path_token + "v1/invalidtoken", check=401)

        logging.debug("*** fetch collection using token (without credentials)")
        _, headers, answer = self.request("GET", path_token + token, check=200)
        assert "UID:event" in answer

        logging.debug("*** disable token (form->text)")
        form_array = ["PathOrToken=" + token]
        _, headers, answer = self._sharing_api_form("token", "disable", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer

        logging.debug("*** fetch collection using disabled token (without credentials)")
        _, headers, answer = self.request("GET", path_token + token, check=401)

        logging.debug("*** enable token (form->text)")
        form_array = ["PathOrToken=" + token]
        _, headers, answer = self._sharing_api_form("token", "enable", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer

        logging.debug("*** fetch collection using token (without credentials)")
        _, headers, answer = self.request("GET", path_token + token, check=200)
        assert "UID:event" in answer

        logging.debug("*** delete token (json->json)")
        json_dict = {'PathOrToken': token}
        _, headers, answer = self._sharing_api_json("token", "delete", 200, "owner:ownerpw", json_dict)
        assert answer['Status'] == "success"

        logging.debug("*** fetch collection using deleted token (without credentials)")
        _, headers, answer = self.request("GET", path_token + token, check=401)

    def test_sharing_api_map_basic(self) -> None:
        """share-by-map API basic tests."""
        self.configure({"auth": {"type": "htpasswd",
                                 "htpasswd_filename": self.htpasswd_file_path,
                                 "htpasswd_encryption": "plain"},
                        "sharing": {
                                    "type": "csv",
                                    "collection_by_map": "True",
                                    "collection_by_token": "True"},
                        "logging": {"request_header_on_debug": "False",
                                    "request_content_on_debug": "True"},
                        "rights": {"type": "owner_only"}})

        json_dict: dict

        logging.debug("*** create map without PathMapped (json) -> should fail")
        json_dict = {}
        _, headers, answer = self._sharing_api_json("map", "create", 400, "owner:ownerpw", json_dict)

        logging.debug("*** create map without PathMapped but User (json) -> should fail")
        json_dict = {'User': "user"}
        _, headers, answer = self._sharing_api_json("map", "create", 400, "owner:ownerpw", json_dict)

        logging.debug("*** create map without PathMapped but User and PathOrToken (json) -> should fail")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathOrToken'] = "/owner/calendar.ics"
        _, headers, answer = self._sharing_api_json("map", "create", 400, "owner:ownerpw", json_dict)

    def test_sharing_api_map_usage(self) -> None:
        """share-by-map API usage tests."""
        self.configure({"auth": {"type": "htpasswd",
                                 "htpasswd_filename": self.htpasswd_file_path,
                                 "htpasswd_encryption": "plain"},
                        "sharing": {
                                    "type": "csv",
                                    "collection_by_map": "True",
                                    "collection_by_token": "True"},
                        "logging": {"request_header_on_debug": "False",
                                    "request_content_on_debug": "True"},
                        "rights": {"type": "owner_only"}})

        json_dict: dict

        path_share = "/user/calendar-shared-by-owner.ics"
        path_mapped = "/owner/calendar.ics"

        logging.debug("*** prepare and test access")
        self.mkcalendar(path_mapped, login="%s:%s" % ("owner", "ownerpw"))
        event = get_file_content("event1.ics")
        path = path_mapped + "/event1.ics"
        self.put(path, event, login="%s:%s" % ("owner", "ownerpw"))

        logging.debug("*** create map with PathMapped and User and PathOrToken (json)")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = "/owner/calendar.ics"
        json_dict['PathOrToken'] = "/user/calendar-shared-by-owner.ics"
        _, headers, answer = self._sharing_api_json("map", "create", 200, "owner:ownerpw", json_dict)
        assert answer['Status'] == "success"

        logging.debug("*** lookup map without filter (json->json)")
        json_dict = {}
        _, headers, answer = self._sharing_api_json("map", "list", 200, "owner:ownerpw", json_dict)
        assert answer['Status'] == "success"
        assert answer['Lines'] == 1
        assert answer['Content'][0]['PathOrToken'] == path_share
        assert answer['Content'][0]['PathMapped'] == path_mapped
        assert answer['Content'][0]['ShareType'] == "map"
        assert answer['Content'][0]['Owner'] == "owner"
        assert answer['Content'][0]['User'] == "user"
        assert answer['Content'][0]['EnabledByOwner'] == str(False)
        assert answer['Content'][0]['EnabledByUser'] == str(False)
        assert answer['Content'][0]['HiddenByOwner'] == str(True)
        assert answer['Content'][0]['HiddenByUser'] == str(True)
        assert answer['Content'][0]['Permissions'] == "r"

        logging.debug("*** enable map by owner (json->json)")
        json_dict = {}
        json_dict['User'] = "owner"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "enable", 404, "owner:ownerpw", json_dict)

        logging.debug("*** enable map by owner for user (json->json)")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "enable", 200, "owner:ownerpw", json_dict)

        logging.debug("*** enable map by user (json->json)")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "enable", 200, "user:userpw", json_dict)
        assert answer['Status'] == "success"

        logging.debug("*** enable map by user for owner (json->json) -> should fail")
        json_dict = {}
        json_dict['User'] = "owner"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "enable", 403, "user:userpw", json_dict)

        logging.debug("*** fetch collection (without credentials)")
        _, headers, answer = self.request("GET", path_mapped, check=401)

        logging.debug("*** fetch collection (with credentials) as owner")
        _, headers, answer = self.request("GET", path_mapped, check=200, login="%s:%s" % ("owner", "ownerpw"))

        logging.debug("*** fetch collection (with credentials) as user")
        _, headers, answer = self.request("GET", path_mapped, check=403, login="%s:%s" % ("user", "userpw"))

        logging.debug("*** fetch collection via map (with credentials) as user")
        _, headers, answer = self.request("GET", path_share, check=200, login="%s:%s" % ("user", "userpw"))

        logging.debug("*** disable map by owner (json->json)")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = "/owner/calendar.ics"
        json_dict['PathOrToken'] = "/user/calendar-shared-by-owner.ics"
        _, headers, answer = self._sharing_api_json("map", "disable", 200, "owner:ownerpw", json_dict)
        assert answer['Status'] == "success"

        logging.debug("*** fetch collection via map (with credentials) as user -> n/a")
        _, headers, answer = self.request("GET", path_share, check=404, login="%s:%s" % ("user", "userpw"))

        logging.debug("*** enable map by owner (json->json)")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = "/owner/calendar.ics"
        json_dict['PathOrToken'] = "/user/calendar-shared-by-owner.ics"
        _, headers, answer = self._sharing_api_json("map", "enable", 200, "owner:ownerpw", json_dict)
        logging.debug("received answer %r", answer)
        assert answer['Status'] == "success"

        logging.debug("*** fetch collection via map (with credentials) as user")
        _, headers, answer = self.request("GET", path_share, check=200, login="%s:%s" % ("user", "userpw"))

        logging.debug("*** disable map by user (json->json)")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = "/owner/calendar.ics"
        json_dict['PathOrToken'] = "/user/calendar-shared-by-owner.ics"
        _, headers, answer = self._sharing_api_json("map", "disable", 200, "user:userpw", json_dict)
        assert answer['Status'] == "success"

        logging.debug("*** fetch collection via map (with credentials) as user -> n/a")
        _, headers, answer = self.request("GET", path_share, check=404, login="%s:%s" % ("user", "userpw"))

        logging.debug("*** delete map by user (json->json) -> fail")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = "/owner/calendar.ics"
        json_dict['PathOrToken'] = "/user/calendar-shared-by-owner.ics"
        _, headers, answer = self._sharing_api_json("map", "delete", 403, "user:userpw", json_dict)

        logging.debug("*** delete map by owner (json->json) -> ok")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = "/owner/calendar.ics"
        json_dict['PathOrToken'] = "/user/calendar-shared-by-owner.ics"
        _, headers, answer = self._sharing_api_json("map", "delete", 200, "owner:ownerpw", json_dict)
        assert answer['Status'] == "success"

        # TODO hide+unhide for REPORT
