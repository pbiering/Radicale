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
from typing import Dict, Sequence, Tuple, Union

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
        htpasswd = ["owner:ownerpw", "user:userpw",
                    "owner1:owner1pw", "user1:user1pw",
                    "owner2:owner2pw", "user2:user2pw"]
        htpasswd_content = "\n".join(htpasswd)
        with open(self.htpasswd_file_path, "w", encoding=encoding) as f:
            f.write(htpasswd_content)

    # Helper functions
    def _sharing_api(self, sharing_type: str, action: str, check: int, login: Union[str | None], data: str, content_type: str, accept_type: Union[str | None]) -> Tuple[int, Dict[str, str], str]:
        path_base = "/.sharing/v1/" + sharing_type + "/"
        _, headers, answer = self.request("POST", path_base + action, check=check, login=login, data=data, content_type=content_type, accept=accept_type)
        logging.info("received answer:\n%s", "\n".join(answer.splitlines()))
        return _, headers, answer

    def _sharing_api_form(self, sharing_type: str, action: str, check: int, login: Union[str | None], form_array: Sequence[str], accept_type: Union[str | None] = None) -> Tuple[int, Dict[str, str], str]:
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        if accept_type is None:
            accept_type = "text/plain"
        _, headers, answer = self._sharing_api(sharing_type, action, check, login, data, content_type, accept_type)
        return _, headers, answer

    def _sharing_api_json(self, sharing_type: str, action: str, check: int, login: Union[str | None], json_dict: dict, accept_type: Union[str | None] = None) -> Tuple[int, Dict[str, str], str]:
        data = json.dumps(json_dict)
        content_type = "application/json"
        if accept_type is None:
            accept_type = "application/json"
        _, headers, answer = self._sharing_api(sharing_type, action, check, login, data, content_type, accept_type)
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
            logging.info("\n*** list (without form) -> should fail")
            path = "/.sharing/v1/" + sharing_type + "/" + action
            _, headers, _ = self.request("POST", path, check=400, login="%s:%s" % ("owner", "ownerpw"))

            logging.info("\n*** list (form->csv)")
            form_array = []
            _, headers, answer = self._sharing_api_form(sharing_type, "list", 200, "owner:ownerpw", form_array)
            assert "Status=not-found" in answer
            assert "Lines=0" in answer

            logging.info("\n*** list (json->text)")
            json_dict = {}
            _, headers, answer = self._sharing_api_json(sharing_type, "list", 200, "owner:ownerpw", json_dict, "text/plain")
            assert "Status=not-found" in answer
            assert "Lines=0" in answer

            logging.info("\n*** list (json->json)")
            json_dict = {}
            _, headers, answer = self._sharing_api_json(sharing_type, "list", 200, "owner:ownerpw", json_dict)
            answer_dict = json.loads(answer)
            assert answer_dict['Status'] == "not-found"
            assert answer_dict['Lines'] == 0

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

        logging.info("\n*** create token without PathMapped (form) -> should fail")
        form_array = []
        _, headers, answer = self._sharing_api_form("token", "create", 400, "owner:ownerpw", form_array)

        logging.info("\n*** create token without PathMapped (json) -> should fail")
        json_dict = {}
        _, headers, answer = self._sharing_api_json("token", "create", 400, "owner:ownerpw", json_dict)

        logging.info("\n*** create token#1 (form->text)")
        form_array = ["PathMapped=/owner/collection1"]
        _, headers, answer = self._sharing_api_form("token", "create", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "PathOrToken=" in answer
        # extract token
        match = re.search('PathOrToken=(.+)', answer)
        if match:
            token1 = match.group(1)
            logging.info("received token %r", token1)
        else:
            assert False

        logging.info("\n*** create token#2 (json->text)")
        json_dict = {'PathMapped': "/owner/collection2"}
        _, headers, answer = self._sharing_api_json("token", "create", 200, "owner:ownerpw", json_dict, "text/plain")
        assert "Status=success" in answer
        assert "Token=" in answer
        # extract token
        match = re.search('Token=(.+)', answer)
        if match:
            token2 = match.group(1)
            logging.info("received token %r", token2)
        else:
            assert False

        logging.info("\n*** lookup token#1 (form->text)")
        form_array = ["PathOrToken=" + token1]
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "Lines=1" in answer
        assert "/owner/collection1" in answer

        logging.info("\n*** lookup token#2 (json->text")
        json_dict = {'PathOrToken': token2}
        _, headers, answer = self._sharing_api_json("token", "list", 200, "owner:ownerpw", json_dict, "text/plain")
        assert "Status=success" in answer
        assert "Lines=1" in answer
        assert "/owner/collection2" in answer

        logging.info("\n*** lookup token#2 (json->json)")
        json_dict = {'PathOrToken': token2}
        _, headers, answer = self._sharing_api_json("token", "list", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"
        assert answer_dict['Lines'] == 1
        assert answer_dict['Content'][0]['PathMapped'] == "/owner/collection2"

        logging.info("\n*** lookup tokens (form->text)")
        form_array = []
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "Lines=2" in answer
        assert "/owner/collection1" in answer
        assert "/owner/collection2" in answer

        logging.info("\n*** lookup tokens (form->csv)")
        form_array = []
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array, "text/csv")
        assert "Status=success" not in answer
        assert "Lines=2" not in answer
        assert ",".join(sharing.DB_FIELDS_V1) in answer
        assert "/owner/collection1" in answer
        assert "/owner/collection2" in answer

        logging.info("\n*** delete token#1 (form->text)")
        form_array = ["PathOrToken=" + token1]
        _, headers, answer = self._sharing_api_form("token", "delete", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer

        logging.info("\n*** lookup token#1 (form->text) -> should not be there anymore")
        form_array = ["PathOrToken=" + token1]
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array)
        assert "Status=not-found" in answer
        assert "Lines=0" in answer

        logging.info("\n*** lookup tokens (form->text) -> still one should be there")
        form_array = []
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "Lines=1" in answer

        logging.info("\n*** disable token#2 (form->text)")
        form_array = ["PathOrToken=" + token2]
        _, headers, answer = self._sharing_api_form("token", "disable", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer

        logging.info("\n*** lookup token#2 (json->json) -> check for not enabled")
        json_dict = {'PathOrToken': token2}
        _, headers, answer = self._sharing_api_json("token", "list", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"
        assert answer_dict['Lines'] == 1
        assert answer_dict['Content'][0]['EnabledByOwner'] == str(False)

        logging.info("\n*** enable token#2 (json->json)")
        json_dict = {}
        json_dict['PathOrToken'] = token2
        _, headers, answer = self._sharing_api_json("token", "enable", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        logging.info("\n*** lookup token#2 (form->text) -> check for enabled")
        form_array = []
        form_array.append("PathOrToken=" + token2)
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "Lines=1" in answer
        assert "True,True,True,True" in answer

        logging.info("\n*** hide token#2 (form->text)")
        form_array = []
        form_array.append("PathOrToken=" + token2)
        _, headers, answer = self._sharing_api_form("token", "hide", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer

        logging.info("\n*** lookup token#2 (form->text) -> check for hidden")
        form_array = []
        form_array.append("PathOrToken=" + token2)
        _, headers, answer = self._sharing_api_form("token", "list", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "Lines=1" in answer
        assert "True,True,True,True" in answer

        logging.info("\n*** unhide token#2 (json->json)")
        json_dict = {}
        json_dict['PathOrToken'] = token2
        _, headers, answer = self._sharing_api_json("token", "unhide", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        logging.info("\n*** lookup token#2 (json->json) -> check for not hidden")
        json_dict = {}
        json_dict['PathOrToken'] = token2
        _, headers, answer = self._sharing_api_json("token", "list", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"
        assert answer_dict['Lines'] == 1
        assert answer_dict['Content'][0]['HiddenByOwner'] == str(False)

        logging.info("\n*** delete token#2 (json->json)")
        json_dict = {}
        json_dict['PathOrToken'] = token2
        _, headers, answer = self._sharing_api_json("token", "delete", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        logging.info("\n*** lookup token#2 (json->json) -> should not be there anymore")
        json_dict = {}
        json_dict['PathOrToken'] = token2
        _, headers, answer = self._sharing_api_json("token", "list", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "not-found"
        assert answer_dict['Lines'] == 0

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
        path_base = "/owner/calendar.ics"

        logging.info("\n*** prepare")
        self.mkcalendar("/owner/calendar.ics/", login="%s:%s" % ("owner", "ownerpw"))
        event = get_file_content("event1.ics")
        path = path_base + "/event1.ics"
        self.put(path, event, login="%s:%s" % ("owner", "ownerpw"))

        logging.info("\n*** test access to collection")
        _, headers, answer = self.request("GET", path_base, check=200, login="%s:%s" % ("owner", "ownerpw"))
        assert "UID:event" in answer

        logging.info("\n*** test access to item")
        _, headers, answer = self.request("GET", path, check=200, login="%s:%s" % ("owner", "ownerpw"))
        assert "UID:event" in answer

        logging.info("\n*** create token")
        form_array = []
        form_array.append("PathMapped=/owner/calendar.ics")
        _, headers, answer = self._sharing_api_form("token", "create", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "PathOrToken=" in answer
        # extract token
        match = re.search('PathOrToken=(.+)', answer)
        if match:
            token = match.group(1)
            logging.info("received token %r", token)
        else:
            assert False

        logging.info("\n*** create token#2")
        form_array = []
        form_array.append("PathMapped=/owner/calendar2.ics")
        _, headers, answer = self._sharing_api_form("token", "create", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer
        assert "PathOrToken=" in answer
        # extract token
        match = re.search('PathOrToken=(.+)', answer)
        if match:
            token2 = match.group(1)
            logging.info("received token %r", token2)
        else:
            assert False

        logging.info("\n*** enable token (form->text)")
        form_array = ["PathOrToken=" + token]
        _, headers, answer = self._sharing_api_form("token", "enable", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer

        logging.info("\n*** fetch collection using invalid token (without credentials)")
        _, headers, answer = self.request("GET", path_token + "v1/invalidtoken", check=401)

        logging.info("\n*** fetch collection using token (without credentials)")
        _, headers, answer = self.request("GET", path_token + token, check=200)
        assert "UID:event" in answer

        logging.info("\n*** disable token (form->text)")
        form_array = ["PathOrToken=" + token]
        _, headers, answer = self._sharing_api_form("token", "disable", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer

        logging.info("\n*** fetch collection using disabled token (without credentials)")
        _, headers, answer = self.request("GET", path_token + token, check=401)

        logging.info("\n*** enable token (form->text)")
        form_array = ["PathOrToken=" + token]
        _, headers, answer = self._sharing_api_form("token", "enable", 200, "owner:ownerpw", form_array)
        assert "Status=success" in answer

        logging.info("\n*** fetch collection using token (without credentials)")
        _, headers, answer = self.request("GET", path_token + token, check=200)
        assert "UID:event" in answer

        logging.info("\n*** delete token#2 (json->json)")
        json_dict = {}
        json_dict['PathOrToken'] = token2
        _, headers, answer = self._sharing_api_json("token", "delete", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['ApiVersion'] == "1"
        assert answer_dict['Status'] == "success"

        logging.info("\n*** delete token (json->json)")
        json_dict = {'PathOrToken': token}
        _, headers, answer = self._sharing_api_json("token", "delete", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['ApiVersion'] == "1"
        assert answer_dict['Status'] == "success"

        logging.info("\n*** delete token (form->text) -> no longer available")
        form_array = ["PathOrToken=" + token]
        _, headers, answer = self._sharing_api_form("token", "delete", 404, "owner:ownerpw", form_array)

        logging.info("\n*** fetch collection using deleted token (without credentials)")
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

        logging.info("\n*** create map without PathMapped (json) -> should fail")
        json_dict = {}
        _, headers, answer = self._sharing_api_json("map", "create", 400, "owner:ownerpw", json_dict)

        logging.info("\n*** create map without PathMapped but User (json) -> should fail")
        json_dict = {'User': "user"}
        _, headers, answer = self._sharing_api_json("map", "create", 400, "owner:ownerpw", json_dict)

        logging.info("\n*** create map without PathMapped but User and PathOrToken (json) -> should fail")
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
                                    "request_content_on_debug": "False"},
                        "rights": {"type": "owner_only"}})

        json_dict: dict

        file_item1 = "event1.ics"
        file_item2 = "event2.ics"
        path_share = "/user/calendar-shared-by-owner.ics/"
        path_share_item1 = os.path.join(path_share, file_item1)
        path_share_item2 = os.path.join(path_share, file_item2)
        path_mapped = "/owner/calendar.ics/"
        path_mapped_item1 = os.path.join(path_mapped, file_item1)
        path_mapped_item2 = os.path.join(path_mapped, file_item2)

        logging.info("\n*** prepare and test access")
        self.mkcalendar(path_mapped, login="%s:%s" % ("owner", "ownerpw"))
        event = get_file_content(file_item1)
        self.put(path_mapped_item1, event, check=201, login="%s:%s" % ("owner", "ownerpw"))
        event = get_file_content(file_item2)
        self.put(path_mapped_item2, event, check=201, login="%s:%s" % ("owner", "ownerpw"))

        logging.info("\n*** test access to collection")
        _, headers, answer = self.request("GET", path_mapped, check=200, login="%s:%s" % ("owner", "ownerpw"))
        assert "UID:event1" in answer
        assert "UID:event2" in answer

        logging.info("\n*** test access to item")
        _, headers, answer = self.request("GET", path_mapped_item1, check=200, login="%s:%s" % ("owner", "ownerpw"))
        assert "UID:event1" in answer

        logging.info("\n*** create map with PathMapped and User and PathOrToken (json)")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "create", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        logging.info("\n*** lookup map without filter (json->json)")
        json_dict = {}
        _, headers, answer = self._sharing_api_json("map", "list", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"
        assert answer_dict['Lines'] == 1
        assert answer_dict['Content'][0]['PathOrToken'] == path_share
        assert answer_dict['Content'][0]['PathMapped'] == path_mapped
        assert answer_dict['Content'][0]['ShareType'] == "map"
        assert answer_dict['Content'][0]['Owner'] == "owner"
        assert answer_dict['Content'][0]['User'] == "user"
        assert answer_dict['Content'][0]['EnabledByOwner'] == str(False)
        assert answer_dict['Content'][0]['EnabledByUser'] == str(False)
        assert answer_dict['Content'][0]['HiddenByOwner'] == str(True)
        assert answer_dict['Content'][0]['HiddenByUser'] == str(True)
        assert answer_dict['Content'][0]['Permissions'] == "r"

        logging.info("\n*** enable map by owner (json->json)")
        json_dict = {}
        json_dict['User'] = "owner"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "enable", 404, "owner:ownerpw", json_dict)

        logging.info("\n*** enable map by owner for user (json->json)")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "enable", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        logging.info("\n*** enable map by user (json->json)")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "enable", 200, "user:userpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        logging.info("\n*** enable map by user for owner (json->json) -> should fail")
        json_dict = {}
        json_dict['User'] = "owner"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "enable", 403, "user:userpw", json_dict)

        logging.info("\n*** fetch collection (without credentials)")
        _, headers, answer = self.request("GET", path_mapped, check=401)

        logging.info("\n*** fetch collection (with credentials) as owner")
        _, headers, answer = self.request("GET", path_mapped, check=200, login="%s:%s" % ("owner", "ownerpw"))
        assert "UID:event" in answer

        logging.info("\n*** fetch item (with credentials) as owner")
        _, headers, answer = self.request("GET", path_mapped_item1, check=200, login="%s:%s" % ("owner", "ownerpw"))
        assert "UID:event" in answer

        logging.info("\n*** fetch collection (with credentials) as user")
        _, headers, answer = self.request("GET", path_mapped, check=403, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** fetch collection via map (with credentials) as user")
        _, headers, answer = self.request("GET", path_share, check=200, login="%s:%s" % ("user", "userpw"))
        assert "UID:event1" in answer
        assert "UID:event2" in answer

        logging.info("\n*** fetch item via map (with credentials) as user")
        _, headers, answer = self.request("GET", path_share_item1, check=200, login="%s:%s" % ("user", "userpw"))
        # only requested event has to be in the answer
        assert "UID:event1" in answer
        assert "UID:event2" not in answer

        logging.info("\n*** fetch item via map (with credentials) as user")
        _, headers, answer = self.request("GET", path_share_item2, check=200, login="%s:%s" % ("user", "userpw"))
        # only requested event has to be in the answer
        assert "UID:event2" in answer
        assert "UID:event1" not in answer

        logging.info("\n*** disable map by owner (json->json)")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "disable", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        logging.info("\n*** fetch collection via map (with credentials) as user -> n/a")
        _, headers, answer = self.request("GET", path_share, check=404, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** enable map by owner (json->json)")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "enable", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        logging.info("\n*** fetch collection via map (with credentials) as user")
        _, headers, answer = self.request("GET", path_share, check=200, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** disable map by user (json->json)")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "disable", 200, "user:userpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        logging.info("\n*** fetch collection via map (with credentials) as user -> n/a")
        _, headers, answer = self.request("GET", path_share, check=404, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** delete map by user (json->json) -> fail")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "delete", 403, "user:userpw", json_dict)

        logging.info("\n*** delete map by owner (json->json) -> ok")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share
        _, headers, answer = self._sharing_api_json("map", "delete", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

    def test_sharing_api_map_usercheck(self) -> None:
        """share-by-map API usage tests related to usercheck."""
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

        path_share1 = "/user1/calendar-shared-by-owner1.ics/"
        path_mapped1 = "/owner1/calendar1.ics/"
        path_share2 = "/user2/calendar-shared-by-owner2.ics/"
        path_mapped2 = "/owner2/calendar2.ics/"

        logging.info("\n*** prepare")
        self.mkcalendar(path_mapped1, login="%s:%s" % ("owner1", "owner1pw"))
        event = get_file_content("event1.ics")
        path = path_mapped1 + "/event1.ics"
        self.put(path, event, login="%s:%s" % ("owner1", "owner1pw"))

        self.mkcalendar(path_mapped2, login="%s:%s" % ("owner2", "owner2pw"))
        event = get_file_content("event1.ics")
        path = path_mapped2 + "/event1.ics"
        self.put(path, event, login="%s:%s" % ("owner2", "owner2pw"))

        logging.info("\n*** create map user1/owner1 as owner(wrong owner) -> fail")
        json_dict = {}
        json_dict['User'] = "user1"
        json_dict['PathMapped'] = path_mapped1
        json_dict['PathOrToken'] = path_share1
        _, headers, answer = self._sharing_api_json("map", "create", 403, "owner:ownerpw", json_dict)

        logging.info("\n*** create map user1/owner1:r -> ok")
        json_dict = {}
        json_dict['User'] = "user1"
        json_dict['PathMapped'] = path_mapped1
        json_dict['PathOrToken'] = path_share1
        json_dict['Permissions'] = "r"
        _, headers, answer = self._sharing_api_json("map", "create", 200, "owner1:owner1pw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        logging.info("\n*** create map user1/owner1 (repeat) -> fail")
        json_dict = {}
        json_dict['User'] = "user1"
        json_dict['PathMapped'] = path_mapped1
        json_dict['PathOrToken'] = path_share1
        _, headers, answer = self._sharing_api_json("map", "create", 409, "owner1:owner1pw", json_dict)

        logging.info("\n*** create map user2/owner2:rw -> ok")
        json_dict = {}
        json_dict['User'] = "user2"
        json_dict['PathMapped'] = path_mapped2
        json_dict['PathOrToken'] = path_share2
        json_dict['Permissions'] = "rw"
        _, headers, answer = self._sharing_api_json("map", "create", 200, "owner2:owner2pw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        logging.info("\n*** create map user2/owner1 -> fail")
        json_dict = {}
        json_dict['User'] = "user2"
        json_dict['PathMapped'] = path_mapped2
        json_dict['PathOrToken'] = path_share1
        _, headers, answer = self._sharing_api_json("map", "create", 403, "owner2:owner2pw", json_dict)

    def test_sharing_api_map_permissions(self) -> None:
        """share-by-map API usage tests related to permissions."""
        self.configure({"auth": {"type": "htpasswd",
                                 "htpasswd_filename": self.htpasswd_file_path,
                                 "htpasswd_encryption": "plain"},
                        "sharing": {
                                    "type": "csv",
                                    "collection_by_map": "True",
                                    "collection_by_token": "True"},
                        "logging": {"request_header_on_debug": "False",
                                    "request_content_on_debug": "False"},
                        "rights": {"type": "owner_only"}})

        json_dict: dict

        path_share_r = "/user/calendar-shared-by-owner-r.ics/"
        path_share_w = "/user/calendar-shared-by-owner-w.ics/"
        path_share_rw = "/user/calendar-shared-by-owner-rw.ics/"
        path_mapped = "/owner/calendar.ics/"

        logging.info("\n*** prepare and test access")
        self.mkcalendar(path_mapped, login="%s:%s" % ("owner", "ownerpw"))
        event = get_file_content("event1.ics")
        path = path_mapped + "/event1.ics"
        self.put(path, event, login="%s:%s" % ("owner", "ownerpw"))

        # check
        logging.info("\n*** fetch event as owner (init) -> ok")
        _, headers, answer = self.request("GET", path_mapped + "event1.ics", check=200, login="%s:%s" % ("owner", "ownerpw"))

        # create maps
        logging.info("\n*** create map user/owner:r -> ok")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share_r
        json_dict['Permissions'] = "r"
        json_dict['Enabled'] = "True"
        _, headers, answer = self._sharing_api_json("map", "create", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        logging.info("\n*** create map user/owner:w -> ok")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share_w
        json_dict['Permissions'] = "w"
        json_dict['Enabled'] = "True"
        _, headers, answer = self._sharing_api_json("map", "create", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        logging.info("\n*** create map user/owner:rw -> ok")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share_rw
        json_dict['Permissions'] = "rw"
        json_dict['Enabled'] = "True"
        _, headers, answer = self._sharing_api_json("map", "create", 200, "owner:ownerpw", json_dict)
        answer_dict = json.loads(answer)
        assert answer_dict['Status'] == "success"

        # list created maps
        logging.info("\n*** list (json->text)")
        json_dict = {}
        _, headers, answer = self._sharing_api_json("map", "list", 200, "owner:ownerpw", json_dict, "text/csv")

        # check permissions, no map is enabled by user -> 404
        logging.info("\n*** fetch collection via map:r -> n/a")
        _, headers, answer = self.request("GET", path_share_r, check=404, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** fetch collection via map:w -> n/a")
        _, headers, answer = self.request("GET", path_share_r, check=404, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** fetch collection via map:rw -> n/a")
        _, headers, answer = self.request("GET", path_share_r, check=404, login="%s:%s" % ("user", "userpw"))

        # enable maps by user
        logging.info("\n*** enable map by user:r")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share_r
        _, headers, answer = self._sharing_api_json("map", "enable", 200, "user:userpw", json_dict)

        logging.info("\n*** enable map by user:w")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share_w
        _, headers, answer = self._sharing_api_json("map", "enable", 200, "user:userpw", json_dict)

        logging.info("\n*** enable map by user:rw")
        json_dict = {}
        json_dict['User'] = "user"
        json_dict['PathMapped'] = path_mapped
        json_dict['PathOrToken'] = path_share_rw
        _, headers, answer = self._sharing_api_json("map", "enable", 200, "user:userpw", json_dict)

        # list adjusted maps
        logging.info("\n*** list (json->text)")
        json_dict = {}
        _, headers, answer = self._sharing_api_json("map", "list", 200, "owner:ownerpw", json_dict, "text/csv")

        # check permissions, no map is enabled by user -> 404
        logging.info("\n*** fetch collection via map:r -> ok")
        _, headers, answer = self.request("GET", path_share_r, check=200, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** fetch collection via map:w -> fail")
        _, headers, answer = self.request("GET", path_share_w, check=403, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** fetch collection via map:rw -> ok")
        _, headers, answer = self.request("GET", path_share_rw, check=200, login="%s:%s" % ("user", "userpw"))

        # list adjusted maps
        logging.info("\n*** list (json->text)")
        json_dict = {}
        _, headers, answer = self._sharing_api_json("map", "list", 200, "owner:ownerpw", json_dict, "text/csv")

        # PUT
        logging.info("\n*** put to collection by user via map:r -> fail")
        event = get_file_content("event2.ics")
        path = path_share_r + "/event2.ics"
        self.put(path, event, check=403, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** put to collection by user via map:w -> ok")
        event = get_file_content("event2.ics")
        path = path_share_w + "event2.ics"
        self.put(path, event, check=201, login="%s:%s" % ("user", "userpw"))

        # check result
        logging.info("\n*** fetch event via map:r -> ok")
        _, headers, answer = self.request("GET", path_share_r + "event2.ics", check=200, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** fetch event as owner -> ok")
        _, headers, answer = self.request("GET", path_mapped + "event2.ics", check=200, login="%s:%s" % ("owner", "ownerpw"))

        logging.info("\n*** put to collection by user via map:rw -> ok")
        event = get_file_content("event3.ics")
        path = path_share_rw + "event3.ics"
        self.put(path, event, check=201, login="%s:%s" % ("user", "userpw"))

        # check result
        logging.info("\n*** fetch event via map:r -> ok")
        _, headers, answer = self.request("GET", path_share_r + "event2.ics", check=200, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** fetch event via map:r -> ok")
        _, headers, answer = self.request("GET", path_share_r + "event3.ics", check=200, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** fetch event via map:rw -> ok")
        _, headers, answer = self.request("GET", path_share_rw + "event2.ics", check=200, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** fetch event via map:rw -> ok")
        _, headers, answer = self.request("GET", path_share_rw + "event3.ics", check=200, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** fetch event as owner -> ok")
        _, headers, answer = self.request("GET", path_mapped + "event1.ics", check=200, login="%s:%s" % ("owner", "ownerpw"))

        logging.info("\n*** fetch event as owner -> ok")
        _, headers, answer = self.request("GET", path_mapped + "event2.ics", check=200, login="%s:%s" % ("owner", "ownerpw"))

        logging.info("\n*** fetch event as owner -> ok")
        _, headers, answer = self.request("GET", path_mapped + "event3.ics", check=200, login="%s:%s" % ("owner", "ownerpw"))

        # DELETE
        logging.info("\n*** DELETE from collection by user via map:r -> fail")
        _, headers, answer = self.request("DELETE", path_share_r + "event1.ics", check=403, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** DELETE from collection by user via map:rw -> ok")
        _, headers, answer = self.request("DELETE", path_share_rw + "event2.ics", check=200, login="%s:%s" % ("user", "userpw"))

        logging.info("\n*** DELETE from collection by user via map:w -> ok")
        _, headers, answer = self.request("DELETE", path_share_w + "event3.ics", check=200, login="%s:%s" % ("user", "userpw"))

        # check results
        logging.info("\n*** fetch event as owner -> ok")
        _, headers, answer = self.request("GET", path_mapped + "event1.ics", check=200, login="%s:%s" % ("owner", "ownerpw"))

        logging.info("\n*** fetch event as owner -> fail")
        _, headers, answer = self.request("GET", path_mapped + "event2.ics", check=404, login="%s:%s" % ("owner", "ownerpw"))

        logging.info("\n*** fetch event as owner -> fail")
        _, headers, answer = self.request("GET", path_mapped + "event3.ics", check=404, login="%s:%s" % ("owner", "ownerpw"))

    # TODO hide+unhide for REPORT
