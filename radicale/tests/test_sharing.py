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
import posixpath
import re
import urllib
from typing import Any, Callable, ClassVar, Iterable, List, Optional, Tuple

import pytest

from radicale import sharing, utils
from radicale.tests import RESPONSES, BaseTest
from radicale.tests.helpers import get_file_content


class TestSharingApiSanity(BaseTest):
    """Tests with sharing."""

    htpasswd_file_path: str

    def setup_method(self) -> None:
        BaseTest.setup_method(self)
        self.htpasswd_file_path = os.path.join(self.colpath, ".htpasswd")
        encoding: str = self.configuration.get("encoding", "stock")
        htpasswd_content = "owner:ownerpw\nuser:userpw"
        with open(self.htpasswd_file_path, "w", encoding=encoding) as f:
            f.write(htpasswd_content)

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
        action = "list"
        for sharingtype in sharing.SHARE_TYPES:
            # basic checks with sharingtype
            path = "/.sharing/v1/" + sharingtype + "/" + action
            _, headers, _ = self.request("POST", path, check=400, login="%s:%s" % ("owner", "ownerpw"))
            # check with request FORM response CSV
            form_array:str = []
            content_type = "application/x-www-form-urlencoded"
            data = "\n".join(form_array)
            _, headers, answer = self.request("POST", path, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
            logging.debug("received answer %r", answer)
            assert "# Status=not-found" in answer
            assert "# Lines=0" in answer
            # check with request JSON response CSV
            json_dict: dict = {}
            content_type = "application/json"
            data = json.dumps(json_dict)
            _, headers, answer = self.request("POST", path, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
            logging.debug("received answer %r", answer)
            assert "# Status=not-found" in answer
            assert "# Lines=0" in answer
            # check with request JSON response JSON
            json_dict: dict = {}
            content_type = "application/json"
            accept = "application/json"
            data = json.dumps(json_dict)
            _, headers, answer = self.request("POST", path, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=accept)
            logging.debug("received answer %r", answer)
            assert '"Status": "not-found"' in answer
            assert '"Lines": 0' in answer
            assert '"Content": null' in answer


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

        sharingtype = "token"
        path_base = "/.sharing/v1/" + sharingtype + "/"

        logging.debug("*** create token without PathMapped (form) -> should fail")
        form_array:str = []
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        _, headers, answer = self.request("POST", path_base + "create", check=400, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)

        logging.debug("*** create token without PathMapped (json) -> should fail")
        form_dict = {}
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "create", check=400, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)

        logging.debug("*** create token#1")
        form_array:str = []
        form_array.append("PathMapped=/owner/collection1")
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        _, headers, answer = self.request("POST", path_base + "create", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=success" in answer
        assert "PathOrToken=" in answer
        # extract token
        match = re.search('PathOrToken=(.+)', answer)
        token1 = match[1]
        logging.debug("received token %r", token1)

        logging.debug("*** create token#2")
        form_dict = {}
        form_dict['PathMapped'] = "/owner/collection2"
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "create", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=success" in answer
        assert "Token=" in answer
        # extract token
        match = re.search('Token=(.+)', answer)
        token2 = match[1]
        logging.debug("received token %r", token2)

        logging.debug("*** lookup token#1 (form->text)")
        form_array:str = []
        form_array.append("PathOrToken=" + token1)
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        _, headers, answer = self.request("POST", path_base + "list", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=success" in answer
        assert "Lines=1" in answer
        assert "/owner/collection1" in answer

        logging.debug("*** lookup token#2 (json->text")
        form_dict = {}
        content_type = "application/json"
        form_dict['PathOrToken'] = token2
        content_type = "application/json"
        data = json.dumps(form_dict)
        _, headers, answer = self.request("POST", path_base + "list", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=success" in answer
        assert "Lines=1" in answer
        assert "/owner/collection2" in answer

        logging.debug("*** lookup token#2 (json->json)")
        form_dict = {}
        content_type = "application/json"
        form_dict['PathOrToken'] = token2
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "list", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)
        result = json.loads(answer)
        assert "success" in result['Status']
        assert result['Lines'] == 1
        assert "/owner/collection2" in result['Content'][0]['PathMapped']

        logging.debug("*** delete token#1 (form->text)")
        form_array:str = []
        form_array.append("PathOrToken=" + token1)
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        _, headers, answer = self.request("POST", path_base + "delete", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=success" in answer

        logging.debug("*** lookup token#1 (form->text) -> should not be there anymore")
        form_array:str = []
        form_array.append("PathOrToken=" + token1)
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        _, headers, answer = self.request("POST", path_base + "list", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=not-found" in answer
        assert "Lines=0" in answer

        logging.debug("*** lookup tokens (form->text) -> still one should be there")
        form_array:str = []
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        _, headers, answer = self.request("POST", path_base + "list", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=success" in answer
        assert "Lines=1" in answer

        logging.debug("*** disable token#2 (form->text)")
        form_array:str = []
        form_array.append("PathOrToken=" + token2)
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        _, headers, answer = self.request("POST", path_base + "disable", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=success" in answer

        logging.debug("*** lookup token#2 (json->json) -> check for not enabled")
        form_dict = {}
        form_dict['PathOrToken'] = token2
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "list", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)
        result = json.loads(answer)
        assert "success" in result['Status']
        assert result['Lines'] == 1
        assert "False" in result['Content'][0]['EnabledByOwner']

        logging.debug("*** enable token#2 (json->json)")
        form_dict = {}
        form_dict['PathOrToken'] = token2
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "enable", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)
        result = json.loads(answer)
        assert "success" in result['Status']

        logging.debug("*** lookup token#2 (form->text) -> check for enabled")
        form_array:str = []
        form_array.append("PathOrToken=" + token2)
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        _, headers, answer = self.request("POST", path_base + "list", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=success" in answer
        assert "Lines=1" in answer
        assert "True,True,False,False" in answer

        logging.debug("*** hide token#2 (form->text)")
        form_array:str = []
        form_array.append("PathOrToken=" + token2)
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        _, headers, answer = self.request("POST", path_base + "hide", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=success" in answer

        logging.debug("*** lookup token#2 (form->text) -> check for hidden")
        form_array:str = []
        form_array.append("PathOrToken=" + token2)
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        _, headers, answer = self.request("POST", path_base + "list", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=success" in answer
        assert "Lines=1" in answer
        assert "True,True,True,False" in answer

        logging.debug("*** unhide token#2 (json->json)")
        form_dict = {}
        form_dict['PathOrToken'] = token2
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "unhide", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)
        result = json.loads(answer)
        assert "success" in result['Status']

        logging.debug("*** lookup token#2 (json->json) -> check for not hidden")
        form_dict = {}
        form_dict['PathOrToken'] = token2
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "list", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)
        result = json.loads(answer)
        assert "success" in result['Status']
        assert result['Lines'] == 1
        assert "False" in result['Content'][0]['HiddenByOwner']

        logging.debug("*** delete token#2 (json->json)")
        form_dict = {}
        form_dict['PathOrToken'] = token2
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "delete", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)
        result = json.loads(answer)
        assert "success" in result['Status']

        logging.debug("*** lookup token#2 (json->json) -> should not be there anymore")
        form_dict = {}
        form_dict['PathOrToken'] = token2
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "list", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)
        result = json.loads(answer)
        assert "not-found" in result['Status']
        assert result['Lines'] == 0


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

        sharingtype = "token"
        path_base = "/.sharing/v1/" + sharingtype + "/"
        path_token = "/.token/"

        logging.debug("*** prepare and test access")
        self.mkcalendar("/owner/calendar.ics/", login="%s:%s" % ("owner", "ownerpw"))
        event = get_file_content("event1.ics")
        path = "/owner/calendar.ics/event1.ics"
        self.put(path, event, login="%s:%s" % ("owner", "ownerpw"))
        _, headers, answer = self.request("GET", path, check=200, login="%s:%s" % ("owner", "ownerpw"))

        logging.debug("*** create token")
        form_array:str = []
        form_array.append("PathMapped=/owner/calendar.ics")
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        _, headers, answer = self.request("POST", path_base + "create", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=success" in answer
        assert "PathOrToken=" in answer
        # extract token
        match = re.search('PathOrToken=(.+)', answer)
        token = match[1]
        logging.debug("received token %r", token)

        logging.debug("*** fetch collection using invalid token (without credentials)")
        _, headers, answer = self.request("GET", path_token + "v1/invalidtoken", check=404)

        logging.debug("*** fetch collection using token (without credentials)")
        _, headers, answer = self.request("GET", path_token + token, check=200)
        assert "UID:event" in answer

        logging.debug("*** disable token (form->text)")
        form_array:str = []
        form_array.append("PathOrToken=" + token)
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        _, headers, answer = self.request("POST", path_base + "disable", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=success" in answer

        logging.debug("*** fetch collection using disabled token (without credentials)")
        _, headers, answer = self.request("GET", path_token + token, check=404)

        logging.debug("*** enable token (form->text)")
        form_array:str = []
        form_array.append("PathOrToken=" + token)
        data = "\n".join(form_array)
        content_type = "application/x-www-form-urlencoded"
        _, headers, answer = self.request("POST", path_base + "enable", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "Status=success" in answer

        logging.debug("*** fetch collection using token (without credentials)")
        _, headers, answer = self.request("GET", path_token + token, check=200)
        assert "UID:event" in answer

        logging.debug("*** delete token (json->json)")
        form_dict = {}
        form_dict['PathOrToken'] = token
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "delete", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)
        result = json.loads(answer)
        assert "success" in result['Status']

        logging.debug("*** fetch collection using deleted token (without credentials)")
        _, headers, answer = self.request("GET", path_token + token, check=404)


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

        sharingtype = "map"
        path_base = "/.sharing/v1/" + sharingtype + "/"

        logging.debug("*** create map without PathMapped (json) -> should fail")
        form_dict = {}
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "create", check=400, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)

        logging.debug("*** create map without PathMapped but User (json) -> should fail")
        form_dict = {}
        form_dict['User'] = "user"
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "create", check=400, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)

        logging.debug("*** create map without PathMapped but User and PathOrToken (json) -> should fail")
        form_dict = {}
        form_dict['User'] = "user"
        form_dict['PathOrToken'] = "/owner/calendar.ics"
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "create", check=400, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)

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

        sharingtype = "map"
        path_base = "/.sharing/v1/" + sharingtype + "/"
        path_share = "/user/calendar-shared-by-owner.ics"
        path_mapped = "/owner/calendar.ics"

        logging.debug("*** prepare and test access")
        self.mkcalendar(path_mapped, login="%s:%s" % ("owner", "ownerpw"))
        event = get_file_content("event1.ics")
        path = path_mapped + "/event1.ics"
        self.put(path, event, login="%s:%s" % ("owner", "ownerpw"))

        logging.debug("*** create map with PathMapped and User and PathOrToken (json)")
        form_dict = {}
        form_dict['User'] = "user"
        form_dict['PathMapped'] = "/owner/calendar.ics"
        form_dict['PathOrToken'] = "/user/calendar-shared-by-owner.ics"
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "create", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)
        result = json.loads(answer)
        assert "success" in result['Status']

        logging.debug("*** lookup map without filter (json->json)")
        form_dict = {}
        content_type = "application/json"
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "list", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)
        result = json.loads(answer)
        assert "success" in result['Status']
        assert result['Lines'] == 1
        assert path_share in result['Content'][0]['PathOrToken']
        assert path_mapped in result['Content'][0]['PathMapped']
        assert "owner" in result['Content'][0]['Owner']
        assert "user" in result['Content'][0]['User']

        logging.debug("*** fetch collection (without credentials)")
        _, headers, answer = self.request("GET", path_mapped, check=401)

        logging.debug("*** fetch collection (with credentials) as owner")
        _, headers, answer = self.request("GET", path_mapped, check=200, login="%s:%s" % ("owner", "ownerpw"))

        logging.debug("*** fetch collection (with credentials) as user")
        _, headers, answer = self.request("GET", path_mapped, check=403, login="%s:%s" % ("user", "userpw"))

        logging.debug("*** fetch collection via map (with credentials) as user")
        _, headers, answer = self.request("GET", path_share, check=200, login="%s:%s" % ("user", "userpw"))

        logging.debug("*** disable map by owner (json->json)")
        form_dict = {}
        form_dict['User'] = "user"
        form_dict['PathMapped'] = "/owner/calendar.ics"
        form_dict['PathOrToken'] = "/user/calendar-shared-by-owner.ics"
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "disable", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)
        result = json.loads(answer)
        assert "success" in result['Status']

        logging.debug("*** fetch collection via map (with credentials) as user -> n/a")
        _, headers, answer = self.request("GET", path_share, check=404, login="%s:%s" % ("user", "userpw"))

        logging.debug("*** enable map by owner (json->json)")
        form_dict = {}
        form_dict['User'] = "user"
        form_dict['PathMapped'] = "/owner/calendar.ics"
        form_dict['PathOrToken'] = "/user/calendar-shared-by-owner.ics"
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "enable", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)
        result = json.loads(answer)
        assert "success" in result['Status']

        logging.debug("*** fetch collection via map (with credentials) as user")
        _, headers, answer = self.request("GET", path_share, check=200, login="%s:%s" % ("user", "userpw"))

        logging.debug("*** disable map by user (json->json)")
        form_dict = {}
        form_dict['User'] = "user"
        form_dict['PathMapped'] = "/owner/calendar.ics"
        form_dict['PathOrToken'] = "/user/calendar-shared-by-owner.ics"
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "disable", check=200, login="%s:%s" % ("user", "userpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)
        result = json.loads(answer)
        assert "success" in result['Status']

        logging.debug("*** fetch collection via map (with credentials) as user -> n/a")
        _, headers, answer = self.request("GET", path_share, check=404, login="%s:%s" % ("user", "userpw"))

        logging.debug("*** delete map by user (json->json) -> fail")
        form_dict = {}
        form_dict['User'] = "user"
        form_dict['PathMapped'] = "/owner/calendar.ics"
        form_dict['PathOrToken'] = "/user/calendar-shared-by-owner.ics"
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "delete", check=403, login="%s:%s" % ("user", "userpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)

        logging.debug("*** delete map by owner (json->json) -> ok")
        form_dict = {}
        form_dict['User'] = "user"
        form_dict['PathMapped'] = "/owner/calendar.ics"
        form_dict['PathOrToken'] = "/user/calendar-shared-by-owner.ics"
        data = json.dumps(form_dict)
        content_type = "application/json"
        _, headers, answer = self.request("POST", path_base + "delete", check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=content_type)
        logging.debug("received answer %r", answer)
        result = json.loads(answer)
        assert "success" in result['Status']

        ## TODO hide+unhide for REPORT
