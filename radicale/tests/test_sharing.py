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
        htpasswd_content = "owner:ownerpw"
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
            assert "# status=success" in answer
            assert "# lines=0" in answer
            # check with request JSON response CSV
            json_dict: dict = {}
            content_type = "application/json"
            data = json.dumps(json_dict)
            _, headers, answer = self.request("POST", path, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
            logging.debug("received answer %r", answer)
            assert "# status=success" in answer
            assert "# lines=0" in answer
            # check with request JSON response JSON
            json_dict: dict = {}
            content_type = "application/json"
            accept = "application/json"
            data = json.dumps(json_dict)
            _, headers, answer = self.request("POST", path, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=accept)
            logging.debug("received answer %r", answer)
            assert '"status": "success"' in answer
            assert '"lines": 0' in answer
            assert '"content": null' in answer

    def test_sharing_api_add_token(self) -> None:
        """create a token-based share."""
        self.configure({"auth": {"type": "htpasswd",
                                 "htpasswd_filename": self.htpasswd_file_path,
                                 "htpasswd_encryption": "plain"},
                        "sharing": {
                                    "type": "csv",
                                    "collection_by_map": "True",
                                    "collection_by_token": "True"},
                        "logging": {"request_header_on_debug": "true",
                                    "request_content_on_debug": "true"},
                        "rights": {"type": "owner_only"}})
        action = "add"
        sharingtype = "token"
        path = "/.sharing/v1/" + sharingtype + "/" + action
        path_list = "/.sharing/v1/" + sharingtype + "/list"
        path_delete = "/.sharing/v1/" + sharingtype + "/delete"
        path_disable = "/.sharing/v1/" + sharingtype + "/disable"
        path_enable = "/.sharing/v1/" + sharingtype + "/enable"
        # without path_mapped
        form_array:str = []
        content_type = "application/x-www-form-urlencoded"
        data = "\n".join(form_array)
        _, headers, answer = self.request("POST", path, check=400, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        ## 1
        # with path_mapped
        form_array:str = []
        form_array.append("path_mapped=/owner/collection1")
        content_type = "application/x-www-form-urlencoded"
        data = "\n".join(form_array)
        _, headers, answer = self.request("POST", path, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "status=success" in answer
        assert "token=" in answer
        # extract token
        match = re.search('token=(.+)', answer)
        token1 = match[1]
        logging.debug("received token %r", token1)
        ## 2
        # with path_mapped
        form_array:str = []
        form_array.append("path_mapped=/owner/collection2")
        content_type = "application/x-www-form-urlencoded"
        data = "\n".join(form_array)
        _, headers, answer = self.request("POST", path, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "status=success" in answer
        assert "token=" in answer
        # extract token
        match = re.search('token=(.+)', answer)
        token2 = match[1]
        logging.debug("received token %r", token2)
        ## lookup token#1
        form_array:str = []
        form_array.append("token=" + token1)
        content_type = "application/x-www-form-urlencoded"
        data = "\n".join(form_array)
        path_list = "/.sharing/v1/" + sharingtype + "/list"
        _, headers, answer = self.request("POST", path_list, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "status=success" in answer
        assert "lines=1" in answer
        assert "/owner/collection2" in answer
        ## delete #1
        form_array:str = []
        form_array.append("token=" + token1)
        content_type = "application/x-www-form-urlencoded"
        data = "\n".join(form_array)
        _, headers, answer = self.request("POST", path_delete, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "status=success" in answer
        ## lookup token#1
        form_array:str = []
        form_array.append("token=" + token1)
        content_type = "application/x-www-form-urlencoded"
        data = "\n".join(form_array)
        path_list = "/.sharing/v1/" + sharingtype + "/list"
        _, headers, answer = self.request("POST", path_list, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "status=success" in answer
        assert "lines=0" in answer
        ## lookup tokens
        form_array:str = []
        content_type = "application/x-www-form-urlencoded"
        data = "\n".join(form_array)
        _, headers, answer = self.request("POST", path_list, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "status=success" in answer
        assert "lines=1" in answer
        ## disable token#2
        form_array:str = []
        form_array.append("token=" + token2)
        content_type = "application/x-www-form-urlencoded"
        data = "\n".join(form_array)
        _, headers, answer = self.request("POST", path_disable, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "status=success" in answer
        ## lookup token#2, check for not enabled
        form_array:str = []
        form_array.append("token=" + token2)
        content_type = "application/x-www-form-urlencoded"
        data = "\n".join(form_array)
        path_list = "/.sharing/v1/" + sharingtype + "/list"
        _, headers, answer = self.request("POST", path_list, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "status=success" in answer
        assert "lines=1" in answer
        assert "False,False" in answer
        ## enable token#2
        form_array:str = []
        form_array.append("token=" + token2)
        content_type = "application/x-www-form-urlencoded"
        data = "\n".join(form_array)
        _, headers, answer = self.request("POST", path_enable, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "status=success" in answer
        ## lookup token#2, check for enabled
        form_array:str = []
        form_array.append("token=" + token2)
        content_type = "application/x-www-form-urlencoded"
        data = "\n".join(form_array)
        path_list = "/.sharing/v1/" + sharingtype + "/list"
        _, headers, answer = self.request("POST", path_list, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "status=success" in answer
        assert "lines=1" in answer
        assert "True,False" in answer
