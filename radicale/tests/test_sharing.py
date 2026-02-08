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
        """GET/POST request at '/.sharing' without authentication."""
        for path in ["/.sharing", "/.sharing/"]:
            for request in ["GET", "POST"]:
                _, headers, _ = self.request(request, path, check=401)

    def test_sharing_api_base_with_auth(self) -> None:
        """GET/POST request at '/.sharing' with authentication."""
        self.configure({"auth": {"type": "htpasswd",
                                 "htpasswd_filename": self.htpasswd_file_path,
                                 "htpasswd_encryption": "plain"},
                        "rights": {"type": "owner_only"}})
        for path in ["/.sharing/", "/.sharing/v9/"]:
            _, headers, _ = self.request("GET", path, check=403, login="%s:%s" % ("owner", "ownerpw"))
            _, headers, _ = self.request("POST", path, check=404, login="%s:%s" % ("owner", "ownerpw"))
        for path in ["/.sharing/v1/"]:
            _, headers, _ = self.request("POST", path, check=404, login="%s:%s" % ("owner", "ownerpw"))
        for action in sharing.API_HOOKS_V1:
            path = "/.sharing/v1/" + action
            _, headers, _ = self.request("POST", path + "NA", check=404, login="%s:%s" % ("owner", "ownerpw"))
            _, headers, _ = self.request("POST", path, check=400, login="%s:%s" % ("owner", "ownerpw"))

    def test_sharing_api_list_with_auth(self) -> None:
        """POST/list with authentication."""
        self.configure({"auth": {"type": "htpasswd",
                                 "htpasswd_filename": self.htpasswd_file_path,
                                 "htpasswd_encryption": "plain"},
                        "logging": {"request_header_on_debug": "true"},
                        "rights": {"type": "owner_only"}})
        action = "list"
        # basic checks
        path = "/.sharing/v1/" + action
        _, headers, _ = self.request("POST", path, check=400, login="%s:%s" % ("owner", "ownerpw"))
        # basic checks with sharingtype
        for sharingtype in sharing.SHARE_TYPES:
            path = "/.sharing/v1/" + action + "/" + sharingtype
            _, headers, _ = self.request("POST", path, check=400, login="%s:%s" % ("owner", "ownerpw"))

        # check with request FORM response CSV
        form_array:str = []
        path = "/.sharing/v1/" + action
        content_type = "application/x-www-form-urlencoded"
        data = "\n".join(form_array)
        _, headers, answer = self.request("POST", path, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "# status=success" in answer
        assert "# lines=0" in answer

        # check with request JSON response CSV
        json_dict: dict = {}
        path = "/.sharing/v1/" + action
        content_type = "application/json"
        data = json.dumps(json_dict)
        _, headers, answer = self.request("POST", path, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type)
        logging.debug("received answer %r", answer)
        assert "# status=success" in answer
        assert "# lines=0" in answer

        # check with request JSON response JSON
        json_dict: dict = {}
        path = "/.sharing/v1/" + action
        content_type = "application/json"
        accept = "application/json"
        data = json.dumps(json_dict)
        _, headers, answer = self.request("POST", path, check=200, login="%s:%s" % ("owner", "ownerpw"), data=data, content_type=content_type, accept=accept)
        logging.debug("received answer %r", answer)
        assert '"status": "success"' in answer
        assert '"lines": 0' in answer
        assert '"content": null' in answer
