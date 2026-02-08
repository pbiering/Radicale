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

import csv
import os

from radicale import sharing
from radicale.log import logger

""" CVS based sharing by token or map """

class Sharing(sharing.BaseSharing):
    _lines: int = 0
    _map_cache = []
    _sharing_db_file: str

    ## Overloaded functions
    def init_database(self) -> bool:
        logger.debug("sharing database initialization for type 'csv'")
        sharing_db_file = self.configuration.get("sharing", "database_filename")
        if sharing_db_file == "":
            folder = self.configuration.get("storage", "filesystem_folder")
            folder_db = os.path.join(folder, "collection-db")
            sharing_db_file = os.path.join(folder_db, "sharing.csv")
            logger.warning("sharing database filename not provided, use default: %r", sharing_db_file)
        else:
            logger.info("sharing database filename: %r", sharing_db_file)

        if not os.path.exists(folder_db):
            logger.warning("sharing database folder is not existing: %r", folder_db)
            try:
                os.mkdir(folder_db)
            except Exception as e:
                logger.error("sharing database folder cannot be created (check permissions): %r (%r)", folder_db, e)
                return False
            logger.info("sharing database folder successfully created: %r", folder_db)

        if not os.path.exists(sharing_db_file):
            logger.warning("sharing database is not existing: %r", sharing_db_file)
            try:
                if self._create_empty_csv(sharing_db_file) is not True:
                    raise
            except Exception as e:
                logger.error("sharing database (empty) cannot be created (check permissions): %r (%r)", sharing_db_file, e)
                return False
            logger.info("sharing database (empty) successfully created: %r", sharing_db_file)
        else:
            logger.info("sharing database exists: %r", sharing_db_file)

        # read database
        try:
            if self._load_csv(sharing_db_file) is not True:
                raise
        except Exception as e:
            logger.error("sharing database load failed: %r (%r)", sharing_db_file, e)
            return False
        logger.info("sharing database load successful: %r (lines=%d)", sharing_db_file, self._lines)
        self._sharing_db_file = sharing_db_file
        return True

    def get_database_info(self) -> [ dict | None]:
        database_info = { 'type': "csv" }
        return database_info

    def get_sharing_collection_by_token(self, token: str) -> [dict | None]:
        """ retrieve target and attributes by token """
        for row in self._map_cache:
            if row['type'] != "token":
                continue
            if row['path_token'] != token:
                continue
            if row['enabled'] != "True":
                continue
            path_mapped = row['path_mapped']
            user = row['user']
            permissions = row['permissions']
            logger.debug("TRACE/sharing_by_token: map %r to %r (user=%r, permissions=%r)", token, path_mapped, user, permissions)
            return {"mapped": True, "path": path_mapped, "user": user, "permissions": permissions}

        # default
        logger.debug("TRACE/sharing_by_token: no entry in map found for token: %r", token)
        return None        

    def get_sharing_collection_by_map(self, path) -> [dict | None]:
        """ retrieve target and attributes by map """
        for row in self._map_cache:
            if row['type'] != "map":
                continue
            if row['path_token'] != path:
                continue
            if row['enabled'] != "True":
                continue
            # TODO: handle "hidden"
            path_mapped = row['path_mapped']
            user = row['owner']
            permissions = row['permissions']
            logger.debug("TRACE/sharing_by_map: map %r to %r (user=%r, permissions=%r)", path, path_mapped, user, permissions)
            return {"mapped": True, "path": path_mapped, "user": user, "permissions": permissions}

        # default
        logger.debug("TRACE/sharing_by_map: no entry in map found for path: %r", path)
        return {"mapped": False}

    def get_sharing_list_by_type_user(self, share_type, user, path_token = None) -> [dict | None]:
        """ retrieve sharing list by type and user """
        result = []
        for row in self._map_cache:
            if share_type != "*" and row['type'] != share_type:
                continue
            if row['owner'] != user:
                continue
            if path_token and row['path_token'] != path_token:
                continue
            result.append(row)
        return result

    def add_sharing_by_token(self, user: str, token: str, path_mapped: str, timestamp: int, permissions: str = "r", enabled: bool = True) -> bool:
        """ add sharing by token """
        logger.debug("TRACE/sharing_by_token/add: user=%r token=%r path_mapped=%r permissions=%r enabled=%s", user, token, path_mapped, permissions, enabled)
        # check for duplicate token
        for row in self._map_cache:
            if row['type'] != "token":
                continue
            if row['path_token'] == token:
                logger.warning("sharing/add_sharing_by_token: token already exists: user=%r token=%r path_mapped=%r", user, token, path_mapped)
                return False
        row = { "type": "token",
                "path_token": token,
                "path_mapped": path_mapped,
                "owner": user,
                "user": user,
                "permissions": permissions,
                "enabled": str(enabled),
                "hidden": "False",
                "created": str(timestamp),
                "last_updated": str(timestamp)
        }
        logger.debug("TRACE/sharing_by_token: add row: %r", row)
        ## TODO: add locking
        self._map_cache.append(row)
        if self._write_csv(self._sharing_db_file):
            logger.debug("TRACE/sharing_by_token: write CSV done")
            return True
        logger.warning("sharing/add_sharing_by_token: cannot update CSV database")
        return False

    def delete_sharing_by_token(self, user: str, token) -> [dict | None]:
        """ delete sharing by token """
        logger.debug("TRACE/sharing_by_token/delete: user=%r token=%r", user, token)
        # lookup token
        token_found = False
        index = 0
        for row in self._map_cache:
            if row['type'] != "token":
                pass
            if row['path_token'] != token:
                pass
            else:
                token_found = True
                break
            index += 1

        if token_found:
            if row['owner'] != user:
                return {"status": "permission-denied"}
            logger.debug("TRACE/sharing_by_token/delete: user=%r token=%r index=%d", user, token, index)
            self._map_cache.pop(index)

            ## TODO: add locking
            if self._write_csv(self._sharing_db_file):
                logger.debug("TRACE/sharing_by_token: write CSV done")
                return {"status": "success"}
            logger.warning("sharing/add_sharing_by_token: cannot update CSV database")
            return {"status": "error"}

        return {"status": "not-found"}

    def disable_sharing_by_token(self, user: str, token) -> [dict | None]:
        """ disable sharing by token """
        logger.debug("TRACE/sharing_by_token/disable: user=%r token=%r", user, token)

        # lookup token
        token_found = False
        index = 0
        for row in self._map_cache:
            if row['type'] != "token":
                pass
            if row['path_token'] != token:
                pass
            else:
                token_found = True
                break
            index += 1

        if token_found:
            if row['owner'] != user:
                return {"status": "permission-denied"}
            logger.debug("TRACE/sharing_by_token/disable: user=%r token=%r index=%d", user, token, index)
            row['enabled'] = str(False)
            # remove
            self._map_cache.pop(index)
            # readd
            self._map_cache.append(row)

            ## TODO: add locking
            if self._write_csv(self._sharing_db_file):
                logger.debug("TRACE/sharing_by_token: write CSV done")
                return {"status": "success"}
            logger.warning("sharing/add_sharing_by_token: cannot update CSV database")
            return {"status": "error"}

        return {"status": "not-found"}

    def enable_sharing_by_token(self, user: str, token) -> [dict | None]:
        """ enable sharing by token """
        logger.debug("TRACE/sharing_by_token/enable: user=%r token=%r", user, token)

        # lookup token
        token_found = False
        index = 0
        for row in self._map_cache:
            if row['type'] != "token":
                pass
            if row['path_token'] != token:
                pass
            else:
                token_found = True
                break
            index += 1

        if token_found:
            if row['owner'] != user:
                return {"status": "permission-denied"}
            logger.debug("TRACE/sharing_by_token/enable: user=%r token=%r index=%d", user, token, index)
            row['enabled'] = str(True)
            # remove
            self._map_cache.pop(index)
            # readd
            self._map_cache.append(row)

            ## TODO: add locking
            if self._write_csv(self._sharing_db_file):
                logger.debug("TRACE/sharing_by_token: write CSV done")
                return {"status": "success"}
            logger.warning("sharing/add_sharing_by_token: cannot update CSV database")
            return {"status": "error"}

        return {"status": "not-found"}

    ## local functions
    def _create_empty_csv(self, file) -> bool:
        with open(file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=sharing.DB_FIELDS)
            writer.writeheader()
        return True

    def _load_csv(self, file) -> bool:
        logger.debug("sharing database load begin: %r", file)
        with open(file, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile, fieldnames=sharing.DB_FIELDS)
            self._lines = 0
            for row in reader:
                # check for duplicates
                dup = False
                for row_cached in self._map_cache:
                    if row == row_cached:
                        dup = True
                        break
                if dup:
                    continue
                self._map_cache.append(row)
                self._lines += 1
        logger.debug("sharing database load end: %r", file)
        return True

    def _write_csv(self, file) -> bool:
        with open(file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=sharing.DB_FIELDS)
            writer.writerows(self._map_cache)
        return True
