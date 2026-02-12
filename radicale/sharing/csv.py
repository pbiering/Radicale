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

    def get_database_info(self) -> [dict | None]:
        database_info = {'type': "csv"}
        return database_info

    def get_sharing(self,
                    ShareType: str,
                    PathOrToken: str,
                    User: [str | None ] = None) -> [dict | None]:
        """ retrieve sharing target and attributes by map """
        # Lookup
        for row in self._map_cache:
            if row['ShareType'] != ShareType:
                continue
            if row['PathOrToken'] != PathOrToken:
                continue
            if User and row['User'] != User:
                continue
            if row['EnabledByOwner'] != str(True):
                continue
            if row['EnabledByUser'] != str(True):
                continue
            PathMapped = row['PathMapped']
            Owner = row['Owner']
            User = row['User']
            Permissions = row['Permissions']
            logger.debug("TRACE/sharing: map %r to %r (Owner=%r User=%r Permissions=%r)", PathOrToken, PathMapped, Owner, User, Permissions)
            return {
                    "mapped": True,
                    "PathOrToken": PathOrToken,
                    "PathMapped": PathMapped,
                    "Owner": Owner,
                    "User": User,
                    "Permissions": Permissions}
        return None

    def list_sharing(self,
                     ShareType: [str | None] =  None,
                     PathOrToken: [str | None] = None, PathMapped: [str | None] = None,
                     Owner: [str | None] = None, User: [str | None] = None) -> bool:
        """ retrieve sharing """
        result = []
        for row in self._map_cache:
            if ShareType and row['ShareType'] != ShareType:
                continue
            if Owner and row['Owner'] != Owner:
                continue
            if User and row['User'] != User:
                continue
            if PathOrToken and row['PathOrToken'] != PathOrToken:
                continue
            if PathMapped and row['PathMapped'] != PathMapped:
                continue
            result.append(row)
        return result

    def create_sharing(self,
                       ShareType: str,
                       PathOrToken: str, PathMapped: str,
                       Owner: str, User: str,
                       Permissions: str = "r",
                       EnabledByOwner: bool = False, EnabledByUser: bool = False,
                       HiddenByOwner:  bool = True , HiddenByUser:  bool = True,
                       Timestamp: int = 0) -> bool:
        """ create sharing """
        if ShareType == "token":
            logger.debug("TRACE/sharing/token/create: PathOrToken=%r Owner=%r PathMapped=%r User=%r Permissions=%r", PathOrToken, Owner, PathMapped, User, Permissions)
            # check for duplicate token entry
            for row in self._map_cache:
                if row['ShareType'] != "token":
                    continue
                if row['PathOrToken'] == PathOrToken:
                    # must be unique systemwide
                    logger.error("sharing/token/create: PathOrToken already exists: PathOrToken=%r", PathOrToken)
                    return False
        elif ShareType == "map":
            logger.debug("TRACE/sharing/map/create: PathOrToken=%r Owner=%r PathMapped=%r User=%r Permissions=%r", PathOrToken, Owner, PathMapped, User, Permissions)
            # check for duplicate map entry
            for row in self._map_cache:
                if row['ShareType'] != "map":
                    continue
                if row['PathMapped'] == PathMapped and row['User'] == User:
                    # must be unique systemwide
                    logger.error("sharing/map/create: entry already exists: PathMapped=%r User=%r", PathMapped, User, Permissions)
                    return False

        row = { "ShareType": ShareType,
                "PathOrToken": PathOrToken,
                "PathMapped": PathMapped,
                "Owner": Owner,
                "User": User,
                "Permissions": Permissions,
                "EnabledByOwner": str(EnabledByOwner),
                "EnabledByUser": str(EnabledByUser),
                "HiddenByOwner": str(HiddenByOwner),
                "HiddenByUser": str(HiddenByUser),
                "TimestampCreated": str(Timestamp),
                "TimestampUpdated": str(Timestamp)
        }
        logger.debug("TRACE/sharing/*/create: add row: %r", row)
        # TODO: add locking
        self._map_cache.append(row)
        if self._write_csv(self._sharing_db_file):
            logger.debug("TRACE/sharing_by_token: write CSV done")
            return True
        logger.warning("sharing/add_sharing_by_token: cannot update CSV database")
        return False

    def delete_sharing(self,
                       ShareType: str,
                       PathOrToken: str, Owner: str,
                       PathMapped: [str | None] = None,
                       User: [str | None] = None) -> [dict | None]:
        """ delete sharing """
        if ShareType == "token":
            logger.debug("TRACE/sharing/token/delete: PathOrToken=%r Owner=%r", PathOrToken, Owner)
        elif ShareType == "map":
            logger.debug("TRACE/sharing/map/delete: PathOrToken=%r Owner=%r PathMapped=%r User=%r", PathOrToken, Owner, PathMapped, User)
        else:
            raise  # should not be reached

        # lookup token
        found = False
        index = 0
        for row in self._map_cache:
            if row['ShareType'] != ShareType:
                pass
            elif row['PathOrToken'] != PathOrToken:
                pass
            else:
                if ShareType == "map":
                    # extra filter
                    if row['PathMapped'] != PathMapped:
                        pass
                    elif row['User'] != User:
                        pass
                    else:
                        found = True
                        break
                else:
                    found = True
                    break
            index += 1

        if found:
            logger.debug("TRACE/sharing/*/delete: found index=%d", index)
            if row['Owner'] != Owner:
                return {"status": "permission-denied"}
            logger.debug("TRACE/sharing/*/delete: Owner=%r PathOrToken=%r index=%d", Owner, PathOrToken, index)
            self._map_cache.pop(index)

            # TODO: add locking
            if self._write_csv(self._sharing_db_file):
                logger.debug("TRACE/sharing_by_token: write CSV done")
                return {"status": "success"}
            logger.warning("sharing/sharing_by_token: cannot update CSV database")
            return {"status": "error"}
        else:
            return {"status": "not-found"}

    def toggle_sharing(self,
                       ShareType: str,
                       PathOrToken: str,
                       OwnerOrUser: str,
                       Action: str,
                       PathMapped: [str | None] = None,
                       User: [str | None] = None,
                       Timestamp: int = 0) -> [dict | None]:
        """ toggle sharing """
        if Action not in sharing.API_SHARE_TOGGLES_V1:
            return False

        logger.debug("TRACE/sharing/*/" + Action + ": OwnerOrUser=%r PathOrToken=%r Action=%r", OwnerOrUser, PathOrToken, Action)

        # lookup entry
        found = False
        index = 0
        for row in self._map_cache:
            if row['ShareType'] != ShareType:
                pass
            if row['PathOrToken'] != PathOrToken:
                pass
            else:
                found = True
                break
            index += 1

        if found:
            if row['Owner'] == OwnerOrUser:
                pass
            elif row['User'] == OwnerOrUser:
                pass
            else:
                return {"status": "permission-denied"}

            # TODO: locking
            if row['Owner'] == OwnerOrUser:
                logger.debug("TRACE/sharing/" + ShareType + "/" + Action + ": Owner=%r PathOrToken=%r index=%d", OwnerOrUser, PathOrToken, index)
                if Action == "disable":
                    row['EnabledByOwner'] = str(False)
                elif Action == "enable":
                    row['EnabledByOwner'] = str(True)
                elif Action == "hide":
                    row['HiddenByOwner'] = str(True)
                elif Action == "unhide":
                    row['HiddenByOwner'] = str(False)
                row['TimestampUpdated'] = str(Timestamp)
            if row['User'] == OwnerOrUser:
                logger.debug("TRACE/sharing/" + ShareType + "/" + Action + ": User=%r PathOrToken=%r index=%d", OwnerOrUser, PathOrToken, index)
                if Action == "disable":
                    row['EnabledByUser'] = str(False)
                elif Action == "enable":
                    row['EnabledByUser'] = str(True)
                elif Action == "hide":
                    row['HiddenByUser'] = str(True)
                elif Action == "unhide":
                    row['HiddenByUser'] = str(False)

            row['TimestampUpdated'] = str(Timestamp)

            # remove
            self._map_cache.pop(index)
            # readd
            self._map_cache.append(row)

            # TODO: add locking
            if self._write_csv(self._sharing_db_file):
                logger.debug("TRACE: write CSV done")
                return {"status": "success"}
            logger.error("sharing: cannot update CSV database")
            return {"status": "error"}
        else:
            return {"status": "not-found"}

    # local functions
    def _create_empty_csv(self, file) -> bool:
        with open(file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=sharing.DB_FIELDS_V1)
            writer.writeheader()
        return True

    def _load_csv(self, file) -> bool:
        logger.debug("sharing database load begin: %r", file)
        with open(file, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile, fieldnames=sharing.DB_FIELDS_V1)
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
            writer = csv.DictWriter(csvfile, fieldnames=sharing.DB_FIELDS_V1)
            writer.writerows(self._map_cache)
        return True
