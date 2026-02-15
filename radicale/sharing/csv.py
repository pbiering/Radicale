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
from typing import Union

from radicale import sharing
from radicale.log import logger

""" CVS based sharing by token or map """


class Sharing(sharing.BaseSharing):
    _lines: int = 0
    _sharing_cache: list[dict] = []
    _sharing_db_file: str

    # Overloaded functions
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

    def get_database_info(self) -> Union[dict | None]:
        database_info = {'type': "csv"}
        return database_info

    def get_sharing(self,
                    ShareType: str,
                    PathOrToken: str,
                    User: Union[str | None] = None) -> Union[dict | None]:
        """ retrieve sharing target and attributes by map """
        # Lookup
        logger.debug("TRACE/sharing: lookup ShareType=%r PathOrToken=%r User=%r)", ShareType, PathOrToken, User)
        for row in self._sharing_cache:
            if row['ShareType'] != ShareType:
                continue
            elif row['PathOrToken'] != PathOrToken:
                continue
            elif User and row['User'] != User:
                continue
            elif row['EnabledByOwner'] != True:
                continue
            elif row['EnabledByUser'] != True:
                continue
            PathMapped = row['PathMapped']
            Owner = row['Owner']
            UserShare = row['User']
            Permissions = row['Permissions']
            Hidden: bool = (row['HiddenByOwner'] or row['HiddenByUser'])
            logger.debug("TRACE/sharing: map %r to %r (Owner=%r User=%r Permissions=%r Hidden=%s)", PathOrToken, PathMapped, Owner, UserShare, Permissions, Hidden)
            return {
                    "mapped": True,
                    "PathOrToken": PathOrToken,
                    "PathMapped": PathMapped,
                    "Owner": Owner,
                    "User": UserShare,
                    "Hidden": Hidden,
                    "Permissions": Permissions}
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
                     HiddenByUser: Union[bool | None] = None) -> list[dict]:
        """ retrieve sharing """
        row: dict
        result = []

        logger.debug("TRACE/sharing/list/called: HiddenByOwner=%s HiddenByUser=%s", HiddenByOwner, HiddenByUser)

        for row in self._sharing_cache:
            logger.debug("TRACE/sharing/list/row: test: %r", row)
            if ShareType is not None and row['ShareType'] != ShareType:
                continue
            elif Owner is not None and row['Owner'] != Owner:
                continue
            elif User is not None and row['User'] != User:
                continue
            elif PathOrToken is not None and row['PathOrToken'] != PathOrToken:
                continue
            elif PathMapped is not None and row['PathMapped'] != PathMapped:
                continue
            elif EnabledByOwner is not None and row['EnabledByOwner'] != EnabledByOwner:
                continue
            elif EnabledByUser is not None and row['EnabledByUser'] != EnabledByUser:
                continue
            elif HiddenByOwner is not None and row['HiddenByOwner'] != HiddenByOwner:
                continue
            elif HiddenByUser is not None and row['HiddenByUser'] != HiddenByUser:
                continue
            logger.debug("TRACE/sharing/list/row: add: %r", row)
            result.append(row)
        return result

    def create_sharing(self,
                       ShareType: str,
                       PathOrToken: str, PathMapped: str,
                       Owner: str, User: str,
                       Permissions: str = "r",
                       EnabledByOwner: bool = False, EnabledByUser: bool = False,
                       HiddenByOwner:  bool = True, HiddenByUser:  bool = True,
                       Timestamp: int = 0) -> dict:
        """ create sharing """
        row: dict

        logger.debug("TRACE/sharing: ShareType=%r", ShareType)
        if ShareType == "token":
            logger.debug("TRACE/sharing/token/create: PathOrToken=%r Owner=%r PathMapped=%r User=%r Permissions=%r", PathOrToken, Owner, PathMapped, User, Permissions)
            # check for duplicate token entry
            for row in self._sharing_cache:
                if row['ShareType'] != "token":
                    continue
                if row['PathOrToken'] == PathOrToken:
                    # must be unique systemwide
                    logger.error("sharing/token/create: PathOrToken already exists: PathOrToken=%r", PathOrToken)
                    return {"status": "conflict"}
        elif ShareType == "map":
            logger.debug("TRACE/sharing/map/create: PathOrToken=%r Owner=%r PathMapped=%r User=%r Permissions=%r", PathOrToken, Owner, PathMapped, User, Permissions)
            # check for duplicate map entry
            for row in self._sharing_cache:
                if row['ShareType'] != "map":
                    continue
                if row['PathMapped'] == PathMapped and row['User'] == User and row['PathOrToken'] == PathOrToken:
                    # must be unique systemwide
                    logger.error("sharing/map/create: entry already exists: PathMapped=%r User=%r", PathMapped, User)
                    return {"status": "conflict"}
        else:
            return {"status": "error"}

        row = {"ShareType": ShareType,
               "PathOrToken": PathOrToken,
               "PathMapped": PathMapped,
               "Owner": Owner,
               "User": User,
               "Permissions": Permissions,
               "EnabledByOwner": EnabledByOwner,
               "EnabledByUser": EnabledByUser,
               "HiddenByOwner": HiddenByOwner,
               "HiddenByUser": HiddenByUser,
               "TimestampCreated": str(Timestamp),
               "TimestampUpdated": str(Timestamp)}
        logger.debug("TRACE/sharing/*/create: add row: %r", row)
        # TODO: add locking
        self._sharing_cache.append(row)
        if self._write_csv(self._sharing_db_file):
            logger.debug("TRACE/sharing_by_token: write CSV done")
            return {"status": "success"}
        logger.error("sharing/add_sharing_by_token: cannot update CSV database")
        return {"status": "error"}

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
        if ShareType == "token":
            logger.debug("TRACE/sharing/token/update: PathOrToken=%r Owner=%r", PathOrToken, Owner)
        elif ShareType == "map":
            logger.debug("TRACE/sharing/map/update: PathOrToken=%r Owner=%r PathMapped=%r", PathOrToken, Owner, PathMapped)
        else:
            raise  # should not be reached

        # lookup token
        found = False
        index = 0
        for row in self._sharing_cache:
            if row['ShareType'] != ShareType:
                pass
            elif row['PathOrToken'] != PathOrToken:
                pass
            else:
                found = True
                break
            index += 1

        if found:
            logger.debug("TRACE/sharing/*/update: found index=%d", index)
            if row['Owner'] != Owner:
                return {"status": "permission-denied"}
            logger.debug("TRACE/sharing/*/update: Owner=%r PathOrToken=%r index=%d", Owner, PathOrToken, index)

            logger.debug("TRACE/sharing/*/update: orig row=%r", row)

            # CSV: remove+adjust+readd
            if PathMapped is not None:
                row["PathMapped"] = PathMapped
            if Permissions is not None:
                row["Permissions"] = Permissions
            if User is not None:
                row["User"] = User
            if EnabledByOwner is not None:
                row["EnabledByOwner"] = EnabledByOwner
            if HiddenByOwner is not None:
                row["HiddenByOwner"] = HiddenByOwner
            # update timestamp
            row["TimestampUpdated"] = Timestamp

            logger.debug("TRACE/sharing/*/update: adj  row=%r", row)

            # TODO: add locking
            # replace row
            self._sharing_cache.pop(index)
            self._sharing_cache.append(row)
            if self._write_csv(self._sharing_db_file):
                logger.debug("TRACE/sharing_by_token: write CSV done")
                return {"status": "success"}
            logger.warning("sharing/sharing_by_token: cannot update CSV database")
            return {"status": "error"}
        else:
            return {"status": "not-found"}

    def delete_sharing(self,
                       ShareType: str,
                       PathOrToken: str, Owner: str,
                       PathMapped: Union[str | None] = None) -> dict:
        """ delete sharing """
        if ShareType == "token":
            logger.debug("TRACE/sharing/token/delete: PathOrToken=%r Owner=%r", PathOrToken, Owner)
        elif ShareType == "map":
            logger.debug("TRACE/sharing/map/delete: PathOrToken=%r Owner=%r PathMapped=%r", PathOrToken, Owner, PathMapped)
        else:
            raise  # should not be reached

        # lookup token
        found = False
        index = 0
        for row in self._sharing_cache:
            if row['ShareType'] != ShareType:
                pass
            elif row['PathOrToken'] != PathOrToken:
                pass
            else:
                if ShareType == "map":
                    # extra filter
                    if row['PathMapped'] != PathMapped:
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
            self._sharing_cache.pop(index)

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
                       PathMapped: Union[str | None] = None,
                       User: Union[str | None] = None,
                       Timestamp: int = 0) -> dict:
        """ toggle sharing """
        row: dict

        if Action not in sharing.API_SHARE_TOGGLES_V1:
            # should not happen
            raise

        logger.debug("TRACE/sharing/*/" + Action + ": ShareType=%r OwnerOrUser=%r User=%r PathOrToken=%r PathMapped=%r Action=%r", ShareType, OwnerOrUser, User, PathOrToken, PathMapped, Action)

        # lookup entry
        found = False
        index = 0
        for row in self._sharing_cache:
            logger.debug("TRACE/sharing/*/" + Action + ": check: %r", row)
            if row['ShareType'] != ShareType:
                pass
            elif row['PathOrToken'] != PathOrToken:
                pass
            elif PathMapped and row['PathMapped'] != PathMapped:
                pass
            elif row['Owner'] == OwnerOrUser:
                # owner has requested filter-by-user
                if User and row['User'] != User:
                    pass
                else:
                    found = True
                    break
            else:
                found = True
                break
            index += 1

        if found:
            # logger.debug("TRACE/sharing/*/" + Action + ": found: %r", row)
            if User and row['User'] != User:
                return {"status": "permission-denied"}
            elif row['Owner'] == OwnerOrUser:
                pass
            elif row['User'] == OwnerOrUser:
                pass
            else:
                return {"status": "permission-denied"}

            # TODO: locking
            if row['Owner'] == OwnerOrUser:
                logger.debug("TRACE/sharing/" + ShareType + "/" + Action + ": Owner=%r User=%r PathOrToken=%r index=%d", OwnerOrUser, User, PathOrToken, index)
                if Action == "disable":
                    row['EnabledByOwner'] = False
                elif Action == "enable":
                    row['EnabledByOwner'] = True
                elif Action == "hide":
                    row['HiddenByOwner'] = True
                elif Action == "unhide":
                    row['HiddenByOwner'] = False
                row['TimestampUpdated'] = str(Timestamp)
            if row['User'] == OwnerOrUser:
                logger.debug("TRACE/sharing/" + ShareType + "/" + Action + ": User=%r PathOrToken=%r index=%d", OwnerOrUser, PathOrToken, index)
                if Action == "disable":
                    row['EnabledByUser'] = False
                elif Action == "enable":
                    row['EnabledByUser'] = True
                elif Action == "hide":
                    row['HiddenByUser'] = True
                elif Action == "unhide":
                    row['HiddenByUser'] = False

            row['TimestampUpdated'] = str(Timestamp)

            # remove
            self._sharing_cache.pop(index)
            # readd
            self._sharing_cache.append(row)

            # TODO: add locking
            if self._write_csv(self._sharing_db_file):
                logger.debug("TRACE: write CSV done")
                return {"status": "success"}
            logger.error("sharing: cannot update CSV database")
            return {"status": "error"}
        else:
            return {"status": "not-found"}

    # local functions
    def _create_empty_csv(self, file: str) -> bool:
        with open(file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=sharing.DB_FIELDS_V1)
            writer.writeheader()
        return True

    def _load_csv(self, file: str) -> bool:
        logger.debug("sharing database load begin: %r", file)
        with open(file, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile, fieldnames=sharing.DB_FIELDS_V1)
            self._lines = 0
            for row in reader:
                # check for duplicates
                dup = False
                for row_cached in self._sharing_cache:
                    if row == row_cached:
                        dup = True
                        break
                if dup:
                    continue
                self._sharing_cache.append(row)
                self._lines += 1
        logger.debug("sharing database load end: %r", file)
        return True

    def _write_csv(self, file: str) -> bool:
        with open(file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=sharing.DB_FIELDS_V1)
            writer.writerows(self._sharing_cache)
        return True
