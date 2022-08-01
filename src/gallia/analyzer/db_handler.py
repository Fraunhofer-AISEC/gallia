# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""
gallia-analyze Database Handler module
"""
import os
import sqlite3
from sqlite3 import OperationalError
import pandas as pd
from pandas.io.sql import DatabaseError
from gallia.analyzer.mode_config import LogMode
from gallia.analyzer.name_config import ColNm
from gallia.utils import g_repr
from gallia.penlog import Logger


class DatabaseHandler:
    """
    Basic class for all classes in gallia-analyze.
    Used for database connection, reading and writing data and log.
    """

    def __init__(self, path: str = "", log_mode: LogMode = LogMode.STD_OUT) -> None:
        self.set_db_path(path)
        self.log_mode = log_mode
        self.con: sqlite3.Connection
        self.cur: sqlite3.Cursor
        self.logger: Logger = Logger("Analyzer")
        self.connect_db()

    def set_db_path(self, path: str = "") -> bool:
        """
        set path for database to read.
        """
        if path != "":
            self.db_path = os.path.expanduser(path)
        else:
            self.db_path = ""
            return False
        return True

    def connect_db(self) -> bool:
        """
        establish connection to database.
        """
        try:
            self.con = sqlite3.connect(self.db_path)
            self.cur = self.con.cursor()
        except OperationalError as exc:
            self.logger.log_error(f"DB connection failed: {g_repr(exc)}")
            return False
        return True

    def create_table(
        self, table_name: str, columns_dict: dict, not_exists: bool = False
    ) -> bool:
        """
        create a relational table in the database.
        """
        sql_columns = ""
        for key in columns_dict.keys():
            sql_columns += '"' + key + '" '
            sql_columns += columns_dict[key]
            sql_columns += ","

        sql_columns = sql_columns[:-1]
        if not_exists:
            create_sql = f"CREATE TABLE IF NOT EXISTS {table_name}({sql_columns});"
        else:
            create_sql = f"DROP TABLE IF EXISTS {table_name};CREATE TABLE {table_name}({sql_columns});"
        try:
            self.cur.executescript(create_sql)
            self.con.commit()
        except (OperationalError, AttributeError) as exc:
            self.logger.log_error(f"DB creating table failed: {g_repr(exc)}")
            return False
        return True

    def clear_table(self, table_name: str) -> bool:
        """
        clear(delete) all data in a relational table in the database.
        """
        try:
            self.cur.execute(f"DELETE FROM {table_name}")
            self.con.commit()
        except (OperationalError, AttributeError) as exc:
            self.logger.log_error(f"DB clearing table failed: {g_repr(exc)}")
            return False
        return True

    def delete_table(self, table_name: str) -> bool:
        """
        delete(drop) a relational table in the database.
        """
        try:
            self.cur.execute(f"DROP TABLE IF EXISTS {table_name}")
            self.con.commit()
        except (OperationalError, AttributeError) as exc:
            self.logger.log_error(f"DB deleting table failed: {g_repr(exc)}")
            return False
        return True

    def get_df_by_query(self, sql: str, error_on: bool = True) -> pd.DataFrame:
        """
        query in a database with SQL query string.
        """
        try:
            raw_df: pd.DataFrame = pd.read_sql_query(sql, self.con)
        except (DatabaseError, AttributeError) as exc:
            if error_on:
                self.logger.log_error(f"DB query failed: {g_repr(exc)}")
            return pd.DataFrame()
        if raw_df.shape[0] == 0:
            if error_on:
                self.logger.log_warning("no entry in database.")
            return pd.DataFrame()
        return raw_df

    def read_db(self, table_name: str) -> pd.DataFrame:
        """
        read out all the data in a relational table in the database.
        returns a pandas data frame.
        """
        return self.get_df_by_query(f"""SELECT * FROM "{table_name}";""")

    def read_run_db(self, table_name: str, run: int) -> pd.DataFrame:
        """
        read out the data of a run in a relational table in the database.
        returns a pandas data frame.
        """
        return self.get_df_by_query(
            f"""SELECT * FROM "{table_name}" WHERE "{ColNm.run}" = {str(run)};"""
        )

    def read_sid_db(self, table_name: str, serv: int) -> pd.DataFrame:
        """
        read out the data of a service ID in a relational table in the database.
        returns a pandas data frame.
        """
        return self.get_df_by_query(
            f"SELECT * FROM {table_name} WHERE {ColNm.serv} = {str(serv)}"
        )

    def delete_run_db(self, table_name: str, run: int) -> bool:
        """
        delete the data of a run in a relational table in the database.
        """
        del_sql = f"""DELETE FROM "{table_name}" WHERE "{ColNm.run}" = {str(run)};"""
        try:
            self.cur.executescript(del_sql)
            self.con.commit()
        except (OperationalError, AttributeError) as exc:
            self.logger.log_error(f"deleting a run from DB failed: {g_repr(exc)}")
            return False
        return True

    def write_db(self, raw_df: pd.DataFrame, table_name: str) -> bool:
        """
        write data into a relational table in the database
        """
        try:
            raw_df.to_sql(table_name, self.con, if_exists="append", index=False)
        except (OperationalError, AttributeError) as exc:
            self.logger.log_error(f"writing data to DB failed: {g_repr(exc)}")
            return False
        return True
