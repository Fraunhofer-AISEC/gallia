"""
gallia-analyze Database Handler module
"""
import os
import sys
import sqlite3
from sqlite3 import OperationalError
import pandas as pd
from pandas.io.sql import DatabaseError
from gallia.analyzer.mode_config import LogMode
from gallia.analyzer.name_config import ColNm


class DatabaseHandler:
    """
    Basic class for all classes in gallia-analyze.
    Used for database connection, reading and writing data and log.
    """

    def __init__(self, path: str = "", log_mode: LogMode = LogMode.STD_OUT) -> None:
        self.set_db_path(path)
        self.log_mode = log_mode
        self.msg_head = "[DatabaseHandler] "
        self.err_head = "<error> "
        self.log_file = "logfile.txt"
        self.con: sqlite3.Connection
        self.cur: sqlite3.Cursor
        self.connect_db()

    def log(self, msg: str = "", err_flag: bool = False, exc: Exception = None) -> None:
        """
        print program messages in console or log program messages in log file.
        """
        if err_flag:
            if exc is None:
                total_msg = self.msg_head + self.err_head + msg + "\n"
            else:
                total_msg = (
                    self.msg_head
                    + self.err_head
                    + msg
                    + f": {type(exc).__name__} {str(exc)}"
                    + "\n"
                )
        else:
            total_msg = self.msg_head + msg + "\n"
        if self.log_mode == LogMode.LOG_FILE:
            try:
                with open(self.log_file, "a", encoding="utf8") as logfile:
                    logfile.write(total_msg)
            except FileNotFoundError:
                sys.stdout.write(total_msg)
        if self.log_mode == LogMode.STD_OUT:
            sys.stdout.write(total_msg)

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
        except (OperationalError) as exc:
            self.log("DB connection failed", True, exc)
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
            self.log("DB creating table failed", True, exc)
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
            self.log("DB clearing table failed", True, exc)
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
            self.log("DB deleting table failed", True, exc)
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
                self.log("DB query failed", True, exc)
            return pd.DataFrame()
        if raw_df.shape[0] == 0:
            if error_on:
                self.log("no entry in database.", True)
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
            self.log("deleting a run from DB failed", True, exc)
            return False
        return True

    def write_db(self, raw_df: pd.DataFrame, table_name: str) -> bool:
        """
        write data into a relational table in the database
        """
        try:
            raw_df.to_sql(table_name, self.con, if_exists="append", index=False)
        except (OperationalError, AttributeError) as exc:
            self.log("writing data to DB failed", True, exc)
            return False
        return True
