# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""
gallia-analyze Extractor module
"""

from sqlite3 import OperationalError
import numpy as np
from gallia.analyzer.operator import Operator
from gallia.analyzer.config import TblStruct
from gallia.analyzer.mode_config import LogMode, ScanMode
from gallia.analyzer.name_config import TblNm, ColNm, VwNm
from gallia.services.uds.core.utils import g_repr


class Extractor(Operator):

    """
    Class for extracting attained scan result data in database,
    archiving it into relational tables.
    """

    def __init__(self, path: str = "", log_mode: LogMode = LogMode.STD_OUT):
        Operator.__init__(self, path, log_mode)

    def extract(self, runs_vec: np.ndarray) -> bool:
        """
        extract scan result data from JSON form in the database
        and save it into relational tables for given input runs.
        """
        if not self.load_meta(force=True):
            return False
        for run in runs_vec:
            self.extract_each_run(run)
        return True

    def extract_each_run(self, run: int) -> bool:
        """
        extract scan result data from JSON form in the database
        and save it into relational tables for a certain input run.
        """
        self.logger.result(f"extracting run #{str(run)} from {self.db_path} ...")
        self.check_boot(run)
        scan_mode = self.get_scan_mode(run)
        if scan_mode == ScanMode.SERV:
            return self.extract_serv(run)
        if scan_mode == ScanMode.IDEN:
            return self.extract_iden(run)
        return False

    def extract_serv(self, run: int) -> bool:
        """
        extract scan_service result data from JSON form in the database
        and save it into relational tables for a certain input run.
        """
        if self.get_scan_mode(run) != ScanMode.SERV:
            return False
        if not self.create_table(TblNm.serv, TblStruct.serv, True):
            return False
        if not self.delete_run_db(TblNm.serv, run):
            return False
        extract_sql = f"""
        DROP VIEW IF EXISTS "{VwNm.resp_vw}";
        CREATE VIEW "{VwNm.resp_vw}"
        AS SELECT "{ColNm.id}", "{ColNm.run}",
        "{ColNm.t_rqst}", "{ColNm.t_resp}",
        json_extract("request_data", '$.service_id') AS "{ColNm.serv}",
        json_extract("state", '$.session') AS "{ColNm.sess}",
        json_extract("state", '$.boot') AS "{ColNm.boot}",
        CASE WHEN json_extract("response_data", '$.service_id') != 127 THEN 0
        WHEN json_extract("response_data", '$.response_code') IS NULL THEN -1
        ELSE json_extract("response_data", '$.response_code')
        END "{ColNm.resp}"
        FROM "{TblNm.scan_result}" WHERE "{ColNm.run}" = {str(run)}
        AND "log_mode" = "explicit" OR "log_mode" = "emphasized";
        INSERT INTO "{TblNm.serv}" ("{ColNm.id}", "{ColNm.run}",
        "{ColNm.t_rqst}", "{ColNm.t_resp}",
        "{ColNm.ecu_mode}", "{ColNm.serv}",
        "{ColNm.sess}", "{ColNm.boot}", "{ColNm.resp}")
        SELECT "{ColNm.id}", "{ColNm.run}",
        "{ColNm.t_rqst}", "{ColNm.t_resp}",
        CASE WHEN "{ColNm.ecu_mode}" IS NULL THEN 0
        ELSE "{ColNm.ecu_mode}"
        END "{ColNm.ecu_mode}",
        "{ColNm.serv}", "{ColNm.sess}",
        CASE WHEN "{ColNm.boot}" IS NULL AND "{ColNm.sess}" = 2 THEN 1
        WHEN "{ColNm.boot}" IS NULL THEN 0
        ELSE "{ColNm.boot}"
        END "{ColNm.boot}",
        "{ColNm.resp}"
        FROM "{VwNm.resp_vw}"
        LEFT JOIN "{TblNm.meta}"
        ON "{TblNm.meta}"."{ColNm.run_id}" = "{VwNm.resp_vw}"."{ColNm.run}";
        UPDATE "{TblNm.serv}" SET "{ColNm.fail}" = 255;
        DROP VIEW IF EXISTS "{VwNm.resp_vw}";
        """
        try:
            self.cur.executescript(extract_sql)
            self.con.commit()
        except OperationalError as exc:
            self.logger.error(f"extracting scan_service failed: {g_repr(exc)}")
            return False
        return True

    def extract_iden(self, run: int) -> bool:
        """
        extract scan_identifier result data from JSON form in the database
        and save it into relational tables for a certain input run.
        """
        if self.get_scan_mode(run) != ScanMode.IDEN:
            return False
        if not self.create_table(TblNm.iden, TblStruct.iden, True):
            return False
        if not self.delete_run_db(TblNm.iden, run):
            return False
        extract_sql = f"""
        DROP VIEW IF EXISTS "{VwNm.resp_vw}";
        CREATE VIEW "{VwNm.resp_vw}"
        AS SELECT "{ColNm.id}", "{ColNm.run}",
        "{ColNm.t_rqst}", "{ColNm.t_resp}",
        json_extract("request_data", '$.service_id') AS "{ColNm.serv}",
        json_extract("state", '$.session') AS "{ColNm.sess}",
        json_extract("state", '$.boot') AS "{ColNm.boot}",
        CASE WHEN json_extract("request_data", '$.service_id') = 49
        THEN json_extract("request_data", '$.sub_function')
        ELSE -1
        END "{ColNm.sbfn}",
        CASE WHEN json_extract("request_data", '$.service_id') = 49
        THEN json_extract("request_data", '$.routine_identifier')
        WHEN json_extract("request_data", '$.service_id') = 39
        AND json_extract("request_data", '$.sub_function') IS NULL THEN -1
        WHEN json_extract("request_data", '$.service_id') = 39
        THEN json_extract("request_data", '$.sub_function')
        WHEN json_extract("request_data", '$.service_id') = 0x11
        THEN json_extract("request_data", '$.sub_function')
        WHEN json_extract("request_data", '$.service_id') = 0x28
        THEN json_extract("request_data", '$.control_type') * 0x100 + json_extract("request_data", '$.communication_type')
        WHEN json_extract("request_data", '$.data_identifier') IS NULL
        THEN json_extract("request_data", '$.data_identifiers[0]')
        ELSE json_extract("request_data", '$.data_identifier')
        END "{ColNm.iden}",
        json_extract("request_data", '$.identifier') AS "{ColNm.iden}",
        CASE WHEN json_extract("response_data", '$.service_id') != 127 THEN 0
        WHEN json_extract("response_data", '$.response_code') IS NULL THEN -1
        ELSE json_extract("response_data", '$.response_code')
        END "{ColNm.resp}"
        FROM "{TblNm.scan_result}"
        WHERE "{ColNm.run}" = {str(run)}
        AND "log_mode" = "explicit" OR "log_mode" = "emphasized";
        INSERT INTO "{TblNm.iden}" ("{ColNm.id}", "{ColNm.run}",
        "{ColNm.t_rqst}", "{ColNm.t_resp}", "{ColNm.ecu_mode}",
        "{ColNm.serv}", "{ColNm.sess}", "{ColNm.boot}",
        "{ColNm.sbfn}", "{ColNm.iden}", "{ColNm.resp}")
        SELECT "{ColNm.id}", "{ColNm.run}",
        "{ColNm.t_rqst}", "{ColNm.t_resp}",
        CASE WHEN "{ColNm.ecu_mode}" IS NULL THEN 0
        ELSE "{ColNm.ecu_mode}"
        END "{ColNm.ecu_mode}",
        "{ColNm.serv}", "{ColNm.sess}",
        CASE WHEN "{ColNm.boot}" IS NULL AND "{ColNm.sess}" = 2 THEN 1
        WHEN "{ColNm.boot}" IS NULL THEN 0
        ELSE "{ColNm.boot}"
        END "{ColNm.boot}",
        "{ColNm.sbfn}", "{ColNm.iden}", "{ColNm.resp}"
        FROM "{VwNm.resp_vw}"
        LEFT JOIN "{TblNm.meta}"
        ON "{TblNm.meta}"."{ColNm.run_id}" = "{VwNm.resp_vw}"."{ColNm.run}";
        UPDATE "{TblNm.iden}" SET "{ColNm.fail}" = 255;
        DROP VIEW IF EXISTS "{VwNm.resp_vw}";
        """
        try:
            self.cur.executescript(extract_sql)
            self.con.commit()
        except OperationalError as exc:
            self.logger.error(f"extracting scan_identifier failed: {g_repr(exc)}")
            return False
        return True

    def check_boot(self, run: int) -> bool:
        try:
            check_sql = f"""
            SELECT json_extract("state", '$.boot') as "{ColNm.boot}"
            FROM "{TblNm.scan_result}" WHERE "{ColNm.run}" = {str(run)};
            """
            boot_df = self.get_df_by_query(check_sql)
            if boot_df.shape[0] == 0:
                return False
            boot_types_vec = np.array([0, 1])  # vendor-specific
            boot_ok = bool(
                boot_df[ColNm.boot].apply(lambda x: x in boot_types_vec).all()
            )
            if not boot_ok:
                self.logger.warning("boot information not complete")
        except (KeyError, AttributeError, OperationalError) as exc:
            self.logger.error(f"checking boot information failed: {g_repr(exc)}")
            return False
        return boot_ok
