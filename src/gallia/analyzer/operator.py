# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""
gallia-analyze Operator module
"""
import json
from json.decoder import JSONDecodeError
from sqlite3 import OperationalError
from itertools import chain
from typing import cast
import numpy as np
import pandas as pd
from pandas.core.indexing import IndexingError
from gallia.analyzer.db_handler import DatabaseHandler
from gallia.analyzer.config import TblStruct, SrcPath, MiscError, NUM_ECU_MODES
from gallia.analyzer.iso_def import ISO_ERR_FOR_ALL, ISO_ERR_NOT_SUPP, ISO_SERV_BY_ID
from gallia.analyzer.failure import Failure
from gallia.analyzer.name_config import ColNm, TblNm, VwNm
from gallia.analyzer.mode_config import LogMode, ScanMode, OpMode
from gallia.analyzer.exceptions import EmptyTableException, ColumnMismatchException
from gallia.analyzer.constants import UDSIsoSessions
from gallia.services.uds.core.constants import UDSErrorCodes, UDSIsoServices
from gallia.services.uds.core.utils import g_repr


class Operator(DatabaseHandler):
    """
    Class for common basic operations and utilities such as loading metadata of runs,
    loading reference dictionaries, getting other information from a certain run in the database.
    """

    def __init__(self, path: str = "", log_mode: LogMode = LogMode.STD_OUT):
        DatabaseHandler.__init__(self, path, log_mode)
        self.num_modes = 0
        self.run_meta_df = pd.DataFrame()
        self.lu_iden_df = pd.DataFrame()
        self.ref_ven_df = pd.DataFrame()
        self.supp_serv_ven_vec = np.array([])
        self.sess_code_vec = np.array([])
        self.sess_code_dict: dict[int, str] = {}
        self.sess_name_dict: dict[str, int] = {}
        self.load_all_dicts()
        if self.connect_db():
            self.load_ref_iso()

    def check_df(self, raw_df: pd.DataFrame, cols_dict: dict) -> bool:
        """
        check if a data frame matches with the given data structure.
        may raise EmptyTableException or ColumnMismatchException.
        """
        if raw_df.shape == (0, 0):
            raise EmptyTableException
        for col in cols_dict.keys():
            if col not in raw_df.columns:
                raise ColumnMismatchException
        return True

    def get_runs(self) -> np.ndarray:
        """
        get all a numpy array of all runs in the database.
        """
        if self.load_meta(force=True):
            return self.run_meta_df.index.to_numpy()
        return np.array([])

    def get_scan_mode(self, run: int) -> ScanMode:
        """
        get scan mode of a run in the database.
        """
        if not self.load_meta():
            return ScanMode.UNKNOWN
        try:
            scan_mode_str = self.run_meta_df.loc[run, ColNm.scan_mode]
            if scan_mode_str == "scan-uds-services":
                return ScanMode.SERV
            if scan_mode_str == "scan-uds-identifiers":
                return ScanMode.IDEN
            else:
                self.logger.error(f"Unknown scan mode: {scan_mode_str}")
                return ScanMode.UNKNOWN
        except (KeyError, IndexingError, AttributeError) as exc:
            self.logger.error(f"getting scan mode failed: {g_repr(exc)}")
            return ScanMode.UNKNOWN

    def get_sid(self, run: int) -> int:
        """
        get Service ID for a given scan_identifier run.
        """
        try:
            if self.get_scan_mode(run) != ScanMode.IDEN:
                self.logger.error("scan mode is not scan_identifier")
                return -1
            raw_df = self.read_run_db(TblNm.iden, run)
            self.check_df(raw_df, TblStruct.iden)
            serv_vec = np.unique(raw_df[ColNm.serv])
            if serv_vec.shape[0] > 1:
                self.logger.warning("A run has more than one Service ID")
            serv_ser = raw_df[ColNm.serv].mode(dropna=True)
            if serv_ser.shape[0] > 1:
                self.logger.warning(
                    "A run has more than one most frequent Service ID"
                )
        except (
            KeyError,
            IndexingError,
            AttributeError,
            EmptyTableException,
            ColumnMismatchException,
        ) as exc:
            self.logger.error(f"getting Service ID failed: {g_repr(exc)}")
            return -1
        return serv_ser[0]

    def get_ecu_mode(self, run: int) -> int:
        """
        get ECU mode of a run in the database.
        """
        if not self.load_meta():
            return -1
        try:
            _ecu_mode = self.run_meta_df.loc[run, ColNm.ecu_mode]
            if isinstance(_ecu_mode, int):
                ecu_mode = _ecu_mode
            else:
                # ecu_mode must be positive integer in the current implementation
                # we use the dummy mode 0 if ECU does not use ecu_modes at all
                ecu_mode = 0
            return ecu_mode
        except (KeyError, IndexingError, AttributeError) as exc:
            self.logger.error(f"getting ECU mode failed: {g_repr(exc)}")
            return -1

    def get_op_mode(self, iso_on: bool) -> OpMode:
        """
        get analysis mode. Input of True returns vendor-specific analysis mode.
        """
        if iso_on:
            an_opt = OpMode.ISO
        else:
            an_opt = OpMode.VEN_SPEC
        return an_opt

    def get_sess_lu(self) -> np.ndarray:
        """
        get a vector of diagnostic sessions that are definded in vendor lookup table.
        """
        try:
            lu_df = self.read_db(TblNm.ven_lu)
            self.check_df(lu_df, TblStruct.ven_lu)
            sess_vec = np.unique(lu_df[ColNm.sess])
        except (
            KeyError,
            IndexingError,
            AttributeError,
            EmptyTableException,
            ColumnMismatchException,
        ) as exc:
            self.logger.error(
                f"getting sessions in lookup table failed: {g_repr(exc)}"
            )
            return np.array([])
        return sess_vec

    def get_ref_df_from_json(self, path: str) -> pd.DataFrame:
        """
        get reference summary from JSON file.
        """
        try:
            with open(path, encoding="utf8") as source_json:
                serv_ls = json.load(source_json)
            ref_df = pd.DataFrame()
            for serv in serv_ls:
                ser = pd.Series(serv)
                ref_df = pd.concat([ref_df, ser], axis=1)
            ref_df = ref_df.T
            ref_df.loc[:, ColNm.serv] = ref_df.loc[:, ColNm.serv].astype("int64")
            ref_df.sort_values(ColNm.serv)
            ref_df = ref_df.set_index(ColNm.serv)
        except (
            KeyError,
            IndexingError,
            AttributeError,
            FileNotFoundError,
            JSONDecodeError,
        ) as exc:
            self.logger.error(
                f"getting reference summary from JSON failed: {g_repr(exc)}"
            )
            return pd.DataFrame()
        return ref_df

    def get_dft_err_df_from_raw(self, raw_df: pd.DataFrame) -> pd.DataFrame:
        """
        get summarized data frame that shows most common error(default error)
        for each diagnostic session from raw data frame.
        """
        try:
            sess_vec = np.unique(raw_df[ColNm.sess])
            dft_err_df = pd.DataFrame([], index=[ColNm.dft], columns=sess_vec)
            for sess in sess_vec:
                cond = raw_df[ColNm.sess] == sess
                dft_err_df.loc[ColNm.dft, sess] = raw_df.loc[cond, ColNm.resp].mode()[0]
            dft_err_df.attrs[ColNm.serv] = list(np.unique(raw_df[ColNm.serv]))
        except (
            KeyError,
            IndexingError,
            AttributeError,
            EmptyTableException,
            ColumnMismatchException,
        ) as exc:
            self.logger.error(
                f"getting default error data frame failed: {g_repr(exc)}"
            )
            return pd.DataFrame()
        return dft_err_df

    def get_pos_res(self, search_id: int) -> str:
        """
        get positive response from data table with a scan entry ID.
        """
        try:
            res_sql = f"""
            SELECT json_extract("response_data", '$.data_records[0]')
            FROM "{TblNm.scan_result}" WHERE "{ColNm.id}" = {str(search_id)};
            """
            res_df = self.get_df_by_query(res_sql)
            resp = cast(str, res_df.iloc[0, 0])
        except (KeyError, IndexingError, AttributeError) as exc:
            self.logger.error(f"getting positive response failed: {g_repr(exc)}")
            return ""
        return resp

    def load_meta(self, force: bool = False) -> bool:
        """
        load meta data of all runs in the database.
        """
        if force:
            pass
        elif self.run_meta_df.shape != (0, 0):
            return True
        gen_meta_sql = f"""
        DROP VIEW IF EXISTS "{VwNm.ecu_vw}";
        DROP VIEW IF EXISTS "{VwNm.mode_vw}";
        CREATE VIEW "{VwNm.ecu_vw}"
        AS SELECT "{ColNm.id}", json_extract("properties_pre", "$.mode") AS "{ColNm.ecu_mode}"
        FROM "{TblNm.scan_run}";
        CREATE VIEW "{VwNm.mode_vw}"
        AS SELECT "{ColNm.id}" AS "{ColNm.run_id}",
        json_extract("command_meta", "$.group") ||  "-" || json_extract("command_meta", "$.subgroup") || "-" || json_extract("command_meta", "$.command") AS "{ColNm.scan_mode}"
        FROM "{TblNm.run_meta}";
        DROP TABLE IF EXISTS "{TblNm.meta}";
        CREATE TABLE "{TblNm.meta}"
        AS SELECT "{ColNm.run_id}", "{ColNm.ecu_mode}", "{ColNm.scan_mode}"
        FROM "{VwNm.ecu_vw}"
        INNER JOIN "{VwNm.mode_vw}"
        ON "{VwNm.ecu_vw}"."{ColNm.id}" = "{VwNm.mode_vw}"."{ColNm.run_id}";
        DROP VIEW IF EXISTS "{VwNm.ecu_vw}";
        DROP VIEW IF EXISTS "{VwNm.mode_vw}";
        """
        try:
            self.cur.executescript(gen_meta_sql)
            meta_df = self.read_db(TblNm.meta)
            if meta_df.shape == (0, 0):
                self.logger.error("no meta data")
                return False
            meta_df.set_index("run_id", inplace=True)
            self.run_meta_df = meta_df
        except (KeyError, IndexingError, AttributeError, OperationalError) as exc:
            self.logger.error(
                f"loading run meta data failed: {g_repr(exc)}",
            )
            return False
        return True

    def load_ven_lu(self, force: bool = False, num_modes: int = NUM_ECU_MODES) -> bool:
        """
        load reference summary for vendor-specific analysis from the database.
        """
        if force:
            pass
        elif self.ref_ven_df.shape != (0, 0):
            return True
        try:
            lu_df = self.read_db(TblNm.ven_lu)
            self.check_df(lu_df, TblStruct.ven_lu)
            supp_serv_vec = np.sort(np.unique(lu_df[ColNm.serv]))
            mode_vec = np.arange(num_modes)
            ven_lu_dict = {}
            self.num_modes = 0
            for mode in mode_vec:
                loi_df = lu_df[lu_df[ColNm.ecu_mode] == mode].copy()
                if loi_df.shape[0] == 0:
                    continue
                else:
                    self.num_modes += 1
                ref_df = pd.DataFrame(columns=supp_serv_vec)
                for serv in supp_serv_vec:
                    sess_ls = list(
                        np.sort(
                            np.unique(
                                loi_df.loc[loi_df[ColNm.serv] == serv, ColNm.sess]
                            )
                        )
                    )
                    sbfn_ls = list(
                        np.sort(
                            np.unique(
                                loi_df.loc[loi_df[ColNm.serv] == serv, ColNm.sbfn]
                            )
                        )
                    )
                    iden_ls = list(
                        np.sort(
                            np.unique(
                                loi_df.loc[
                                    loi_df[ColNm.serv] == serv,
                                    ColNm.iden,
                                ]
                            )
                        )
                    )
                    ref_df[serv] = pd.Series(
                        [sess_ls, sbfn_ls, iden_ls],
                        index=[ColNm.sess, ColNm.sbfn, ColNm.iden],
                    )
                ven_lu_dict[mode] = ref_df.T
            ven_lu_df = pd.concat(ven_lu_dict.values(), axis=1, keys=ven_lu_dict.keys())
            self.ref_ven_df = ven_lu_df
            self.supp_serv_ven_vec = np.sort(np.array(ven_lu_df.index))
        except (
            KeyError,
            IndexingError,
            AttributeError,
            EmptyTableException,
            ColumnMismatchException,
        ) as exc:
            self.logger.error(
                f"loading vendor-specific reference failed: {g_repr(exc)}"
            )
            return False
        return True

    def load_ref_iso(self, force: bool = False) -> bool:
        """
        load reference summary for UDS ISO standard.
        """
        if force:
            pass
        elif self.ref_ven_df.shape != (0, 0):
            return True
        try:
            ref_iso_df = self.get_ref_df_from_json(SrcPath.uds_iso_src)
            self.supp_serv_iso_vec = np.sort(np.array(ref_iso_df.index))
            self.ref_iso_df: pd.DataFrame = ref_iso_df.sort_index()
        except (KeyError, IndexingError, AttributeError) as exc:
            self.logger.error(
                f"loading reference summary for UDS ISO failed: {g_repr(exc)}"
            )
            return False
        return True

    def load_all_dicts(self) -> bool:
        """
        load necessary dictionaries for UDS ISO standard.
        """
        self.iso_err_means_not_supp_vec = np.array(ISO_ERR_NOT_SUPP)
        self.iso_supp_err_for_all_vec = np.array(ISO_ERR_FOR_ALL)
        self.iso_serv_by_iden_vec = np.array(ISO_SERV_BY_ID)
        self.iso_serv_name_dict = {serv.name: serv.value for serv in UDSIsoServices}
        self.iso_serv_name_dict.update({"noService": -1})
        self.iso_serv_code_dict = dict(
            (y, x) for x, y in self.iso_serv_name_dict.items()
        )
        self.iso_serv_code_vec = np.array(list(self.iso_serv_name_dict.values()))
        self.iso_err_name_dict = {
            e.name: e.value for e in chain(UDSErrorCodes, MiscError)
        }
        self.iso_err_code_dict = dict((y, x) for x, y in self.iso_err_name_dict.items())
        self.iso_err_code_vec = np.array(list(self.iso_err_name_dict.values()))
        self.iso_sess_name_dict = {sess.name: sess.value for sess in UDSIsoSessions}
        self.iso_sess_code_dict = dict(
            (y, x) for x, y in self.iso_sess_name_dict.items()
        )
        self.fail_name_dict = {fail.name: fail.value for fail in Failure}
        self.fail_code_dict = dict((y, x) for x, y in self.fail_name_dict.items())
        return True

    def load_ven_sess(self) -> bool:
        try:
            sess_df = self.read_db(TblNm.ven_sess)
            self.check_df(sess_df, TblStruct.ven_sess)
            sess_df = sess_df.set_index(ColNm.sess)
            self.sess_code_dict = sess_df[ColNm.sess_name].to_dict(dict)
            self.sess_name_dict = dict((y, x) for x, y in self.sess_code_dict.items())
            self.sess_code_vec = np.array(list(self.sess_code_dict.keys()))
        except (
            KeyError,
            IndexingError,
            AttributeError,
            EmptyTableException,
            ColumnMismatchException,
        ) as exc:
            self.sess_name_dict = self.iso_sess_name_dict
            self.sess_code_dict = self.iso_sess_code_dict
            self.logger.error(
                f"loading vendor-specific sessions failed: {g_repr(exc)}"
            )
            return False
        return True

    def load_lu_iden(self, serv: int, ecu_mode: int) -> bool:
        """
        load lookup reference of a certain service for scan_identifier analysis.
        """
        if serv not in self.iso_serv_by_iden_vec:
            return False
        try:
            raw_df = self.read_db(TblNm.ven_lu)
            self.check_df(raw_df, TblStruct.ven_lu)
            serv_df = raw_df[
                (raw_df[ColNm.serv] == serv) & (raw_df[ColNm.ecu_mode] == ecu_mode)
            ].copy()
            self.lu_iden_df = pd.DataFrame(
                np.unique(
                    list(
                        zip(
                            serv_df[ColNm.sess],
                            serv_df[ColNm.boot],
                            serv_df[ColNm.sbfn],
                            serv_df[ColNm.iden],
                            serv_df[ColNm.ecu_mode],
                        )
                    )
                ),
                columns=[ColNm.combi],
            )
        except (
            EmptyTableException,
            ColumnMismatchException,
            KeyError,
            AttributeError,
            OperationalError,
        ) as exc:
            self.lu_iden_df = pd.DataFrame()
            self.logger.error(
                f"loading lookup for service 0x{serv:02x} failed: {g_repr(exc)}"
            )
            return False
        return True

    def prepare_table(self) -> bool:
        """
        prepare relational tables to save data for scan_service and scan_identifier.
        """
        if not self.create_table(TblNm.serv, TblStruct.serv):
            self.logger.error("preparing table for scan_service failed")
            return False
        if not self.create_table(TblNm.iden, TblStruct.iden):
            self.logger.error("preparing table for scan_identifier failed")
            return False
        return True

    def prepare_alwd_all(
        self, ecu_mode: int = 0, op_mode: OpMode = OpMode.VEN_SPEC
    ) -> bool:
        """
        prepare reference relational tables for response, session and subfunctions.
        """
        if op_mode == OpMode.ISO:
            ref_df = self.ref_iso_df
        if op_mode == OpMode.VEN_SPEC:
            ref_df = cast(
                pd.DataFrame, self.ref_ven_df[ecu_mode]
            )  # this a nested DataFrame, which yields a DataFrame per ecu_mode
        if not self.prepare_alwd_res():
            return False
        if not self.prepare_alwd_sess_boot(op_mode, ecu_mode):
            return False
        if not self.prepare_alwd(
            TblNm.ref_sbfn, TblStruct.ref_sbfn, ColNm.sbfn, ref_df
        ):
            return False
        return True

    def prepare_alwd_res(self) -> bool:
        """
        prepare reference relational table for response.
        """
        if not self.prepare_alwd(
            TblNm.ref_resp,
            TblStruct.ref_resp,
            ColNm.resp,
            self.ref_iso_df,
        ):
            return False
        return True

    def prepare_alwd_sess_boot(
        self, op_mode: OpMode = OpMode.VEN_SPEC, ecu_mode: int = 0
    ) -> bool:
        """
        prepare reference relational table for session and boot.
        """
        try:
            if op_mode == OpMode.ISO:
                return self.prepare_alwd(
                    TblNm.ref_sess, TblStruct.ref_sess, ColNm.sess, self.ref_iso_df
                )
            if not self.create_table(TblNm.ref_sess, TblStruct.ref_sess):
                return False
            pair_ls = []
            ven_lu_df = self.read_db(TblNm.ven_lu)
            self.check_df(ven_lu_df, TblStruct.ven_lu)
            ven_lu_df = ven_lu_df[ven_lu_df[ColNm.ecu_mode] == ecu_mode]
            ven_lu_df[ColNm.combi] = list(
                zip(ven_lu_df[ColNm.serv], ven_lu_df[ColNm.sess], ven_lu_df[ColNm.boot])
            )
            entries_vec = np.unique(ven_lu_df[ColNm.combi])
            for entry in entries_vec:
                pair_ls.append((entry[0], entry[1], entry[2]))
            pair_df = pd.DataFrame(
                pair_ls, columns=[ColNm.serv, ColNm.sess, ColNm.boot]
            )
            self.write_db(pair_df, TblNm.ref_sess)
        except (
            KeyError,
            IndexError,
            AttributeError,
            EmptyTableException,
            ColumnMismatchException,
        ) as exc:
            self.logger.error(
                f"preparing table for session and boot failed: {g_repr(exc)}"
            )
            return False
        return True

    def prepare_alwd(
        self, table_name: str, table_struct: dict, col_name: str, ref_df: pd.DataFrame
    ) -> bool:
        """
        prepare a relational table for available diagnotic sessions, sub-functions
        or NRCs for Service IDs defined in UDS ISO Standard.
        """
        try:
            if not self.create_table(table_name, table_struct):
                return False
            pair_ls = []
            for serv in ref_df[col_name].index:
                entries_ls = ref_df.loc[serv, col_name]
                for entry in entries_ls:
                    pair_ls.append((serv, entry))
                if table_name == TblNm.ref_resp and col_name == ColNm.resp:
                    for entry in self.iso_supp_err_for_all_vec:
                        pair_ls.append((serv, entry))
            pair_df = pd.DataFrame(pair_ls, columns=[ColNm.serv, col_name])
            self.write_db(pair_df, table_name)
        except (KeyError, IndexError, AttributeError) as exc:
            self.logger.error(
                f"preparing table for availabilities failed: {g_repr(exc)}"
            )
            return False
        return True

    def clear(self) -> bool:
        """
        clear all relational tables in the database.
        """
        if not self.clear_alwd():
            return False
        table_ls = [
            TblNm.serv,
            TblNm.iden,
            TblNm.meta,
        ]
        for table_name in table_ls:
            if not self.delete_table(table_name):
                return False
        return True

    def clear_alwd(self) -> bool:
        """
        clear relational tables for reference in the database.
        """
        table_ls = [
            TblNm.ref_resp,
            TblNm.ref_sess,
            TblNm.ref_sbfn,
        ]
        for table_name in table_ls:
            if not self.delete_table(table_name):
                return False
        return True
