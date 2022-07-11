"""
gallia-analyze Reporter module
"""
import os
import numpy as np
import pandas as pd
from pandas.core.indexing import IndexingError
from gallia.analyzer.operator import Operator
from gallia.analyzer.xl_generator import ExcelGenerator
from gallia.analyzer.config import TblStruct, NUM_ECU_MODES
from gallia.analyzer.mode_config import LogMode, ScanMode
from gallia.analyzer.name_config import ColNm, TblNm
from gallia.analyzer.exceptions import ColumnMismatchException, EmptyTableException


class Reporter(Operator):
    """
    Reporter class for generating EXCEL report and visualizing data with graphs and data frames.
    """

    def __init__(self, path: str = "", log_mode: LogMode = LogMode.STD_OUT):
        Operator.__init__(self, path, log_mode)
        self.msg_head = "[Reporter] "
        self.out_path = f"./reports_{os.path.basename(path)}/"
        self.abn_serv_vec = np.array([])
        self.abn_iden_vec = np.array([])
        self.xl_ext = ".xlsx"

    def iterate_all(self, out_path: str, show_psb: bool = False) -> bool:
        """
        consolidate all scan_identifier runs for all services by identifier respectively into EXCEL files.
        """
        for serv in self.iso_serv_by_iden_vec:
            if not self.consolidate_xl_iden(serv, out_path, show_psb):
                continue
        return True

    def consolidate_xl_serv(self, out_path: str, show_psb: bool = False) -> bool:
        """
        consolidate all scan_service runs sorted by ECU mode into one EXCEL file.
        """
        if not self.load_meta(force=True):
            return False
        self.load_ven_sess()
        self.load_ven_lu()
        self.log(f"consolidating scan_service by ECU mode from {self.db_path} ...")
        self.set_path_prefix(out_path)
        xl_generator = ExcelGenerator(self.db_path, self.log_mode)
        xl_is_empty = True
        for ecu_mode in np.arange(self.num_modes):
            try:
                sql = f"""
                SELECT * FROM "{TblNm.serv}"
                WHERE "{ColNm.ecu_mode}" = {str(ecu_mode)};
                """
                raw_df = self.get_df_by_query(sql, False)
                self.check_df(raw_df, TblStruct.serv)
                if not self.load_sid_oi_from_df(raw_df, ecu_mode):
                    continue
                entries_vec = self.get_entries_oi(ScanMode.SERV, show_psb)
                xl_generator.write_xl(entries_vec, raw_df, ScanMode.SERV, ecu_mode)
                xl_is_empty = False
            except (
                IndexError,
                ColumnMismatchException,
                AttributeError,
            ) as exc:
                self.log("consolidating scan_service failed", True, exc)
                continue
            except EmptyTableException:
                self.log(f"nothing to report for ECU mode {ecu_mode}.")
        if xl_is_empty:
            return False
        self.set_path_prefix(out_path)
        out_path = self.get_path(
            "all_services_by_ecu_mode", self.xl_ext, rm_if_exists=True
        )
        if not xl_generator.save_close_xl(out_path):
            return False
        return True

    def consolidate_xl_iden(
        self, serv: int, out_path: str, show_psb: bool = False
    ) -> bool:
        """
        consolidate all scan_identifier runs sorted by ECU mode
        for a certain given service into one EXCEL file.
        """
        if serv not in self.iso_serv_by_iden_vec:
            self.log("given Service ID is not service by identifier.")
            return False
        if not self.load_meta(force=True):
            return False
        self.load_ven_sess()
        self.load_ven_lu()
        self.log(
            f"consolidating for Service ID 0x{serv:02X} {self.iso_serv_code_dict[serv]} from {self.db_path} ..."
        )
        self.set_path_prefix(out_path)
        xl_generator = ExcelGenerator(self.db_path, self.log_mode)
        xl_is_empty = True
        if self.num_modes == 0:
            num_modes = NUM_ECU_MODES
            self.log(
                f"no information about ECU modes. trying {NUM_ECU_MODES} mode(s)..."
            )
        else:
            num_modes = self.num_modes
        for ecu_mode in np.arange(num_modes):
            try:
                sql = f"""
                SELECT * FROM "{TblNm.iden}"
                WHERE "{ColNm.ecu_mode}" = {str(ecu_mode)}
                AND "{ColNm.serv}" = {str(serv)};
                """
                raw_df = self.get_df_by_query(sql, False)
                self.check_df(raw_df, TblStruct.iden)
                self.load_iden_oi_from_df(raw_df, ecu_mode)
                entries_vec = self.get_entries_oi(ScanMode.IDEN, show_psb)
                if xl_generator.write_xl(entries_vec, raw_df, ScanMode.IDEN, ecu_mode):
                    xl_is_empty = False
            except (
                IndexError,
                ColumnMismatchException,
                AttributeError,
            ) as exc:
                self.log("consolidating scan_identifier failed", True, exc)
                continue
            except EmptyTableException:
                self.log(f"nothing to report for ECU mode {ecu_mode}.")
        if xl_is_empty:
            self.log(f"nothing to report for Service ID 0x{serv:02X}")
            return False
        self.set_path_prefix(out_path)
        out_path = self.get_path(
            f"0x{serv:02X}_{self.iso_serv_code_dict[serv]}",
            self.xl_ext,
            rm_if_exists=True,
        )
        if not xl_generator.save_close_xl(out_path):
            return False
        return True

    def report_xl(
        self,
        runs_vec: np.ndarray,
        show_psb: bool = False,
        out_path: str = "",
    ) -> bool:
        """
        generate EXCEL report for given input runs.
        """
        if not self.load_meta(force=True):
            return False
        self.load_ven_sess()
        self.load_ven_lu()
        self.set_path_prefix(out_path)
        for run in runs_vec:
            self.report_xl_each_run(run, show_psb)
        return True

    def report_xl_each_run(self, run: int, show_psb: bool = False) -> bool:
        """
        generate EXCEL report for a certain run.
        """
        self.log(f"reporting run #{str(run)} from {self.db_path} ...")
        scan_mode = self.get_scan_mode(run)
        if scan_mode == ScanMode.SERV:
            return self.report_xl_serv(run, show_psb)
        if scan_mode == ScanMode.IDEN:
            return self.report_xl_iden(run, show_psb)
        return False

    def report_xl_serv(self, run: int, show_psb: bool = False) -> bool:
        """
        generate EXCEL report for a certain run of scan_service.
        """
        try:
            raw_df = self.read_run_db(TblNm.serv, run)
            self.check_df(raw_df, TblStruct.serv)
            self.load_sid_oi_from_df(raw_df)
            entries_vec = self.get_entries_oi(ScanMode.SERV, show_psb)
            xl_generator = ExcelGenerator(self.db_path, self.log_mode)
            if not xl_generator.write_xl(entries_vec, raw_df, ScanMode.SERV):
                return False
            out_path = self.get_path(
                f"serv_run{run:02}", self.xl_ext, rm_if_exists=True
            )
            if not xl_generator.save_close_xl(out_path):
                return False
        except (EmptyTableException, ColumnMismatchException, AttributeError) as exc:
            self.log("reporting scan_service failed", True, exc)
            return False
        return True

    def report_xl_iden(self, run: int, show_psb: bool = False) -> bool:
        """
        generate EXCEL report for a certain run of scan_identifier.
        """
        try:
            raw_df = self.read_run_db(TblNm.iden, run)
            self.check_df(raw_df, TblStruct.iden)
            self.load_iden_oi_from_df(raw_df)
            entries_vec = self.get_entries_oi(ScanMode.IDEN, show_psb)
            xl_generator = ExcelGenerator(self.db_path, self.log_mode)
            if not xl_generator.write_xl(entries_vec, raw_df, ScanMode.IDEN):
                return False
            out_path = self.get_path(
                f"iden_run{run:02}", self.xl_ext, rm_if_exists=True
            )
            if not xl_generator.save_close_xl(out_path):
                return False
        except (EmptyTableException, ColumnMismatchException, AttributeError) as exc:
            self.log("reporting scan_identifier failed", True, exc)
            return False
        return True

    def set_path_prefix(self, path: str = "") -> None:
        """
        set path prefix for EXCEL report file to save.
        """
        if path == "":
            self.out_path = os.path.expanduser(
                f"./reports_{os.path.basename(self.db_path)}/"
            )
        elif path == ".":
            self.out_path = os.path.expanduser("./")
        elif path == "..":
            self.out_path = os.path.expanduser("../")
        elif path[-1] == "/":
            self.out_path = os.path.expanduser(path)
        else:
            self.out_path = os.path.expanduser(path + "/")

    def get_path(
        self, suffix: str = "", ext: str = ".xlsx", rm_if_exists: bool = False
    ) -> str:
        """
        get path for EXCEL report file by combining path prefix,
        run number and EXCEL extention.
        """
        try:
            dir_name = os.path.dirname(self.out_path)
            file_name = os.path.basename(self.out_path)
            if dir_name == "":
                dir_name = "./"
            out_path = os.path.join(dir_name, file_name + str(suffix) + ext)
            if os.path.isdir(dir_name):
                if os.path.isfile(out_path) and rm_if_exists:
                    os.remove(out_path)
                    self.log(f"existing file removed from {out_path}")
            else:
                os.mkdir(dir_name)
                self.log(f"directory created at {dir_name}")
        except (OSError) as exc:
            self.log("getting path failed", True, exc)
            return f"./reports/run{str(suffix)}{ext}"
        return out_path

    def get_entries_oi(self, scan_mode: ScanMode, show_psb: bool = False) -> np.ndarray:
        """
        get services or identifieres of interest to display in summary sheet.
        """
        if show_psb:
            if scan_mode == ScanMode.SERV:
                return np.arange(256)
            if scan_mode == ScanMode.IDEN:
                return np.arange(65536)
        else:
            if scan_mode == ScanMode.SERV:
                return self.abn_serv_vec
            if scan_mode == ScanMode.IDEN:
                return self.abn_iden_vec
        return np.array([])

    def load_sid_oi(self, run: int, ecu_mode: int = -1) -> bool:
        """
        load services of interest for a given input run.
        """
        try:
            raw_df = self.read_run_db(TblNm.serv, run)
            self.check_df(raw_df, TblStruct.serv)
            if not self.load_sid_oi_from_df(raw_df, ecu_mode):
                return False
        except (EmptyTableException, ColumnMismatchException) as exc:
            self.log("loading services of interest failed", True, exc)
            return False
        return True

    def load_sid_oi_from_df(self, raw_df: pd.DataFrame, ecu_mode: int = -1) -> bool:
        """
        load services of interest from input raw data frame.
        """
        try:
            dft_err_df = self.get_dft_err_df_from_raw(raw_df)
            dft_err_ser: pd.Series = dft_err_df.loc[ColNm.dft]
            cond_abn = pd.Series([False]).repeat(raw_df.shape[0]).reset_index(drop=True)
            sess_vec = np.array(dft_err_df.columns)
            raw_df[ColNm.combi] = list(zip(raw_df[ColNm.sess], raw_df[ColNm.resp]))
            for sess in sess_vec:
                cond_abn |= raw_df[ColNm.combi].apply(
                    lambda x, s=sess: (x[0] == s)
                    and (x[1] != dft_err_ser[s])
                    and (x[1] != -1)
                    and (x[1] != 0)
                )
            if ecu_mode != -1:
                cond_abn &= raw_df[ColNm.ecu_mode] == ecu_mode
            self.abn_serv_vec = np.sort(np.unique(raw_df.loc[cond_abn, ColNm.serv]))
        except (KeyError, IndexingError, AttributeError) as exc:
            self.log("loading services of interest from data frame failed", True, exc)
            return False
        return True

    def load_iden_oi(self, run: int, ecu_mode: int = -1) -> bool:
        """
        load identifiers of interest for a given input run.
        """
        try:
            raw_df = self.read_run_db(TblNm.iden, run)
            self.check_df(raw_df, TblStruct.iden)
            if not self.load_iden_oi_from_df(raw_df, ecu_mode):
                return False
        except (EmptyTableException, ColumnMismatchException) as exc:
            self.log("loading identifiers of interest failed", True, exc)
            return False
        return True

    def load_iden_oi_from_df(self, raw_df: pd.DataFrame, ecu_mode: int = -1) -> bool:
        """
        load identifiers of interest from input raw data frame.
        """
        try:
            serv_vec = np.sort(np.unique(raw_df[ColNm.serv]))
            if not serv_vec.size == 1:
                self.log("more than one service in a run", True)
                return False
            dft_err_df = self.get_dft_err_df_from_raw(raw_df)
            dft_err_ser: pd.Series = dft_err_df.loc[ColNm.dft]
            cond_abn = pd.Series([False]).repeat(raw_df.shape[0]).reset_index(drop=True)
            sess_vec = np.array(dft_err_df.columns)
            raw_df[ColNm.combi] = list(zip(raw_df[ColNm.sess], raw_df[ColNm.resp]))
            for sess in sess_vec:
                cond_abn |= raw_df[ColNm.combi].apply(
                    lambda x, s=sess: (x[0] == s)
                    and (x[1] != dft_err_ser[s])
                    and (x[1] != -1)
                )
            if ecu_mode != -1:
                cond_abn &= raw_df[ColNm.ecu_mode] == ecu_mode
            self.abn_iden_vec = np.sort(np.unique(raw_df.loc[cond_abn, ColNm.iden]))
        except (KeyError, IndexingError, AttributeError) as exc:
            self.log(
                "loading identifiers of interest from data frame failed", True, exc
            )
            return False
        return True
