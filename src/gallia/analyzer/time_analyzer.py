"""
gallia-analyze Time Analyzer module
"""
import json
import numpy as np
import pandas as pd
from pandas.core.indexing import IndexingError
import matplotlib.pyplot as plt
from gallia.analyzer.exceptions import ColumnMismatchException, EmptyTableException
from gallia.analyzer.reporter import Reporter
from gallia.analyzer.config import PltDesign, TblStruct, SrcPath, DFT_T_PREC
from gallia.analyzer.mode_config import ScanMode, LogMode
from gallia.analyzer.name_config import ColNm, TblNm, KyNm

if __name__ == "__main__":
    exit()


class TimeAnalyzer(Reporter):
    """
    Time Analyzer class for reaction time analysis.
    """

    def __init__(
        self,
        path: str = "",
        t_prec: int = DFT_T_PREC,
        log_mode: LogMode = LogMode.STD_OUT,
    ):
        Reporter.__init__(self, path, log_mode)
        self.msg_head = "[TimeAnalyzer] "
        self.t_prec = t_prec
        self.jpg_ext = ".jpg"
        self.csv_ext = ".csv"

    def extract_tra(self, runs_vec: np.ndarray) -> bool:
        """
        extract reaction times of scan_service or scan_identifier in database.
        """
        for run in runs_vec:
            self.extract_tra_each_run(run)
        return True

    def extract_tra_each_run(self, run: int) -> bool:
        """
        extract reaction times of each run.
        """
        self.log(f"extracting time for run #{str(run)} from {self.db_path} ...")
        scan_mode = self.get_scan_mode(run)
        if scan_mode == ScanMode.SERV:
            tbl_nm = TblNm.serv
            tbl_struct = TblStruct.serv
        if scan_mode == ScanMode.IDEN:
            tbl_nm = TblNm.iden
            tbl_struct = TblStruct.iden
        try:
            raw_df = self.read_run_db(tbl_nm, run)
            self.check_df(raw_df, tbl_struct)
            raw_df[ColNm.t_rqst] = (
                raw_df[ColNm.t_rqst]
                .astype(str)
                .apply(self.del_p)
                .apply(self.adj_len)
                .astype("int64")
            )
            raw_df[ColNm.t_resp] = (
                raw_df[ColNm.t_resp]
                .fillna(0)
                .astype(str)
                .apply(self.del_p)
                .apply(self.adj_len)
                .astype("int64")
            )
            raw_df.loc[raw_df[ColNm.t_resp] == 0, ColNm.t_resp] = raw_df.loc[
                raw_df[ColNm.t_resp] == 0, ColNm.t_rqst
            ]
            raw_df[ColNm.t_react] = raw_df[ColNm.t_resp] - raw_df[ColNm.t_rqst]
            raw_df.to_csv(
                self.get_path(f"time_run{run:02}", self.csv_ext, rm_if_exists=True)
            )
        except (
            KeyError,
            IndexingError,
            AttributeError,
            EmptyTableException,
            ColumnMismatchException,
        ) as exc:
            self.log(f"extracting reaction time for run #{run} failed", True, exc)
            return False
        return True

    def plot_tra(self, runs_vec: np.ndarray) -> bool:
        """
        plot service ID or identifier and reaction time in scatter plot.
        """
        for run in runs_vec:
            self.plot_tra_each_run(run)
        return True

    def plot_tra_each_run(self, run: int) -> bool:
        """
        plot reaction time for each run.
        """
        self.log(f"plotting reaction time for run #{str(run)} from {self.db_path} ...")
        scan_mode = self.get_scan_mode(run)
        if scan_mode == ScanMode.SERV:
            self.plot_tra_serv(run)
        if scan_mode == ScanMode.IDEN:
            self.plot_tra_iden(run)
        return True

    def plot_tra_serv(self, run: int) -> bool:
        """
        plot service ID and reaction time in scatter for a given run.
        """
        try:
            raw_df = pd.read_csv(self.get_path(f"time_run{run:02}", self.csv_ext))
            plt.rcParams["figure.figsize"] = [30, 25]
            with open(SrcPath.err_src, encoding="utf8") as resp_json:
                resp_ls = json.load(resp_json)
            c_tbl_dict = {}
            for resp in resp_ls:
                c_tbl_dict.update({resp[KyNm.resp]: f"#{resp[KyNm.rgb]}"})
            plt.style.use(PltDesign.plot_style)
            plt.scatter(
                x=raw_df[ColNm.serv],
                y=raw_df[ColNm.t_react],
                s=10,
                c=raw_df[ColNm.resp].map(c_tbl_dict),
                cmap="viridis",
            )
            plt.xlabel("Service ID")
            plt.ylabel("Reaction Time (nsec)")
            plt.savefig(
                self.get_path(
                    f"serv_tra_plot_p{self.t_prec}_run{run:02}",
                    self.jpg_ext,
                    rm_if_exists=True,
                )
            )
            plt.clf()
            plt.cla()
            plt.close()
        except (KeyError, IndexingError, AttributeError, FileNotFoundError) as exc:
            self.log(
                f"plotting service ID and reaction time in run #{run} failed", True, exc
            )
            return False
        return True

    def plot_tra_iden(self, run: int) -> bool:
        """
        plot identifier and reaction time in scatter for a given run.
        """
        try:
            raw_df = pd.read_csv(self.get_path(f"time_run{run:02}", self.csv_ext))
            plt.rcParams["figure.figsize"] = [30, 25]
            with open(SrcPath.err_src, encoding="utf8") as resp_json:
                resp_ls = json.load(resp_json)
            c_tbl_dict = {}
            for resp in resp_ls:
                c_tbl_dict.update({resp[KyNm.resp]: f"#{resp[KyNm.rgb]}"})
            plt.style.use(PltDesign.plot_style)
            plt.scatter(
                x=raw_df[ColNm.iden],
                y=raw_df[ColNm.t_react],
                s=10,
                c=raw_df[ColNm.resp].map(c_tbl_dict),
                cmap="viridis",
            )
            plt.xlabel("Identifier")
            plt.ylabel("Reaction Time (nsec)")
            plt.savefig(
                self.get_path(
                    f"iden_tra_plot_p{self.t_prec}_run{run:02}",
                    self.jpg_ext,
                    rm_if_exists=True,
                )
            )
            plt.clf()
            plt.cla()
            plt.close()
        except (KeyError, IndexingError, AttributeError, FileNotFoundError) as exc:
            self.log(
                f"plotting identifier and reaction time in run #{run} failed", True, exc
            )
            return False
        return True

    def hist_tra(self, runs_vec: np.ndarray) -> bool:
        """
        create a histogram of reaction time.
        """
        for run in runs_vec:
            self.hist_tra_each_run(run)
        return True

    def hist_tra_each_run(self, run: int) -> bool:
        """
        create a histogram of reaction time for a given run.
        """
        self.log(f"creating a histogram for run #{str(run)} from {self.db_path} ...")
        try:
            raw_df = pd.read_csv(self.get_path(f"time_run{run:02}", self.csv_ext))
            plt.style.use(PltDesign.hist_style)
            plt.hist(raw_df[ColNm.t_react], bins=500)
            plt.savefig(
                self.get_path(
                    f"tra_hist_p{self.t_prec}_run{run:02}",
                    self.jpg_ext,
                    rm_if_exists=True,
                )
            )
            plt.clf()
            plt.cla()
            plt.close()
        except (KeyError, IndexingError, AttributeError, FileNotFoundError) as exc:
            self.log(
                f"establishing histogram of identifiers in run #{run} failed", True, exc
            )
            return False
        return True

    def adj_len(self, t_stamp: str) -> str:
        """
        adjust the length of time stamp to the given time precision.
        """
        diff = self.t_prec - len(t_stamp)
        if diff < 0:
            return t_stamp[:diff]
        if diff > 0:
            return t_stamp + ("0" * diff)
        else:
            return t_stamp

    def del_p(self, t_stamp: str) -> str:
        """
        delete period in string.
        """
        return t_stamp.replace(".", "")
