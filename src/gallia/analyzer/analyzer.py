"""
gallia-analyze Analyzer module
"""
import os
import json
from json.decoder import JSONDecodeError
from sqlite3 import OperationalError
import textwrap
from typing import Tuple
import numpy as np
from pandas.core.indexing import IndexingError
from gallia.analyzer.operator import Operator
from gallia.analyzer.config import SrcPath
from gallia.analyzer.mode_config import LogMode, ScanMode, OpMode
from gallia.analyzer.name_config import ColNm, KyNm, TblNm, VwNm, NEG_STR


class Analyzer(Operator):
    """
    Analyzer class for categorizing failures(undocumented, missing)
    at each scan mode(scan_service, scan_identifier)
    and operation mode(ISO or vendor-specific).
    """

    def __init__(
        self,
        path: str = "",
        log_mode: LogMode = LogMode.STD_OUT,
        debug_on: bool = False,
    ):
        Operator.__init__(self, path, log_mode)
        self.msg_head = "[Analyzer] "
        self.debug_on = debug_on

    def analyze(self, runs_vec: np.ndarray, op_mode: OpMode = OpMode.VEN_SPEC) -> bool:
        """
        analyze given input runs at a given operation mode.
        """
        if not self.load_meta(force=True):
            return False
        if op_mode == OpMode.VEN_SPEC:
            if not self.load_ven_lu():
                return False
            if not self.load_ven_sess():
                return False
        for run in runs_vec:
            self.analyze_each_run(run, op_mode)
        return True

    def analyze_each_run(self, run: int, op_mode: OpMode) -> bool:
        """
        analyze certain run at a given operation mode.
        """
        self.log(f"analyzing run #{str(run)} from {self.db_path} ...")
        scan_mode = self.get_scan_mode(run)
        if scan_mode == ScanMode.SERV:
            if not self.reset(TblNm.serv, run):
                return False
            return self.analyze_serv(run, op_mode)
        if scan_mode == ScanMode.IDEN:
            if not self.reset(TblNm.iden, run):
                return False
            return self.analyze_iden(run, op_mode)
        return False

    def reset(self, table_name: str, run: int) -> bool:
        """
        reset analysis results in relational table in database.
        """
        reset_sql = f"""
        UPDATE "{table_name}" SET "{ColNm.fail}" = 255 WHERE "{ColNm.run}" = {str(run)};
        """
        try:
            self.cur.executescript(reset_sql)
            self.con.commit()
        except (OperationalError, FileNotFoundError, KeyError) as exc:
            self.log("reseting analysis in place failed", True, exc)
            return False
        return True

    def analyze_serv(self, run: int, op_mode: OpMode) -> bool:
        """
        analyze scan_service result data for certain run at a given operation mode
        without using data frame direct in data base.
        """
        try:
            ecu_mode = self.get_ecu_mode(run)
            self.prepare_alwd_all(ecu_mode, op_mode)
            with open(SrcPath.cond_src, encoding="utf8") as source_json:
                cond_ls = json.load(source_json)
            analyze_sql = ""
            for cond_dict in cond_ls:
                try:
                    if cond_dict[KyNm.scan_mode] == KyNm.scan_serv:
                        fail, cond = self.interpret(cond_dict, op_mode, ScanMode.SERV)
                        update_sql = (
                            f"""UPDATE "{TblNm.serv}" """
                            + f"""SET "{ColNm.fail}" = {fail} """
                            + f"""WHERE "{ColNm.run}" = {str(run)} """
                            + f"""AND "{ColNm.fail}" = 255{cond};\n"""
                        )
                        analyze_sql += update_sql
                except KeyError as exc:
                    self.log("condition key reading failed", True, exc)
            if self.debug_on:
                if not os.path.isdir("debug"):
                    os.mkdir("debug")
                with open(
                    f"./debug/analyze_serv_{str(run)}.sql", "w", encoding="utf8"
                ) as file:
                    file.write(analyze_sql)
            self.cur.executescript(analyze_sql)
            self.con.commit()
            self.clear_alwd()
        except (
            OperationalError,
            FileNotFoundError,
            KeyError,
            IndexingError,
            AttributeError,
            JSONDecodeError,
            NotImplementedError,
        ) as exc:
            self.log("analyzing scan_service in place failed", True, exc)
            return False
        return True

    def analyze_iden(self, run: int, op_mode: OpMode) -> bool:
        """
        analyze scan_identifier result data for certain run at a given operation mode
        without using data frame direct in data base.
        """
        if op_mode == OpMode.ISO:
            self.log("ISO Standard analysis unavailable for scan_identifier.", True)
            return False
        self.prepare_alwd_res()
        try:
            with open(SrcPath.cond_src, encoding="utf8") as src_json:
                cond_ls = json.load(src_json)
            serv = self.get_sid(run)
            if serv == -1:
                return False
            create_view_sql = f"""
            DROP VIEW IF EXISTS "{VwNm.sess_alwd}";
            CREATE VIEW "{VwNm.sess_alwd}"
            AS SELECT "{ColNm.sess}"
            FROM "{TblNm.ven_lu}"
            WHERE "{ColNm.serv}" = {serv}
            GROUP BY "{ColNm.sess}";
            DROP VIEW IF EXISTS "{VwNm.sbfn_alwd}";
            CREATE VIEW "{VwNm.sbfn_alwd}"
            AS SELECT "{ColNm.sbfn}"
            FROM "{TblNm.ven_lu}"
            WHERE "{ColNm.serv}" = {serv}
            GROUP BY "{ColNm.sbfn}";
            DROP VIEW IF EXISTS "{VwNm.resp_alwd}";
            CREATE VIEW "{VwNm.resp_alwd}"
            AS SELECT "{ColNm.resp}"
            FROM "{TblNm.ref_resp}"
            WHERE "{ColNm.serv}" = {serv}
            GROUP BY "{ColNm.resp}";
            DROP VIEW IF EXISTS "{VwNm.ref_vw}";
            CREATE VIEW "{VwNm.ref_vw}"
            AS SELECT "{ColNm.serv}", "{ColNm.sess}", "{ColNm.boot}",
            "{ColNm.sbfn}", "{ColNm.iden}", "{ColNm.ecu_mode}"
            FROM "{TblNm.ven_lu}" WHERE "{ColNm.serv}" = {serv};
            """
            analyze_sql = textwrap.dedent(create_view_sql) + "\n"
            for cond_dict in cond_ls:
                try:
                    if cond_dict[KyNm.scan_mode] == KyNm.scan_iden:
                        fail, cond = self.interpret(cond_dict, op_mode, ScanMode.IDEN)
                        update_sql = (
                            f"""UPDATE "{TblNm.iden}" """
                            + f"""SET "{ColNm.fail}" = {fail} """
                            + f"""WHERE "{ColNm.run}" = {str(run)} """
                            + f"""AND "{ColNm.fail}" = 255{cond};\n"""
                        )
                        analyze_sql += update_sql
                    else:
                        pass
                except (KeyError) as exc:
                    self.log("condition key reading failed", True, exc)
            drop_view_sql = f"""
            DROP VIEW IF EXISTS "{VwNm.sess_alwd}";
            DROP VIEW IF EXISTS "{VwNm.sbfn_alwd}";
            DROP VIEW IF EXISTS "{VwNm.resp_alwd}";
            DROP VIEW IF EXISTS "{VwNm.ref_vw}";
            """
            analyze_sql += textwrap.dedent(drop_view_sql) + "\n"
            if self.debug_on:
                if not os.path.isdir("debug"):
                    os.mkdir("debug")
                with open(
                    f"./debug/analyze_iden_{str(run)}.sql", "w", encoding="utf8"
                ) as file:
                    file.write(analyze_sql)
            self.cur.executescript(analyze_sql)
            self.con.commit()
            self.clear_alwd()
        except (
            OperationalError,
            FileNotFoundError,
            KeyError,
            IndexingError,
            AttributeError,
            JSONDecodeError,
        ) as exc:
            self.log("analyzing scan_identifier in place failed", True, exc)
            return False
        return True

    def interpret(
        self,
        cond_dict: dict,
        op_mode: OpMode,
        scan_mode: ScanMode,
    ) -> Tuple[int, str]:
        """
        interpret JSON conditions file and get failure condition partial SQL string.
        """
        cond = ""
        try:
            failure = self.fail_name_dict[cond_dict[KyNm.fail]]
        except (KeyError) as exc:
            self.log("getting failure condition from JSON failed", True, exc)
            return 255, ""

        if KyNm.match in cond_dict.keys():
            cond = self.get_fail_cond_match(cond, cond_dict, scan_mode, op_mode)

        if NEG_STR + KyNm.match in cond_dict.keys():
            cond = self.get_fail_cond_match(
                cond, cond_dict, scan_mode, op_mode, neg=True
            )

        if KyNm.resd in cond_dict.keys():
            cond = self.get_fail_cond_resp(cond, cond_dict)

        if NEG_STR + KyNm.resd in cond_dict.keys():
            cond = self.get_fail_cond_resp(cond, cond_dict, neg=True)

        if KyNm.supp in cond_dict.keys():
            cond = self.get_fail_cond_supp(cond, cond_dict, scan_mode, op_mode)

        if NEG_STR + KyNm.supp in cond_dict.keys():
            cond = self.get_fail_cond_supp(
                cond, cond_dict, scan_mode, op_mode, neg=True
            )

        if KyNm.for_serv in cond_dict.keys():
            cond = self.get_fail_cond_for_serv(cond, cond_dict)

        if NEG_STR + KyNm.for_serv in cond_dict.keys():
            cond = self.get_fail_cond_for_serv(cond, cond_dict, neg=True)

        if KyNm.known in cond_dict.keys():
            cond = self.get_fail_cond_known(cond, cond_dict)

        if NEG_STR + KyNm.known in cond_dict.keys():
            cond = self.get_fail_cond_known(cond, cond_dict, neg=True)

        return failure, cond

    def get_neg_str(self, neg: bool = False) -> str:
        """
        get negative prefix for SQL query and condition key.
        """
        if neg:
            return NEG_STR
        else:
            return ""

    def get_fail_cond_match(
        self,
        cond: str,
        cond_dict: dict,
        scan_mode: ScanMode,
        op_mode: OpMode = OpMode.VEN_SPEC,
        neg: bool = False,
    ) -> str:
        """
        get failure condition SQL query for the keyword 'match'.
        """
        if op_mode == OpMode.VEN_SPEC and scan_mode == ScanMode.IDEN:
            ref_cols = ""
            neg_str = self.get_neg_str(neg)
            try:
                for ref_col in cond_dict[neg_str + KyNm.match]:
                    if ref_col in (
                        ColNm.sess,
                        ColNm.serv,
                        ColNm.sbfn,
                        ColNm.iden,
                        ColNm.ecu_mode,
                        ColNm.boot,
                    ):
                        ref_cols = ref_cols + f""""{ref_col}"||"/"||"""
                ref_cols = ref_cols[:-7]
                add_cond = (
                    f""" AND ({ref_cols}) {neg_str}IN """
                    + f"""(SELECT({ref_cols} ) FROM "{VwNm.ref_vw}")"""
                )
            except (KeyError) as exc:
                self.log(
                    f"condition key reading failed at '{neg_str}{KyNm.match}'",
                    True,
                    exc,
                )
                add_cond = ""
        return cond + " " + textwrap.dedent(add_cond)

    def get_fail_cond_resp(self, cond: str, cond_dict: dict, neg: bool = False) -> str:
        """
        get failure condition SQL query for the keyword 'responded'.
        """
        try:
            neg_str = self.get_neg_str(neg)
            add_cond = f""" AND "{ColNm.resp}" {neg_str}IN ("""
            for resp_name in cond_dict[neg_str + KyNm.resd]:
                if str(resp_name).strip("-").isnumeric():
                    add_cond += str(resp_name) + ","
                else:
                    add_cond += str(self.iso_err_name_dict[resp_name]) + ","
            add_cond = add_cond[:-1] + ")"
        except (KeyError) as exc:
            self.log(
                f"condition key reading failed at '{neg_str}{KyNm.resd}'", True, exc
            )
            add_cond = ""
        return cond + " " + textwrap.dedent(add_cond)

    def get_fail_cond_supp(
        self,
        cond: str,
        cond_dict: dict,
        scan_mode: ScanMode,
        op_mode: OpMode = OpMode.VEN_SPEC,
        neg: bool = False,
    ) -> str:
        """
        get failure condition SQL query for the keyword 'supported'.
        """
        neg_str = self.get_neg_str(neg)
        if op_mode == OpMode.ISO:
            supp_serv_vec = self.supp_serv_iso_vec
        if op_mode == OpMode.VEN_SPEC:
            supp_serv_vec = self.supp_serv_ven_vec
        try:
            add_cond = ""
            supp_ls = cond_dict[neg_str + KyNm.supp]
            if ColNm.serv in supp_ls:
                add_cond = f""" AND "{ColNm.serv}" {neg_str}IN ("""
                for serv in supp_serv_vec:
                    add_cond += str(serv) + ","
                cond += add_cond[:-1] + ")"
            if ColNm.sess in supp_ls:
                if scan_mode == ScanMode.IDEN:
                    add_cond = (
                        f""" AND "{ColNm.sess}" {neg_str}IN """
                        + f"""(SELECT * FROM "{VwNm.sess_alwd}")"""
                    )
                if scan_mode == ScanMode.SERV:
                    if op_mode == OpMode.ISO:
                        add_cond = (
                            f""" AND ("{ColNm.serv}"||"/"||"{ColNm.sess}") """
                            + f"""{neg_str}IN (SELECT("{ColNm.serv}"||"/"||"{ColNm.sess}") """
                            + f"""FROM "{TblNm.ref_sess}")"""
                        )
                    if op_mode == OpMode.VEN_SPEC:
                        add_cond = (
                            f""" AND ("{ColNm.serv}"||"/"||"{ColNm.sess}"||"/"||"{ColNm.boot}") """
                            + f"""{neg_str}IN (SELECT("{ColNm.serv}"||"/"||"{ColNm.sess}"||"/"||"{ColNm.boot}") """
                            + f"""FROM "{TblNm.ref_sess}")"""
                        )
                cond += add_cond
            if ColNm.sbfn in supp_ls:
                if scan_mode == ScanMode.IDEN:
                    add_cond = (
                        f""" AND "{ColNm.sbfn}" {neg_str}IN """
                        + f"""(SELECT * FROM "{VwNm.sbfn_alwd}")"""
                    )
                if scan_mode == ScanMode.SERV:
                    add_cond = (
                        f""" AND ("{ColNm.serv}"||"/"||"{ColNm.sbfn}") """
                        + f"""{neg_str}IN (SELECT("{ColNm.serv}"||"/"||"{ColNm.sbfn}") """
                        + f"""FROM "{TblNm.ref_sbfn}")"""
                    )
                cond += add_cond
            if ColNm.resp in supp_ls:
                if scan_mode == ScanMode.IDEN:
                    add_cond = (
                        f""" AND "{ColNm.resp}" {neg_str}IN """
                        + f"""(SELECT * FROM "{VwNm.resp_alwd}")"""
                    )
                if scan_mode == ScanMode.SERV:
                    add_cond = (
                        f""" AND ("{ColNm.serv}"||"/"||"{ColNm.resp}") """
                        + f"""{neg_str}IN (SELECT("{ColNm.serv}"||"/"||"{ColNm.resp}") """
                        + f"""FROM "{TblNm.ref_resp}")"""
                    )
                cond += add_cond
        except (KeyError) as exc:
            self.log(
                f"condition key reading failed at '{neg_str}{KyNm.supp}'", True, exc
            )
        return cond

    def get_fail_cond_for_serv(
        self, cond: str, cond_dict: dict, neg: bool = False
    ) -> str:
        """
        get failure condition SQL query for the keyword 'for service'.
        """
        neg_str = self.get_neg_str(neg)
        try:
            add_cond = f""" AND "{ColNm.serv}" {neg_str}IN ("""
            for serv_name in cond_dict[neg_str + KyNm.for_serv]:
                if str(serv_name).strip("-").isnumeric():
                    add_cond += str(serv_name) + ","
                else:
                    add_cond += str(self.iso_serv_name_dict[serv_name]) + ","
            add_cond = add_cond[:-1] + ")"
        except (KeyError) as exc:
            self.log(
                f"condition key reading failed at '{neg_str}{KyNm.for_serv}'", True, exc
            )
            return cond
        return cond + " " + add_cond

    def get_fail_cond_known(self, cond: str, cond_dict: dict, neg: bool = False) -> str:
        """
        get failure condition SQL query for the keyword 'known'.
        """
        neg_str = self.get_neg_str(neg)
        try:
            unknown_ls = cond_dict[neg_str + KyNm.known]
            if ColNm.serv in unknown_ls:
                add_cond = f""" AND "{ColNm.serv}" {neg_str}IN ("""
                for serv in self.iso_serv_code_vec:
                    add_cond += str(serv) + ","
                add_cond = add_cond[:-1]
                cond += add_cond + ")"
            if ColNm.sess in unknown_ls:
                add_cond = f""" AND "{ColNm.sess}" {neg_str}IN ("""
                for sess in self.sess_code_vec:
                    add_cond += str(sess) + ","
                add_cond = add_cond[:-1]
                cond += add_cond + ")"
            if ColNm.resp in unknown_ls:
                add_cond = f""" AND "{ColNm.resp}" {neg_str}IN ("""
                for resp in self.iso_err_code_vec:
                    add_cond += str(resp) + ","
                cond += add_cond[:-1] + ")"
        except (KeyError) as exc:
            self.log(
                f"condition key reading failed at '{neg_str}{KyNm.known}'", True, exc
            )
        return cond
