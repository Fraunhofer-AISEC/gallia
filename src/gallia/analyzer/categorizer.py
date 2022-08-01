# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""
gallia-analyze Categorizer module
"""
from pathlib import Path
from sqlite3 import OperationalError
from typing import cast

import numpy as np
import pandas as pd
from gallia.analyzer.analyzer import Analyzer
from gallia.analyzer.config import TblStruct
from gallia.analyzer.failure import Failure
from gallia.analyzer.mode_config import LogMode, OpMode
from gallia.analyzer.name_config import ColNm, TblNm
from gallia.analyzer.exceptions import EmptyTableException, ColumnMismatchException
from gallia.uds.core.constants import UDSIsoServices, UDSErrorCodes
from gallia.utils import g_repr


class Categorizer(Analyzer):
    """
    Categorizer class for analysis operation based on pandas.
    Inherited from Analyzer.
    """

    def __init__(
        self, path: str, artifacts_dir: Path, log_mode: LogMode = LogMode.STD_OUT
    ):
        Analyzer.__init__(self, path, artifacts_dir, log_mode)

    def analyze_serv(self, run: int, op_mode: OpMode) -> bool:
        """
        analyze scan_service result data for certain run at a given analysis mode.
        """
        try:
            raw_df = self.read_run_db(TblNm.serv, run)
            self.check_df(raw_df, TblStruct.serv)
            raw_df = self.categorize_serv(raw_df, op_mode)
            if not self.delete_run_db(TblNm.serv, run):
                return False
            if not self.write_db(raw_df, TblNm.serv):
                return False
        except (EmptyTableException, ColumnMismatchException, OperationalError) as exc:
            self.logger.log_error(f"analyzing scan_service failed: {g_repr(exc)}")
            return False
        return True

    def analyze_iden(self, run: int, op_mode: OpMode) -> bool:
        """
        analyze scan_identifier result data for certain run at a given analysis mode.
        """
        try:
            if not self.load_lu_iden(self.get_sid(run), self.get_ecu_mode(run)):
                return False
            raw_df = self.read_run_db(TblNm.iden, run)
            self.check_df(raw_df, TblStruct.iden)
            raw_df.set_index(ColNm.id, inplace=True)
            raw_df = self.categorize_iden(raw_df, op_mode)
            if not self.delete_run_db(TblNm.iden, run):
                return False
            if not self.write_db(raw_df, TblNm.iden):
                return False
        except (EmptyTableException, ColumnMismatchException, OperationalError) as exc:
            self.logger.log_error(f"analyzing scan_identifier failed: {g_repr(exc)}")
            return False
        return True

    def categorize_serv(
        self, raw_df: pd.DataFrame, op_mode: OpMode = OpMode.VEN_SPEC
    ) -> pd.DataFrame:
        """
        categorize failures for scan_service.
        """
        try:
            raw_df[ColNm.combi] = list(
                zip(
                    raw_df[ColNm.serv],
                    raw_df[ColNm.sess],
                    raw_df[ColNm.resp],
                    raw_df[ColNm.ecu_mode],
                )
            )
            raw_df.loc[:, ColNm.fail] = raw_df[ColNm.combi].apply(
                lambda x: self.get_fail_serv(op_mode, x[0], x[1], x[2], x[3])
            )
            raw_df = raw_df.drop([ColNm.combi], axis=1)
        except KeyError as exc:
            self.logger.log_error(
                f"categorizing failures for scan_service failed: {g_repr(exc)}"
            )
            return pd.DataFrame()
        return raw_df

    def categorize_iden(
        self,
        raw_df: pd.DataFrame,
        ecu_mode: int,
        op_mode: OpMode = OpMode.VEN_SPEC,
    ) -> pd.DataFrame:
        """
        categorize failures for scan_identifier.
        """
        try:
            serv_vec = np.unique(raw_df[ColNm.serv])
            if not serv_vec.size == 1:
                self.logger.log_error("more than one service in a run")
                return pd.DataFrame()
            else:
                serv = serv_vec[0]
                if not self.load_lu_iden(serv, ecu_mode):
                    return pd.DataFrame()
            raw_df[ColNm.combi] = list(
                zip(
                    raw_df[ColNm.sess],
                    raw_df[ColNm.boot],
                    raw_df[ColNm.sbfn],
                    raw_df[ColNm.iden],
                    raw_df[ColNm.resp],
                    raw_df[ColNm.ecu_mode],
                )
            )
            raw_df.loc[:, ColNm.fail] = raw_df[ColNm.combi].apply(
                lambda x: self.get_fail_iden(
                    op_mode, serv, x[0], x[1], x[2], x[3], x[4], x[5]
                )
            )
            raw_df = raw_df.drop([ColNm.combi], axis=1)
        except KeyError as exc:
            self.logger.log_error(
                f"categorizing failures for scan_identifier failed: {g_repr(exc)}"
            )
            return pd.DataFrame()
        return raw_df

    def check_sess_alwd(
        self, serv: int, sess: int, op_mode: OpMode, ecu_mode: int
    ) -> bool:
        """
        check if a certain diagnostic session is available or supported
        for a certain service at given analysis mode.
        """
        if op_mode == OpMode.VEN_SPEC:
            ref_df = cast(
                pd.DataFrame, self.ref_ven_df[ecu_mode]
            )  # this a nested DataFrame, which yields a DataFrame per ecu_mode
        if op_mode == OpMode.ISO:
            ref_df = self.ref_iso_df
        if serv not in ref_df.index:
            return False
        return sess in cast(
            list[int],
            ref_df.loc[
                serv, ColNm.sess
            ],  # The session column is a list of supported session IDs
        )

    def check_resp_alwd(self, serv: int, resp: int) -> bool:
        """
        check if a certain response is available or supported for a certain service.
        """
        if serv not in list(self.ref_iso_df.index):
            return False
        return (
            resp
            in self.ref_iso_df.loc[serv, ColNm.resp]
            + self.iso_supp_err_for_all_vec.tolist()
        )

    def check_sbfn_alwd(
        self, serv: int, sbfn: int, op_mode: OpMode, ecu_mode: int
    ) -> bool:
        """
        check if a certain sub-function is available or supported
        for a certain service at given analysis mode.
        """
        if op_mode == OpMode.VEN_SPEC:
            ref_df = cast(
                pd.DataFrame, self.ref_ven_df[ecu_mode]
            )  # this a nested DataFrame, which yields a DataFrame per ecu_mode
        if op_mode == OpMode.ISO:
            ref_df = self.ref_iso_df
        if serv not in ref_df.index:
            return False
        return sbfn in cast(
            list[int],
            ref_df.loc[
                serv, ColNm.sbfn
            ],  # The sub-function column is a list of supported sub-functions
        )

    def get_fail_serv(
        self,
        op_mode: OpMode,
        serv: int,
        sess: int,
        resp: int,
        ecu_mode: int,
    ) -> Failure:
        """
        get failure for given parameters, service, diagnostic session and response
        at given analysis mode.
        """
        if op_mode == OpMode.VEN_SPEC:
            supp_serv_vec = self.supp_serv_ven_vec
        if op_mode == OpMode.ISO:
            supp_serv_vec = self.supp_serv_iso_vec

        cond_serv_known = serv in self.iso_serv_code_vec
        cond_serv_supp = serv in supp_serv_vec
        cond_resp_means_not_supp = resp in self.iso_err_means_not_supp_vec
        cond_no_resp = resp == -1
        cond_sess_alwd = self.check_sess_alwd(serv, sess, op_mode, ecu_mode)
        cond_resp_alwd = self.check_resp_alwd(serv, resp)
        cond_resp_serv_not_supp = resp == UDSErrorCodes.serviceNotSupported
        cond_resp_serv_not_supp_in_cur_sess = (
            resp == UDSErrorCodes.serviceNotSupportedInActiveSession
        )
        cond_resp_sbfn_not_supp = resp == UDSErrorCodes.subFunctionNotSupported

        # invalid or unknown response
        if resp == 0x80:
            return Failure.UNDOC_SERV
        if resp == 0xA0:
            return Failure.UNDOC_SERV

        if not cond_serv_known:
            # normal responses to unknown services
            if cond_resp_serv_not_supp:
                return Failure.OK_SERV_A

            # time out / no Response to unknown services
            if cond_no_resp:
                return Failure.OK_SERV_B

        if not cond_serv_supp:
            # normal responses to unsupported services
            if cond_resp_means_not_supp:
                return Failure.OK_SERV_C

            # time out / no Response to unsupported services
            if cond_no_resp:
                return Failure.OK_SERV_D

            # Undocumented Type A: services not defined in ISO standard
            # or vendor-specific reference responded otherwise
            if not cond_resp_means_not_supp and not cond_no_resp:
                return Failure.UNDOC_SERV_A

        if cond_serv_supp:
            # normal response to supported services when they are not supported in active session
            if not cond_sess_alwd:
                if cond_resp_means_not_supp:
                    return Failure.OK_SERV_E

                # Undocumented Type B: supported services in not available session responded
                # other than "not supported" family
                if not cond_resp_means_not_supp:
                    return Failure.UNDOC_SERV_B

            if cond_sess_alwd:
                # available NRC to available service in active session
                if cond_resp_alwd and not cond_resp_means_not_supp:
                    return Failure.OK_SERV_F

                # supported services (and even in available session) give a response undocumented in ISO
                if not cond_resp_means_not_supp:
                    return Failure.OK_SERV_G

                # Missing Type A: in ISO standard or vendor-specific reference defined as available
                # in a session but gives response "not supported in active session"
                if cond_resp_serv_not_supp_in_cur_sess:
                    return Failure.MISS_SERV_A

                # Missing Type B: in ISO standard or vendor-specific reference defined as available
                # in a session but gives response "service not supported"
                if cond_resp_serv_not_supp:
                    return Failure.MISS_SERV_B

                # supported services in available session give a responded as "subFunctionNotSupported"
                if cond_resp_sbfn_not_supp:
                    return Failure.OK_SERV_H

        return Failure.UNKNOWN

    def get_fail_iden(
        self,
        op_mode: OpMode,
        serv: int,
        sess: int,
        boot: int,
        sbfn: int,
        iden: int,
        resp: int,
        ecu_mode: int,
    ) -> Failure:
        """
        get failure for given parameters, service, diagnostic session, sub-function,
        identifier and response at given analysis mode.
        """
        if op_mode == OpMode.VEN_SPEC:
            supp_serv_vec = self.supp_serv_ven_vec
        elif op_mode == OpMode.ISO:
            supp_serv_vec = self.supp_serv_iso_vec
        else:
            raise RuntimeError(f"Unsupported op_mode: {op_mode}")

        cond_serv_supp = serv in supp_serv_vec
        cond_resp_alwd = self.check_resp_alwd(serv, resp)
        cond_sbfn_alwd = self.check_sbfn_alwd(serv, sbfn, op_mode, ecu_mode)
        cond_resp_serv_not_supp = resp == UDSErrorCodes.serviceNotSupported
        cond_resp_sbfn_not_supp = resp == UDSErrorCodes.subFunctionNotSupported

        if (not cond_serv_supp) and (cond_resp_serv_not_supp):
            return Failure.OK_IDEN_A
        if (not cond_sbfn_alwd) and (cond_resp_sbfn_not_supp):
            return Failure.OK_IDEN_B

        try:
            combi = (sess, boot, sbfn, iden, ecu_mode)
            combis_ls = list(self.lu_iden_df[ColNm.combi])
            cond_combi = combi in combis_ls
            cond_combi_aem = False
            for cur_mode in np.arange(self.num_modes):
                combi = (sess, boot, sbfn, iden, cur_mode)
                combis_ls = list(self.lu_iden_df[ColNm.combi])
                if combi in combis_ls:
                    cond_combi_aem = True
                    break

        except (KeyError, AttributeError) as exc:
            self.logger.log_error(
                f"getting failure for identifier failed: {g_repr(exc)}"
            )
            return Failure.UNKNOWN

        if cond_combi:
            if resp == UDSErrorCodes.serviceNotSupportedInActiveSession:
                return Failure.MISS_IDEN_A

            if resp == UDSErrorCodes.serviceNotSupported:
                return Failure.MISS_IDEN_B

            if resp == UDSErrorCodes.requestOutOfRange:
                return Failure.MISS_IDEN_C

            if serv == UDSIsoServices.WriteDataByIdentifier:
                if resp == UDSErrorCodes.securityAccessDenied:
                    return Failure.MISS_IDEN_D

            if cond_resp_alwd:
                return Failure.OK_IDEN_C

            if resp == 0:
                return Failure.OK_IDEN_D

        if cond_combi_aem:
            if resp == UDSErrorCodes.conditionsNotCorrect:
                if serv == UDSIsoServices.ReadDataByIdentifier:
                    return Failure.OK_IDEN_E

                if serv == UDSIsoServices.RoutineControl:
                    return Failure.OK_IDEN_F

        if not cond_combi:
            # general default response
            if resp == UDSErrorCodes.requestOutOfRange:
                return Failure.OK_IDEN_G

            if serv == UDSIsoServices.ReadDataByIdentifier:
                if resp == UDSErrorCodes.incorrectMessageLengthOrInvalidFormat:
                    return Failure.DFT_RES_A

            if serv == UDSIsoServices.SecurityAccess:
                if resp == UDSErrorCodes.subFunctionNotSupported:
                    return Failure.DFT_RES_B

                if resp == UDSErrorCodes.serviceNotSupportedInActiveSession:
                    return Failure.DFT_RES_B

                if resp == UDSErrorCodes.subFunctionNotSupportedInActiveSession:
                    return Failure.DFT_RES_B

            if serv == UDSIsoServices.RoutineControl:
                if resp == UDSErrorCodes.subFunctionNotSupported:
                    return Failure.DFT_RES_C

            if serv == UDSIsoServices.WriteDataByIdentifier:
                if resp == UDSErrorCodes.securityAccessDenied:
                    return Failure.DFT_RES_D

                if resp == UDSErrorCodes.incorrectMessageLengthOrInvalidFormat:
                    return Failure.DFT_RES_D

                if resp == UDSErrorCodes.serviceNotSupportedInActiveSession:
                    return Failure.DFT_RES_D

                if resp == UDSErrorCodes.conditionsNotCorrect:
                    return Failure.DFT_RES_D

            if resp == UDSErrorCodes.conditionsNotCorrect:
                return Failure.UNDOC_IDEN_A

            if resp == UDSErrorCodes.subFunctionNotSupportedInActiveSession:
                return Failure.UNDOC_IDEN_B

            # TODO: What is this case about?
            if resp == 0:
                return Failure.UNDOC_IDEN_E

            if cond_resp_alwd:
                return Failure.UNDOC_IDEN_C

            if not cond_resp_alwd:
                return Failure.UNDOC_IDEN_D

        return Failure.UNKNOWN
