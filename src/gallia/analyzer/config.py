# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""
gallia-analyze Config module
"""
import importlib.resources
from enum import IntEnum
from gallia import analyzer
from gallia.analyzer.name_config import ColNm
from gallia.analyzer.constants import SqlDataType


def load_resource_file(path: str) -> str:
    """
    load resource file by name from package_data

    :param path: path to object within the  package_data
    :return: absolut path to resource
    """
    pkg = importlib.resources.files(analyzer)
    return str(pkg / path)


FAIL_CLS_CAP = 16
NUM_ECU_MODES = 3

# default time precision for time analysis
# 19: nanosecond
# 16: microsecond
# 13: millisecond
DFT_T_PREC = 19


class MiscError(IntEnum):
    """
    enum class for undefined errors
    """

    UNKNOWN_ERROR = 0x80
    INVALID_RESPONSE = 0xA0
    NO_RESPONSE = -1
    POSITIVE_RESPONSE = 0


class SrcPath:
    """
    class for source paths
    """

    err_src = load_resource_file("json/responses.json")
    uds_iso_src = load_resource_file("json/uds_iso_standard.json")
    cond_src = load_resource_file("json/conditions.json")


class TblStruct:
    """
    class for relational table structures
    """

    serv = {
        ColNm.id: SqlDataType.integer,
        ColNm.run: SqlDataType.integer,
        ColNm.t_rqst: SqlDataType.integer,
        ColNm.t_resp: SqlDataType.integer,
        ColNm.ecu_mode: SqlDataType.integer,
        ColNm.serv: SqlDataType.integer,
        ColNm.sess: SqlDataType.integer,
        ColNm.boot: SqlDataType.integer,
        ColNm.resp: SqlDataType.integer,
        ColNm.fail: SqlDataType.integer,
    }
    iden = {
        ColNm.id: SqlDataType.integer,
        ColNm.run: SqlDataType.integer,
        ColNm.t_rqst: SqlDataType.integer,
        ColNm.t_resp: SqlDataType.integer,
        ColNm.ecu_mode: SqlDataType.integer,
        ColNm.serv: SqlDataType.integer,
        ColNm.sess: SqlDataType.integer,
        ColNm.boot: SqlDataType.integer,
        ColNm.sbfn: SqlDataType.integer,
        ColNm.iden: SqlDataType.integer,
        ColNm.resp: SqlDataType.integer,
        ColNm.fail: SqlDataType.integer,
    }
    ven_lu = {
        ColNm.serv: SqlDataType.integer,
        ColNm.sess: SqlDataType.integer,
        ColNm.boot: SqlDataType.integer,
        ColNm.sbfn: SqlDataType.integer,
        ColNm.iden: SqlDataType.integer,
        ColNm.ecu_mode: SqlDataType.integer,
    }
    ven_sess = {
        ColNm.sess_name: SqlDataType.text,
        ColNm.sess: SqlDataType.integer,
    }
    ref_resp = {
        ColNm.serv: SqlDataType.integer,
        ColNm.resp: SqlDataType.integer,
    }
    ref_sbfn = {
        ColNm.serv: SqlDataType.integer,
        ColNm.sbfn: SqlDataType.integer,
    }
    ref_sess = {
        ColNm.serv: SqlDataType.integer,
        ColNm.sess: SqlDataType.integer,
        ColNm.boot: SqlDataType.integer,
    }


class XlDesign:
    """
    class for EXCEL report design
    """

    font_index = "Calibri"
    font_value = "Courier New"

    dim_wide = 45
    dim_mid_wide = 32
    dim_middle = 25
    dim_narrow = 10


class PltDesign:
    """
    class for matplotlib graph design
    """

    hist_style = "dark_background"
    plot_style = "dark_background"
