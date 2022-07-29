# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""
gallia-analyze Name Config module
"""

NEG_STR = "NOT "


class TblNm:
    """
    class for relational table names in the database
    """

    scan_result = "scan_result"
    scan_run = "scan_run"
    run_meta = "run_meta"
    serv = "analysis_service"
    iden = "analysis_identifier"
    ven_lu = "vendor_lookup"
    ven_sess = "vendor_session"
    ref_resp = "analysis_ref_response"
    ref_sess = "analysis_ref_session"
    ref_sbfn = "analysis_ref_subfunc"
    meta = "analysis_meta"


class ColNm:
    """
    class for colunm names in relational tables
    """

    run = "run"
    run_id = "run_id"
    index = "index"
    sess = "session"
    sess_name = "session_name"
    state = "state"
    serv = "service"
    serv_name = "service_name"
    sbfn = "subfunc"
    iden = "identifier"
    fail = "failure"
    resp = "response"
    resp_name = "response_name"
    scan_mode = "scan_mode"
    mode = "mode"
    ecu_mode = "ecu_mode"
    boot = "boot"
    combi = "combi"
    dft = "default"
    id = "id"
    t_rqst = "request_time"
    t_resp = "response_time"
    t_react = "reaction_time"
    prefix = "$_"
    infix = "_"
    ecu_mode = "ecu_mode"
    is_err = "is_error"


class VwNm:
    """
    class for view names in database
    """

    ecu_vw = "ecu_view"
    mode_vw = "mode_view"
    ven_ref_vw = "vendor_ref_view"
    ven_ref_sep_vw = "vendor_ref_sep_view"
    resp_vw = "res_view"
    ref_vw = "ref_view"
    serv_oi = "service_of_interest"
    sess_alwd = "session_allowed"
    sbfn_alwd = "subfunc_allowed"
    iden_alwd = "identifier_allowed"
    resp_alwd = "response_allowed"


class KyNm:
    """
    class for JSON key names
    """

    err = "response"
    err_name = "response_name"
    sess = "session"
    sess_name = "session_name"
    serv = "service"
    serv_name = "service_name"
    resp = "response"
    rgb = "rgb"
    sbfn = "subfunc"
    mode = "mode"

    # key names for conditions
    scan_serv = "scan-service"
    scan_iden = "scan-identifier"
    scan_mode = "SCAN MODE"
    fail = "FAILURE"
    resd = "RESPONDED"
    match = "MATCH"
    supp = "SUPPORTED"
    known = "KNOWN"
    for_serv = "FOR SERVICE"


class ShtNm:
    """
    class for EXCEL sheet names
    """

    init = "Sheet"
    sum = "Summary"
    undoc = "IDs Undocumented"
    miss = "IDs Missing"


class CellCnt:
    """
    class for EXCEL cell texts
    """

    default = "Default"
    serv = "Service ID"
    no_ent = "NO_ENTRY"
    sbfn = "Subfunc"
    sess_unscn = "[Session not scanned]"
    sess_undoc = "[Session undocumented]"
