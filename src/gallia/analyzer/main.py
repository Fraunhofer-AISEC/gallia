#!/usr/bin/env python3
"""
gallia-analyze main script
"""
from argparse import Namespace
import sys
import time
import numpy as np
from gallia.analyzer.operator import Operator
from gallia.analyzer.analyzer import Analyzer
from gallia.analyzer.extractor import Extractor
from gallia.analyzer.reporter import Reporter
from gallia.analyzer.categorizer import Categorizer
from gallia.analyzer.time_analyzer import TimeAnalyzer
from gallia.analyzer.mode_config import LogMode
from gallia.analyzer.arg_help import ArgHelp
from gallia.udscan.core import Script

# ========================================================== #
# [Rule for arguments]
#
# Command: one letter lowercase
# Functional Option: one letter uppercase
# Report Option: one word starting with uppercase
# Parameter: one word lowercase(sometimes with dash)
# ========================================================== #


class AnalyzerMain(Script):
    def add_parser(self) -> None:
        # Commands
        grp_cmd = self.parser.add_argument_group("Command")
        grp_cmd.add_argument("-a", action="store_true", help=ArgHelp.analyze)
        grp_cmd.add_argument("-c", action="store_true", help=ArgHelp.clear)
        grp_cmd.add_argument("-e", action="store_true", help=ArgHelp.extract)
        grp_cmd.add_argument("-i", action="store_true", help=ArgHelp.aio_iden)
        grp_cmd.add_argument("-r", action="store_true", help=ArgHelp.report)
        grp_cmd.add_argument("-s", action="store_true", help=ArgHelp.aio_serv)
        grp_cmd.add_argument("-t", action="store_true", help=ArgHelp.time)

        # Options
        grp_opt = self.parser.add_argument_group("Option")
        grp_opt.add_argument("-A", action="store_true", help=ArgHelp.all_serv)
        grp_opt.add_argument("-D", action="store_true", help=ArgHelp.debug)
        grp_opt.add_argument("-I", action="store_true", help=ArgHelp.iso)
        grp_opt.add_argument("-L", action="store_true", help=ArgHelp.log)
        grp_opt.add_argument("-P", action="store_true", help=ArgHelp.possible)
        grp_opt.add_argument("-C", action="store_true", help=ArgHelp.cat)

        # Parameters
        grp_param = self.parser.add_argument_group("Parameter")
        grp_param.add_argument("--sid", type=int, help=ArgHelp.sid, default=-1)
        grp_param.add_argument("--from", type=int, help=ArgHelp.first, default=0)
        grp_param.add_argument("--to", type=int, help=ArgHelp.last, default=0)
        grp_param.add_argument("--output", type=str, help=ArgHelp.output, default="")
        grp_param.add_argument("--source", type=str, help=ArgHelp.source, default="")
        grp_param.add_argument("--precision", type=int, help=ArgHelp.prec, default=0)

    def main(self, args: Namespace) -> None:
        args = vars(args)
        # Commands
        analyze_on = args["a"]
        clear_on = args["c"]
        extract_on = args["e"]
        aio_identifier_on = args["i"]
        report_on = args["r"]
        aio_service_on = args["s"]
        t_analyze_on = args["t"]

        # Functional Options
        all_services_on = args["A"]
        debug_on = args["D"]
        iso_on = args["I"]
        log_file_on = args["L"]
        show_possible_on = args["P"]
        categorizer_on = args["C"]

        # Parameters
        service_id = args["sid"]
        db_path = args["source"]
        run_start = args["from"]
        run_end = args["to"] + 1
        file_path = args["output"]
        t_prec = args["precision"]

        if run_end <= run_start:
            run_end = run_start + 1

        if db_path == "":
            print("Please set database path with --source option!")
            sys.exit()

        start_time = time.process_time()

        if log_file_on:
            log_mode = LogMode.LOG_FILE
        else:
            log_mode = LogMode.STD_OUT

        if run_start == 0 and run_end == 1:
            operator = Operator(db_path)
            runs_vec = operator.get_runs()
        else:
            runs_vec = np.arange(run_start, run_end)

        if clear_on or extract_on:
            extractor = Extractor(db_path, log_mode)

        if clear_on:
            extractor.clear()

        if extract_on:
            extractor.extract(runs_vec)

        if analyze_on:
            if categorizer_on:
                categorizer = Categorizer(db_path, log_mode)
                an_opt = categorizer.get_op_mode(iso_on)
                categorizer.analyze(runs_vec, an_opt)
            else:
                analyzer = Analyzer(db_path, log_mode, debug_on)
                an_opt = analyzer.get_op_mode(iso_on)
                analyzer.analyze(runs_vec, an_opt)

        if t_analyze_on:
            if t_prec > 0:
                time_analyzer = TimeAnalyzer(db_path, t_prec, log_mode)
            else:
                time_analyzer = TimeAnalyzer(db_path, log_mode=log_mode)
            time_analyzer.extract_tra(runs_vec)
            time_analyzer.hist_tra(runs_vec)
            time_analyzer.plot_tra(runs_vec)

        if report_on or aio_service_on or aio_identifier_on:
            reporter = Reporter(db_path, log_mode)

        if report_on:
            reporter.report_xl(runs_vec, show_possible_on, file_path)

        if aio_service_on:
            reporter.consolidate_xl_serv(file_path, show_possible_on)

        if aio_identifier_on:
            if all_services_on:
                reporter.iterate_all(file_path, show_possible_on)
            else:
                if service_id == -1:
                    print("Please input Service ID with --sid option.")
                else:
                    reporter.consolidate_xl_iden(
                        service_id, file_path, show_possible_on
                    )

        print(
            f"gallia-analyze: elapsed time(sec): {str(time.process_time() - start_time)}"
        )
