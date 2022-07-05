"""
gallia-analyze module for argument help texts
"""


class ArgHelp:
    """
    class for argument help text
    """

    main = """
    gallia-analyze, version 0.1.0
    Extract, analyze and visualize data obtained from gallia scan_service and scan_identifier.
    """

    usage = """
    ex) execute all the analysis and reporting operations in a sequence for runs 1 to 5.
    > gallia-analyze --source [database file path] -near --from 1 --to 5

    ex) clear all the data and redo all the analysis operations in a sequence for all runs.
    > gallia-analyze --source [database file path] -clean

    Please refer to help for details.
    > gallia-analye --help
    """

    # Commands
    analyze = """
    Categorize failures judging by parameters using vendor-specific lookup data as default.
    """
    clear = """
    Clear all analyzed data in database.
    """
    extract = """
    Extract JSON data, etc. from database and store into relational database.
    """
    aio_iden = """
    Consolidate all scan_identifier runs into one EXCEL file sorted by ECU mode for a certain Service ID.
    """
    graph = """
    Output reponse statistic graphs in PNG format.
    """
    report = """
    Output reports in excel file.
    """
    aio_serv = """
    Consolidate all scan_service runs into one EXCEL file sorted by ECU mode.
    """
    time = """
    Conduct time analysis with reaction time.
    """

    # Options
    all_serv = """
    Iterate 'all-ECU-modes' reporting for all services by identifier defined in UDS ISO Standard.
    """
    debug = """
    Use debug mode. Save SQL queries for analysis to SQL files.
    """
    iso = """
    Use UDS ISO Standard while analyzing data.
    """
    log = """
    Log messages to file.
    """
    possible = """
    Show all possible service IDs or Identifiers on summary sheet.
    """
    cat = """
    Use Categorizer(Analyzer based on pandas framework) instead of SQL-based Analyzer.
    """

    # Parameters
    sid = """
    Service ID to report for all ECU modes in one EXCEL file
    """
    first = """
    The first run to process
    """
    last = """
    The last run to process
    """
    output = """
    Path of excel reports
    """
    source = """
    Path of source database
    """
    prec = """
    Time precision for time analysis. Defined as the number of digits in Unix time. ex) 19 = nanosecond
    """
