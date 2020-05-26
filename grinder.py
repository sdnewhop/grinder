#!/usr/bin/env python3

import sys

from grinder.asciiart import AsciiOpener
from grinder.core import GrinderCore
from grinder.interface import GrinderInterface

if __name__ == "__main__":
    AsciiOpener.print_opener()
    interface = GrinderInterface()
    interface.check_python_version()
    args = interface.parse_args()

    core = GrinderCore(
        shodan_api_key=args.shodan_key,
        censys_api_id=args.censys_id,
        censys_api_secret=args.censys_secret,
        vulners_api_key=args.vulners_key,
    )

    if args.censys_max:
        core.set_censys_max_results(args.censys_max)
    if args.shodan_max:
        core.set_shodan_max_results(args.shodan_max)
    if args.vendor_confidence:
        core.set_vendor_confidence(args.vendor_confidence)
    if args.query_confidence:
        core.set_query_confidence(args.query_confidence)
    if args.max_limit:
        core.set_unique_entities_quantity(args.max_limit)
    if args.vendors:
        core.set_vendors(args.vendors)

    search_results = (
        core.batch_search(
            queries_filename=args.queries_file,
            not_incremental=args.not_incremental
        )
        if args.run
        else core.load_results()
    )

    if not search_results:
        print(f"Results are empty.")
        sys.exit(1)

    print(f"Total results: {len(search_results)}")
    if args.vulners_scan:
        core.vulners_scan(
            top_ports=args.top_ports,
            host_timeout=args.host_timeout,
            workers=args.vulners_workers,
        )
    if args.nmap_scan:
        core.nmap_scan(
            top_ports=args.top_ports,
            host_timeout=args.host_timeout,
            workers=args.nmap_workers,
        )
    if args.tls_scan:
        core.tls_scan(args.tls_scan_path)
    if args.script_check:
        core.run_scripts(queries_filename=args.queries_file)
    if args.count_unique:
        core.count_unique_entities("product")
        core.count_unique_entities("vendor")
        core.count_unique_entities("port")
        core.count_unique_entities("proto")
        core.count_unique_entities("country")
        core.count_unique_entities("vulnerability")
        core.count_unique_entities("continent")
        core.count_unique_entities("organization")
    if args.vulners_report:
        core.vulners_report()
    if args.update_markers:
        core.update_map_markers()
    if args.create_plots:
        core.create_plots()
    if args.run:
        core.save_results_to_database()
    core.save_results()
    if args.onehost:
        core.onehost(host_address=args.host_ip)
