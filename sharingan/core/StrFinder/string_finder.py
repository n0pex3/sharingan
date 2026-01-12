# String Finder - Detection and Mapping Only
from cgitb import reset
import idautils
import re
from math import log2

from .ignore_store import apply_ignore_store
from .result_filter import ResultFilter
from .string_extractor import FLOSSStringExtractor
from .report import ScanReport

MIN_LENGTH = 4

class StringFinder:
    """
    Finds encrypted strings and maps where they're used.
    NO DECRYPTION - just detection and location mapping.
    """

    def __init__(self, min_length: int = MIN_LENGTH):
        # Handle the filtering of results
        self.result_filter = ResultFilter()
        self.ignore_store = apply_ignore_store(self.result_filter)
        self.filter_results = self.result_filter.filter_results

        # FLOSS-inspired comprehensive string extractor
        self.extractor = FLOSSStringExtractor(min_length=min_length)

    def find_all_encrypted_strings(self):
        """Find all potentially encrypted strings"""
        print("[Sharingan] Scanning for potentially encrypted strings...")
        report = ScanReport()

        # Static strings (raw segment scan)
        static_strings = list(self.extractor.extract_static_strings())

        print(f"[Sharingan]   Found {len(static_strings)} static strings")
        report.log_message(f"   Found {len(static_strings)} static strings")
        if static_strings:
            report.log_message(f"\t\t{[x['value'] for x in static_strings]}")

        # Stack strings (constructed on stack)
        stack_strings = list(self.extractor.extract_stack_strings())

        print(f"[Sharingan]   Found {len(stack_strings)} stack strings")
        report.log_message(f"   Found {len(stack_strings)} stack strings")
        if stack_strings:
            report.log_message(f"\t\t{[(x['value'], hex(x['address'])) for x in stack_strings]}")

        # Tight strings (push immediate sequences)
        tight_strings = list(self.extractor.extract_tight_strings())

        print(f"[Sharingan]   Found {len(tight_strings)} tight strings")
        report.log_message(f"   Found {len(tight_strings)} tight strings")
        if tight_strings:
            report.log_message(f"\t\t{[(x['value'], hex(x['address'])) for x in tight_strings]}")

        # Filter the results
        all_strings = self.filter_results(static_strings, report)

        print(f"[Sharingan]   Found {len(all_strings)} strings after filtering")
        report.log_message(f"   Found {len(all_strings)} strings after filtering, \
            \n\t\t{[(x['value'], hex(x['address'])) for x in all_strings]}")

        # Add stack strings and tight strings to results. Merge and deduplicate
        all_strings = self.merge_results(all_strings, stack_strings, tight_strings)

        print(f"[Sharingan]   Merged stack strings and tight strings to results, total: {len(all_strings)}")
        report.log_message(f"Final merged total: {len(all_strings)}, \
            \n\t\t{[(x['value'], hex(x['address'])) for x in all_strings]}")

        return all_strings

    # ------------------------------------------------------------------
    # Merge results
    # ------------------------------------------------------------------
    def merge_results(self, *result_lists):
        """Merge and deduplicate results by string value"""
        merged = {}

        for result in result_lists:
            for item in result:
                value = item['value']
                if not value:
                    continue

                if value in merged:
                    # Already exists, merge xrefs and addresses
                    existing_xrefs = set(merged[value]['xrefs'])
                    new_xrefs = set(item.get('xrefs', []))
                    merged[value]['xrefs'] = list(existing_xrefs | new_xrefs)
                    merged[value]['xref_count'] = len(merged[value]['xrefs'])

                    # Track all addresses where this string appears
                    if 'addresses' not in merged[value]:
                        merged[value]['addresses'] = [merged[value]['address']]
                    if item.get('address') and item['address'] not in merged[value]['addresses']:
                        merged[value]['addresses'].append(item['address'])
                else:
                    merged[value] = item.copy()
                    merged[value]['addresses'] = [item.get('address', 0)]

        # Sort by xref count (most used first)
        ret = list(merged.values())
        ret.sort(key=lambda x: x.get('xref_count', 0), reverse=True)
        return ret
