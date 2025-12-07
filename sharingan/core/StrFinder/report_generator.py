# Report Generator
import json, time, os, idaapi, idc

class ReportGenerator:
    def generate_report(self, results):
        """Generate JSON report with findings"""

        # Get file info
        input_file = idaapi.get_input_file_path()

        # Create report directory
        report_dir = os.path.join(os.path.dirname(input_file), "esf_reports")
        try:
            os.makedirs(report_dir, exist_ok=True)
        except:
            report_dir = os.path.dirname(input_file)

        # Generate report
        report = {
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'binary': os.path.basename(input_file),
            'total_encrypted_strings': len(results),
            'findings': []
        }

        for item in results:
            finding = {
                'string_value': item['value'],
                'string_address': hex(item['address']),
                'type': item['type'],
                'usage_locations': []
            }

            # Add usage locations with function names
            for xref in item['xrefs']:
                func_name = idc.get_func_name(xref)
                finding['usage_locations'].append({
                    'address': hex(xref),
                    'function': func_name if func_name else 'unknown'
                })

            report['findings'].append(finding)

        # Save report
        report_name = f"encrypted_strings_{time.strftime('%Y%m%d_%H%M%S')}.json"
        report_path = os.path.join(report_dir, report_name)

        try:
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[ESF] Report saved: {report_path}")
        except Exception as e:
            print(f"\n[ESF] Error saving report: {e}")
