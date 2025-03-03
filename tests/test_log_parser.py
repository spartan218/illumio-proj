import unittest
import os
import csv

from tempfile import NamedTemporaryFile

from log_parser import load_lookup_table, parse_flow_logs, write_output


class TestFlowLogProcessing(unittest.TestCase):

    def setUp(self):
        # Create a temporary lookup table file
        self.lookup_file = NamedTemporaryFile(delete=False, mode='w', encoding='ascii')
        writer = csv.writer(self.lookup_file)
        writer.writerow(["dst_port", "protocol", "tag"])  # Header
        writer.writerow([80, "tcp", "http"])
        writer.writerow([443, "tcp", "https"])
        self.lookup_file.close()

        # Create a temporary flow log file
        self.log_file = NamedTemporaryFile(delete=False, mode='w', encoding='ascii')
        self.log_file.write("""
        1 2 3 4 5 6 80 6 9 10 11 12 13 14
        1 2 3 4 5 6 443 6 9 10 11 12 13 14
        1 2 3 4 5 6 22 6 9 10 11 12 13 14
        """.strip())
        self.log_file.close()

        # Temporary output file
        self.output_file = NamedTemporaryFile(delete=False, mode='w', encoding='ascii')
        self.output_file.close()

    def tearDown(self):
        if os.path.exists('output_tests_data.csv'):
            os.remove('output_tests_data.csv')

    def test_load_lookup_table(self):
        lookup = load_lookup_table('lookup_table_test_data')
        self.assertEqual(lookup[(25, "tcp")], ["sv_P1"])
        self.assertEqual(lookup[(0, "icmp")], ["sv_P5"])
        self.assertNotIn((69, "udp"), lookup)

    def test_parse_flow_logs(self):
        lookup = load_lookup_table('lookup_table_test_data')
        tag_counts, port_protocol_counts = parse_flow_logs('raw_logs_test_data', lookup)

        self.assertEqual(tag_counts["sv_P2"], 1)
        self.assertEqual(tag_counts["sv_P1"], 2)
        self.assertEqual(tag_counts["Untagged"], 8)
        self.assertEqual(tag_counts["email"], 3)
        self.assertEqual(port_protocol_counts[(80, "tcp")], 1)
        self.assertEqual(port_protocol_counts[(443, "tcp")], 1)
        self.assertEqual(port_protocol_counts[(23, "tcp")], 1)
        self.assertNotIn((22, "tcp"), port_protocol_counts)

    def test_write_output(self):
        lookup = load_lookup_table('lookup_table_test_data')
        tag_counts, port_protocol_counts = parse_flow_logs('raw_logs_test_data', lookup)
        write_output('output_tests_data.csv', tag_counts, port_protocol_counts)

        with open('output_tests_data.csv', 'r', encoding='ascii') as f:
            content = f.read()
            self.assertIn("Tag Counts:\nTag,Count\nUntagged,8\nemail,3\nsv_P1,2\nsv_P2,1", content)
            self.assertIn(
                "Port/Protocol Combination Counts:\nPort,Protocol,Count\n23,tcp,1\n25,tcp,1\n80,tcp,1\n110,tcp,"
                "1\n143,tcp,1\n443,tcp,1\n993,tcp,1\n1024,tcp,1\n49153,tcp,1\n49154,tcp,1\n49155,tcp,1\n49156,tcp,"
                "1\n49157,tcp,1\n49158,tcp,1",
                content)


if __name__ == '__main__':
    unittest.main()
