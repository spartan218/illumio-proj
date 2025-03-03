import csv
import os
from collections import defaultdict

iana_protocols = {
    1: "icmp",
    6: "tcp",
    17: "udp",
}


def load_lookup_table(lookup_file):
    if not os.path.isfile(lookup_file):
        raise FileNotFoundError(lookup_file)
    lookup = defaultdict(list)
    with open(lookup_file, mode='r', encoding='ascii') as file:
        reader = csv.reader(file)
        next(reader)  # Skip header
        for row in reader:
            dst_port, protocol, tag = row
            lookup[(int(dst_port), protocol.lower())].append(tag)
    return lookup


def parse_flow_logs(log_file, lookup):
    if not os.path.isfile(log_file):
        raise FileNotFoundError(log_file)
    if not lookup:
        raise ValueError('No lookup table', lookup)
    tag_counts = defaultdict(int)
    port_protocol_counts = defaultdict(int)

    with open(log_file, mode='r', encoding='ascii') as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) != 14:
                print('Only version 2 flow logs are supported')
                # print rather than raise error in the case that valid logs are mixed
                continue

            dst_port = int(parts[6])
            protocol_num = int(parts[7])
            protocol = iana_protocols.get(protocol_num, 'None')

            tags = lookup.get((dst_port, protocol))
            if not tags:
                tag_counts['Untagged'] += 1
            else:
                for tag in tags:
                    tag_counts[tag] += 1
            port_protocol_counts[(dst_port, protocol)] += 1

    return tag_counts, port_protocol_counts


def write_output(output_file, tag_counts, port_protocol_counts):
    with open(output_file, mode='w', encoding='ascii') as file:
        file.write("Tag Counts:\nTag,Count\n")
        for tag, count in sorted(tag_counts.items()):
            file.write(f"{tag},{count}\n")

        file.write("\nPort/Protocol Combination Counts:\nPort,Protocol,Count\n")
        for (port, protocol), count in sorted(port_protocol_counts.items()):
            file.write(f"{port},{protocol},{count}\n")


def main():
    lookup_file = 'tests/lookup_table_test_data'
    log_file = 'tests/raw_logs_test_data'
    output_file = 'resources/output.csv'

    lookup = load_lookup_table(lookup_file)
    tag_counts, port_protocol_counts = parse_flow_logs(log_file, lookup)
    write_output(output_file, tag_counts, port_protocol_counts)

    print("Processing complete. Results saved in", output_file)


if __name__ == "__main__":
    main()
