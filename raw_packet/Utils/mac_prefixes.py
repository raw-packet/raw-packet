from os.path import dirname, abspath, join


def get_mac_prefixes(prefixes_filename="mac-prefixes.txt"):
    current_path = dirname(abspath(__file__))
    vendor_list = []
    with open(join(current_path, prefixes_filename), 'r') as mac_prefixes_descriptor:
        for string in mac_prefixes_descriptor.readlines():
            string_list = string.split(" ", 1)
            vendor_list.append({
                "prefix": string_list[0],
                "vendor": string_list[1][:-1]
            })
    return vendor_list
