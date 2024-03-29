import argparse
import baseconv
from datetime import datetime
import glob
from os import path
from typing import Sequence
import uuid

import plyara
from plyara import utils

def contains(dicts:Sequence[dict], key:any) -> bool:
    for d in dicts:
        if key in d:
            return True
    return False

def first(dicts:Sequence[dict], key:any, default:any = None) -> dict:
    for d in dicts:
        if key in d:
            return d[key]
    return default

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate YARAhub rules file.')
    parser.add_argument('path', metavar='PATH', type=str, nargs='+', help='a glob expression to YARA rules compliant with the Canadian Centre for Cyber Security YARA specififcation')
    parser.add_argument('--dir', metavar='DIR', type=str, required=False, default='./', help='a directory in which rules should be saved')

    args = parser.parse_args()
    yara = plyara.Plyara()

    for expression in args.path:
        for filepath in glob.iglob(expression, recursive=True):
            with open(filepath, mode='r') as file:
                for rule in yara.parse_string(file.read()):
                    # Date when the YARA rule has been written. Format: YYYY-MM-DD
                    if not contains(rule['metadata'], 'date'):
                        rule['metadata'].append({'date': first(rule['metadata'], 'last_modified', datetime.today().strftime('%Y-%m-%d'))})
                    # MD5 hash of a sample (file) that should match this YARA rule
                    if not contains(rule['metadata'], 'yarahub_reference_md5'):
                        md5 = []
                        for entry in rule['metadata']:
                            for k, v in entry.items():
                                if k.startswith('hash') and len(v) == 32:
                                    md5.append({'yarahub_reference_md5': v})
                        if not md5:
                            md5.append({'yarahub_reference_md5': '0'*32})
                        rule['metadata'].extend(md5)
                    # A unique UUID 4 identifying this YARA rule
                    identifier = uuid.UUID(first(rule['metadata'], 'yarahub_uuid', '{00000000-0000-0000-0000-000000000000}'))
                    if not identifier.int:
                        identifier = uuid.UUID(int=int(baseconv.base62.decode(first(rule['metadata'], 'id', 0))))
                        if not identifier.int:
                            identifier = uuid.uuid4()
                        rule['metadata'].append({'yarahub_uuid': str(identifier)})
                    # Creative Commons license under which you want to share your YARA rule.
                    # Most restrictive as DRL is not supported (yet).
                    if not contains(rule['metadata'], 'yarahub_license'):
                        rule['metadata'].append({'yarahub_license': 'CC BY-NC-ND 4.0'})
                    # This TLP defines whether YARA matches of this rule should be publicly visible or not
                    if not contains(rule['metadata'], 'yarahub_rule_matching_tlp'):
                        tlp = first(rule['metadata'], 'sharing')
                        # Use legacy TLP codes
                        if tlp == "TLP:CLEAR":
                            tlp = "TLP:WHITE"
                        rule['metadata'].append({'yarahub_rule_matching_tlp': tlp})
                    # This TLP defines whether the YARA rule itself should be shared or not.
                    # Quite restrictive as DRL is not supported (yet).
                    if not contains(rule['metadata'], 'yarahub_rule_sharing_tlp'):
                        rule['metadata'].append({'yarahub_rule_sharing_tlp': 'TLP:AMBER'})
                    destination = path.join(args.dir, f'{rule["rule_name"]}_{identifier}.yar')
                    with open(destination, mode='w') as compiled:
                        compiled.write(utils.rebuild_yara_rule(rule, condition_indents=True))
                        print(destination)
            yara.clear()
