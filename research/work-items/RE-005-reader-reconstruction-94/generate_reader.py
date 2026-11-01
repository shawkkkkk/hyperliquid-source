#!/usr/bin/env python3
"""Independent mathematical vectors; never imports project code or executes input."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

def mathematical_answer(width, dl, raw):
    n = len(raw)
    if n == 0:
        fields, consumed = ['end', '1'], 0
    else:
        marker = raw[0]
        invalid = {253: 3, 254: 4, 255: 12} if width == 32 else {254: 4, 255: 12}
        if marker in invalid:
            fields, consumed = ['type', str(2 if width == 32 else 3), str(invalid[marker])], 1
        elif marker < 251:
            fields, consumed = ['ok', str(marker)], 1
        else:
            payload_width = {251: 2, 252: 4, 253: 8}[marker]
            total = 1 + payload_width
            if n < total:
                fields, consumed = ['end', str(total - n)], 1
            else:
                # Positional polynomial, independent of any target evaluator/parser.
                digits = raw[1:total] if dl != 0 else raw[1:total][::-1]
                value = sum(digit * 256 ** (payload_width - 1 - index)
                            for index, digit in enumerate(digits))
                fields, consumed = ['ok', str(value)], total
    return '\t'.join(fields + [str(consumed), str(n - consumed), raw[consumed:].hex()])

cases = []
seen = set()
def add(label, width, dl, raw):
    key = width, dl, raw
    if key in seen:
        return
    seen.add(key)
    cases.append({'id': label, 'input': f'{width}\t{dl}\t{raw.hex()}',
                  'expected': mathematical_answer(width, dl, raw)})

for width in (32, 64):
    for dl in (0, 1, 2, 127, 128, 255):
        add(f'empty-w{width}-dl{dl}', width, dl, b'')
        for marker in range(256):
            add(f'tag-w{width}-dl{dl}-t{marker}', width, dl, bytes([marker]))
            add(f'tag-tail-w{width}-dl{dl}-t{marker}', width, dl,
                bytes([marker, 1, 35, 69, 103, 137, 171, 205, 239, 90, 0]))
        for marker, count in ((251, 2), (252, 4), (253, 8)):
            for present in range(count):
                add(f'short-w{width}-dl{dl}-t{marker}-n{present}', width, dl,
                    bytes([marker]) + bytes(range(1, present + 1)))
            payloads = [bytes(count), bytes([255]) * count,
                        bytes([250]) + bytes(count - 1),
                        bytes(count - 1) + bytes([250]),
                        bytes(range(1, count + 1))]
            for payload_index, payload in enumerate(payloads):
                for suffix in (b'', b'\x00', b'\xff\xfb\x00\x01'):
                    add(f'payload-w{width}-dl{dl}-t{marker}-p{payload_index}-s{suffix.hex()}',
                        width, dl, bytes([marker]) + payload + suffix)
    for dl in range(256):
        for marker, payload in ((251, bytes.fromhex('0123')),
                                (252, bytes.fromhex('01234567')),
                                (253, bytes.fromhex('0123456789abcdef'))):
            add(f'alldl-w{width}-dl{dl}-t{marker}', width, dl, bytes([marker]) + payload + b'\xa5')

body = {'schema': 'reader623-pre-source-math-v1', 'target_sha256': TARGET,
        'published_basis': {'pr': 253, 'current_ref': '3324e50333042b391312515e542279ca21f63dc8',
                            'listing_path': 'research/work-items/RE-005-bincode-slow-widths/objdump-excerpts.txt',
                            'listing_sha256': '0a8b937e511c334bc640b417042359a864051e8b758de85b5aeadefbe1e9eb03'},
        'cases': cases,
        'limitations': ['Mathematical oracle frozen before new Reader Rust; published native listing basis only at freeze.',
                        'No captured target execution or instruction evaluator.',
                        'Outer slice budgets, fast paths, ABI padding and original compiler/code identity excluded.']}
encoded = (json.dumps(body, indent=2, sort_keys=True) + '\n').encode()
(ROOT / 'reader623-corpus.json').write_bytes(encoded)
(ROOT / 'reader623-input.tsv').write_text('\n'.join(case['input'] for case in cases) + '\n')
(ROOT / 'reader623-expected.tsv').write_text('\n'.join(case['expected'] for case in cases) + '\n')
receipt = {'corpus_sha256': hashlib.sha256(encoded).hexdigest(), 'cases': len(cases)}
for filename in ('generate_reader.py', 'reader623-input.tsv', 'reader623-expected.tsv'):
    receipt[filename + '_sha256'] = hashlib.sha256((ROOT / filename).read_bytes()).hexdigest()
(ROOT / 'reader623-freeze.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps(receipt, sort_keys=True))
