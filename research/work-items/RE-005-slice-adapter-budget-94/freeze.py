#!/usr/bin/env python3
"""Independent mathematical outer-adapter state expectations, before new model.

Integer inequalities, byte positional value, and finite state contracts only.
No repository import, new model read, target execution or PC/register evaluator.
"""
from pathlib import Path
import hashlib,json,datetime

P=Path(__file__).resolve().parent
MAX=(1<<64)-1
cases=[]
seen=set()
families={}

def add(family,width,mode,counter,limit,raw):
    key=(width,mode,counter,limit,raw)
    if key in seen:return
    seen.add(key)
    ident=f'a{len(cases):05d}'
    pointer=(1<<32)+len(cases)*32
    cases.append({'id':ident,'width':width,'mode':mode,'counter':counter,
                  'limit':limit,'pointer':pointer,'raw_hex':raw.hex(),'family':family})
    families[family]=families.get(family,0)+1

raws=[b'',b'\x00',b'\xfb\x01',b'\xfb\x01\x23',b'\xfc\x01\x23\x45\x67',
      bytes.fromhex('fd0123456789abcdef'),b'\xfe',b'\xff',
      bytes.fromhex('fe112233445566778899'),bytes.fromhex('ff112233445566778899')]
for width in (32,64):
    charge=width//8
    for mode in (0,1,2,0x10000001,0xffffffff):
        for counter in (0,1,charge-1,charge,MAX-charge-1,MAX-charge,MAX-charge+1,MAX):
            limits={0,charge-1,charge,charge+1,MAX,counter}
            if counter<=MAX-charge:
                limits.update(x for x in (counter+charge-1,counter+charge,counter+charge+1) if 0<=x<=MAX)
            for limit in sorted(limits):
                for raw in raws:add('counter-mode-limit-boundaries',width,mode,counter,limit,raw)

for width in (32,64):
    charge=width//8
    for mode in (0,1):
        for tag in (0,1,250,251,252,253,254,255):
            for length in range(11):
                raw=(bytes([tag])+bytes((17*i+3)%256 for i in range(10)))[:length]
                add('critical-tags-all-lengths',width,mode,0,MAX,raw)
    for tag in range(256):
        for length in (1,charge+1):
            raw=(bytes([tag])+bytes((29*i+7)%256 for i in range(10)))[:length]
            add('all-tags-fast-and-slow',width,0,0,MAX,raw)

def answer(case):
    width=case['width'];charge=width//8
    counter=case['counter'];limit=case['limit'];raw=bytes.fromhex(case['raw_hex'])
    after=counter;written=False;used=0
    if case['mode']==1 and counter>MAX-charge:
        result={'tag':2};path='counter-overflow'
    else:
        if case['mode']==1:
            after=counter+charge;written=True
        if case['mode']==1 and after>limit:
            result={'tag':2};path='over-limit-after-store'
        else:
            fast=len(raw)>charge
            path='fast' if fast else 'slow-forced-little'
            if not raw:
                result={'tag':0,'additional':1}
            else:
                tag=raw[0]
                used=0 if fast else 1
                invalid={253:3,254:4,255:12} if width==32 else {254:4,255:12}
                if tag in invalid:
                    result={'tag':3,'expected':2 if width==32 or fast else 3,'found':invalid[tag]}
                elif tag<251:
                    result={'tag':18,'value':tag};used=1
                else:
                    total={251:3,252:5,253:9}[tag]
                    if len(raw)<total:
                        assert not fast
                        result={'tag':0,'additional':total-len(raw)}
                    else:
                        result={'tag':18,'value':int.from_bytes(raw[1:total],'little')};used=total
    return {'id':case['id'],'result':result,'counter_after':after,'counter_written':written,
            'path':path,'consumed':used,'remaining':len(raw)-used,
            'pointer_after':case['pointer']+used,'tail_hex':raw[used:].hex()}

inputs=[];answers=[]
for case in cases:
    inputs.append('\t'.join(str(case[k]) for k in ('id','width','mode','counter','limit','pointer','raw_hex'))+'\n')
    answers.append(answer(case))
input_raw=''.join(inputs).encode()
expected_raw=''.join(json.dumps(x,sort_keys=True,separators=(',',':'))+'\n' for x in answers).encode()
authority={'schema':'outer472-independent-pre-model-math/1','cases':cases,'expected':answers}
authority_raw=(json.dumps(authority,sort_keys=True,indent=2)+'\n').encode()
for name,raw in [('inputs.tsv',input_raw),('expected.jsonl',expected_raw),('authority.json',authority_raw)]:
    (P/name).write_bytes(raw)
assert len({(x['width'],x['mode'],x['counter'],x['limit'],x['pointer'],x['raw_hex']) for x in cases})==len(cases)
result_counts={};path_counts={}
for x in answers:
    result_counts[str(x['result']['tag'])]=result_counts.get(str(x['result']['tag']),0)+1
    path_counts[x['path']]=path_counts.get(x['path'],0)+1
freeze={'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'schema':'outer472-independent-pre-model-freeze/1',
        'target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
        'primary_bytes':472,'primary_rows':142,
        'native_review_sha256':'7848bfb0cfdcf4273d1904abaecb82607ac7f0e39528d7495aceabadbd0a0e0e',
        'cases':len(cases),'distinct_complete_inputs':len(cases),'distinct_without_pointer_or_ID':len(seen),
        'families':families,'result_tag_counts':result_counts,'path_counts':path_counts,
        'basis':'Fresh full native outer472B plus accepted253 and independently freshly authenticated623B Reader/helper relation',
        'new_model_or_Rust_read':False,'repository_imports':False,'target_execution':False,'PC_register_evaluator':False,
        'chosen_projection':'Valid separated state/buffer and ordinary helper returns. Pointer is a nonwrapping numeric observation label; result payload padding/privateABI excluded.',
        'scope_exclusions':['Original struct or ABI identity','Captured execution','Whole serialization component gates','Direct Reader Rust implementation already covered by1325','Budget result payload other than observed tag2'],
        'files':{name:{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for name,raw in [('inputs.tsv',input_raw),('expected.jsonl',expected_raw),('authority.json',authority_raw),('freeze.py',Path(__file__).read_bytes())]}}
f=P/'FREEZE.json';f.write_text(json.dumps(freeze,sort_keys=True,indent=2)+'\n')
print(json.dumps({'freeze_sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'cases':len(cases),'families':families,'paths':path_counts,'results':result_counts,'input_sha256':hashlib.sha256(input_raw).hexdigest(),'expected_sha256':hashlib.sha256(expected_raw).hexdigest()},sort_keys=True))
