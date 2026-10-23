"""Reproducible source-snapshot digests; no claim of tamper-proof storage."""
import hashlib
import hmac
import json

CANONICALIZATION='redsecsoc-json-v1: sorted keys, compact separators, UTF-8, ensure_ascii=false'
def digest(source):
    return hashlib.sha256(json.dumps(source,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf-8')).hexdigest()

def verify(snapshot,expected):
    source=snapshot.get('source')
    actual=digest(source) if isinstance(source,dict) else None
    return {'algorithm':'SHA-256','canonicalization':CANONICALIZATION,'matches':bool(actual and hmac.compare_digest(actual,expected)),'computed':actual,'stored':expected,'notice':'Verifies the preserved source copy against its recorded digest. This is not a digital signature, immutable storage or an assertion that the event itself is truthful.'}
