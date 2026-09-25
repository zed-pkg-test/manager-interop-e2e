import hashlib, json

def digest(entries):
    normalized = sorted(entries, key=lambda x: (x['name'], x['version']))
    data = json.dumps(normalized, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(data.encode()).hexdigest()

a = [{'name':'a','version':'1'}, {'name':'b','version':'2'}]
b = list(reversed(a))
c = [{'name':'a','version':'1'}, {'name':'b','version':'3'}]
assert digest(a) == digest(b)
assert digest(a) != digest(c)
print('formal_wave5_model: ok')
