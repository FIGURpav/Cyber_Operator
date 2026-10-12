"""Deterministic byte budgets with optional caller-supplied exact token counting."""
from __future__ import annotations

import hashlib
import json


def compose(required, sections, *, required_tail='', max_bytes=65536, section_bytes=16384, token_counter=None, max_tokens=None):
    if type(max_bytes) is not int or not 2048<=max_bytes<=4*1024*1024:
        raise ValueError('max_bytes must be between 2048 and 4194304')
    if type(section_bytes) is not int or section_bytes<256:
        raise ValueError('section_bytes must be at least 256')
    if max_tokens is not None and (type(max_tokens) is not int or max_tokens<1 or not callable(token_counter)):
        raise ValueError('token budgets require a positive limit and a configured exact token counter')
    required=required.rstrip()+'\n\n'
    def fits(text):
        return len(text.encode())<=max_bytes and (max_tokens is None or token_counter(text)<=max_tokens)
    records=[{'source':name,'source_bytes':len(text.encode()),'source_sha256':hashlib.sha256(text.encode()).hexdigest(),
              'included_bytes':0} for name,text in sections]
    chunks=[f'## {name}\n\n' for name,_ in sections]
    def render():
        omissions=[{**record,'omitted_bytes':record['source_bytes']-record['included_bytes']}
                   for record in records if record['included_bytes']<record['source_bytes']]
        footer='## Context budget\n\n'
        footer+='Omitted material must be reviewed at its source before relying on it for an action.\n' if omissions else 'All selected sections fit within the budget.\n'
        footer+='```\n'+json.dumps({'max_bytes':max_bytes,'omissions':omissions},sort_keys=True)+'\n```\n'
        return required+''.join(chunks)+required_tail+'\n\n'+footer
    if not fits(render()):
        raise ValueError('critical configuration and omission references exceed the budget; increase the limit')
    for index,(name,text) in enumerate(sections):
        raw=text.encode()
        low,high=0,min(section_bytes,len(raw))
        # Byte count is monotonic; token counts need not be, so trim independently below.
        while low<high:
            count=(low+high+1)//2
            part=raw[:count].decode('utf-8',errors='ignore')
            records[index]['included_bytes']=len(part.encode())
            chunks[index]=f'## {name}\n\n{part}\n\n'
            if len(render().encode())<=max_bytes:
                low=count
            else:
                high=count-1
        part=raw[:low].decode('utf-8',errors='ignore')
        while True:
            records[index]['included_bytes']=len(part.encode())
            chunks[index]=f'## {name}\n\n{part}\n\n'
            if fits(render()):
                break
            if not part:
                raise ValueError('critical configuration exceeds the token budget')
            part=part[:max(0,len(part)-max(1,len(part)//8))]
    content=render()
    return content,{'bytes':len(content.encode()),'tokens':token_counter(content) if token_counter else None,
                    'sections':records,'max_bytes':max_bytes}
