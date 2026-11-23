import sys
sys.path.insert(0, 'harness')
from target_logs import collect_events
from hand_lab import _format_event_line
file = input('Enter the file path (example: B/target-events-20261115T225533Z.jsonl):')
text = open("runs/hand/" +file, encoding='utf-8').read()
for e in collect_events(text, '0'*32):
    print(_format_event_line(e))
