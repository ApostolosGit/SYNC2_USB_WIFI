"""AIRCAT500 v5 offline audit for synthetic LAB TCP CSV files only.
No live I/O, no device control, no network connections.
"""
import argparse
import csv
import io
import json
import statistics
import unittest
from dataclasses import dataclass, field

REQUIRED = {'capture_event', 'capture_segment', 'source_us', 'frame_no',
            'udp_payload_hex', 'capture_connection', 'reason'}
NORTH = bytes.fromhex('1940FD000000')

@dataclass
class Audit:
    frames: int = 0
    gaps: int = 0
    invalid_rows: int = 0
    interrupted_rotations: int = 0
    ambiguous_rotations: int = 0
    evaluated_rotations: int = 0
    perfect_rotations: int = 0
    observed_missing_sectors: int = 0
    duplicate_sectors: int = 0
    missing_by_sector: list = field(default_factory=lambda: [0]*32)
    source_intervals_us: list = field(default_factory=list)
    _active: bool = False
    _seen: set = field(default_factory=set)
    _last_sector: int | None = None
    _north: int | None = None
    _segment: int | None = None
    _tick: int | None = None
    _seq: int | None = None

    def reset(self):
        self._active = False; self._seen.clear(); self._last_sector = None
        self._north = None; self._tick = None; self._seq = None

    def gap(self, invalid=False):
        self.gaps += 1
        self.invalid_rows += int(invalid)
        self.interrupted_rotations += int(self._active)
        self.reset(); self._segment = None

    def accept(self, row):
        event = row.get('capture_event', '')
        if event == 'GAP':
            self.gap(); return
        try:
            if event != 'FRAME' or row.get('capture_connection') != 'LAB TCP v5':
                raise ValueError('Unsupported event or source')
            seg, tick, seq = (int(row[x]) for x in ('capture_segment','source_us','frame_no'))
            if min(seg,tick,seq)<0 or seq>0xffffffff: raise ValueError('Invalid metadata')
            p = bytes.fromhex(row['udp_payload_hex'])
            if len(p)<2 or p[1]!=0x40: raise ValueError('Invalid payload')
            if p[0]==0x19 and p!=NORTH: raise ValueError('Invalid NORTH')
            if p[0]==0x0c and (len(p)<4 or p[2]!=0xfd or p[3]>31): raise ValueError('Invalid sector')
        except (ValueError, TypeError, KeyError):
            self.gap(True); return
        # Sequence gaps are not interpreted as lost frames: heartbeats are not CSV rows.
        if self._segment is not None and (seg!=self._segment or tick<self._tick or
                not 0<((seq-self._seq)&0xffffffff)<0x80000000):
            self.gap()
        self._segment, self._tick, self._seq = seg,tick,seq
        self.frames += 1
        if p==NORTH:
            if self._active:
                missing=set(range(32))-self._seen
                self.evaluated_rotations+=1
                self.perfect_rotations+=int(not missing)
                self.observed_missing_sectors+=len(missing)
                for s in missing:self.missing_by_sector[s]+=1
                if self._north is not None and tick>self._north:
                    self.source_intervals_us.append(tick-self._north)
            self._active=True;self._seen.clear();self._last_sector=None;self._north=tick
        elif p[0]==0x0c and self._active:
            sec=p[3]
            if sec in self._seen or (self._last_sector is not None and sec<=self._last_sector):
                # A missing NORTH, duplicate or reversed sector makes the interval ambiguous.
                self.duplicate_sectors+=int(sec in self._seen)
                self.ambiguous_rotations+=1
                self._active=False;self._seen.clear();self._north=None;self._last_sector=None
                return
            self._seen.add(sec);self._last_sector=sec

    def report(self):
        d={k:v for k,v in vars(self).items() if not k.startswith('_') and k!='source_intervals_us'}
        d['trailing_partial_rotation']=int(self._active)
        d['source_intervals_measured']=len(self.source_intervals_us)
        d['source_median_period_us']=statistics.median(self.source_intervals_us) if self.source_intervals_us else None
        d['source_timing_outliers']=None
        if len(self.source_intervals_us)>=10:
            median=d['source_median_period_us']
            d['source_timing_outliers']=sum(abs(v/median-1)>0.05 for v in self.source_intervals_us)
        d['interpretation']='Observed missing IDs in recorded LAB intervals without detected gaps; not proof of physical radar failure. CSV omits heartbeat records, so an unmarked deletion is not always detectable. No arrival-time inference.'
        return d

def analyze_stream(stream):
    reader=csv.DictReader(stream)
    if not REQUIRED.issubset(reader.fieldnames or []):
        raise ValueError('Not a continuity-aware v5 LAB CSV. Legacy files cannot establish continuity.')
    a=Audit()
    indexed='capture_index' in (reader.fieldnames or [])
    expected=1
    for row in reader:
        if indexed:
            try:
                n=int(row['capture_index'])
                if n<1:raise ValueError('Invalid index')
            except (ValueError,TypeError,KeyError):
                a.gap(True)
                continue
            if n!=expected:a.gap(True)
            expected=n+1
        a.accept(row)
    report=a.report()
    report['record_index_verified']=indexed
    if indexed:
        report['interpretation']='Observed missing IDs in recorded LAB intervals without detected gaps. Capture-index discontinuities invalidate the active rotation. Not proof of physical radar failure; no arrival-time inference.'
    return report

def analyze_file(path):
    with open(path,encoding='utf-8-sig',newline='') as f:return analyze_stream(f)

def gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox
    from tkinter.scrolledtext import ScrolledText
    root=tk.Tk();root.title('AIRCAT500 v5 — Offline LAB Audit');root.geometry('800x600')
    out=ScrolledText(root,wrap='word');out.pack(fill='both',expand=True,padx=12,pady=12)
    def choose():
        path=filedialog.askopenfilename(filetypes=[('CSV','*.csv'),('All files','*.*')])
        if not path:return
        try:result=analyze_file(path)
        except Exception as e:messagebox.showerror('CSV audit',str(e));return
        out.delete('1.0','end');out.insert('end',json.dumps(result,indent=2,ensure_ascii=False))
    tk.Button(root,text='Open LAB CSV',command=choose).pack(pady=10)
    root.mainloop()

class Tests(unittest.TestCase):
    def make(self, sequence):
        a=Audit()
        for i,item in enumerate(sequence):
            if item=='GAP':a.accept({'capture_event':'GAP'});continue
            if isinstance(item,tuple):s,tick,seg=item
            else:s,tick,seg=item,i*125000,0
            payload=NORTH if s=='N' else bytes((0x0c,0x40,0xfd,s))
            a.accept(dict(capture_event='FRAME',capture_segment=str(seg),source_us=str(tick),frame_no=str(i),udp_payload_hex=payload.hex(),capture_connection='LAB TCP v5'))
        return a.report()
    def test_perfect(self):self.assertEqual(self.make(['N',*range(32),'N'])['perfect_rotations'],1)
    def test_one_missing(self):self.assertEqual(self.make(['N',*[i for i in range(32) if i!=9],'N'])['observed_missing_sectors'],1)
    def test_gap(self):
        d=self.make(['N',0,1,'GAP',20,21,'N',*range(32),'N']);self.assertEqual((d['observed_missing_sectors'],d['perfect_rotations'],d['interrupted_rotations']),(0,1,1))
    def test_wrap(self):
        d=self.make(['N',*range(32),0,1,'N']);self.assertEqual((d['observed_missing_sectors'],d['ambiguous_rotations']),(0,1))
    def test_source_time_backwards(self):
        d=self.make([('N',100,0),(0,200,0),('N',50,0)]);self.assertEqual((d['observed_missing_sectors'],d['gaps']),(0,1))
    def test_segment_change(self):
        d=self.make([('N',100,0),(0,200,0),('N',300,1)]);self.assertEqual((d['observed_missing_sectors'],d['gaps']),(0,1))
    def test_timing(self):
        d=self.make(['N',*range(32),'N']);self.assertEqual(d['source_median_period_us'],4125000)
    def test_bad_row(self):
        a=Audit();a.accept({'capture_event':'FRAME'});self.assertEqual(a.report()['invalid_rows'],1)
    def test_legacy_refused(self):
        with self.assertRaises(ValueError):analyze_stream(io.StringIO('udp_payload_hex\n1940FD000000\n'))
    def test_trailing(self):self.assertEqual(self.make(['N',0,1])['observed_missing_sectors'],0)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('csv',nargs='?');p.add_argument('--self-test',action='store_true');p.add_argument('--gui',action='store_true');a=p.parse_args()
    if a.self_test:unittest.main(argv=['self-test'])
    elif a.gui:gui()
    elif a.csv:print(json.dumps(analyze_file(a.csv),indent=2,ensure_ascii=False))
    else:p.print_help()
