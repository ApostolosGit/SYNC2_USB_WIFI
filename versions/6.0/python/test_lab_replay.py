import csv, io, unittest
from AIRCAT500_OfflineAudit_v5 import REQUIRED
from aircat_lab_replay import read_timeline

def timeline(sequence,deleted=None,indexed=True):
    f=io.StringIO()
    fields=sorted(REQUIRED|({'capture_index'} if indexed else set()))
    w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
    for i,sec in enumerate(sequence,1):
        if i==deleted:continue
        row=dict(capture_event='FRAME',capture_segment=0,source_us=i*125000,frame_no=i,
                 udp_payload_hex=('1940FD000000' if sec=='N' else f'0C40FD{sec:02X}' if isinstance(sec,int) else ''),
                 capture_connection='LAB TCP v5',reason='')
        if sec=='GAP':row.update(capture_event='GAP',reason='disconnect')
        if indexed:row['capture_index']=i
        w.writerow(row)
    f.seek(0);return read_timeline(f)
class Tests(unittest.TestCase):
    def test_complete(self):
        t=timeline(['N',*range(32),'N'])
        self.assertEqual(t.events[-1].rotation_miss,0);self.assertEqual(t.events[-1].period_us,4125000)
    def test_gap(self):
        t=timeline(['N',0,1,'GAP',20,'N',*range(32),'N'])
        gap=next(e for e in t.events if e.kind=='GAP')
        self.assertEqual(gap.mask,0);self.assertIsNone(gap.source_us)
        self.assertEqual(t.summary['observed_missing_sectors'],0)
        self.assertEqual(t.summary['evaluated_rotations'],1)
    def test_deleted(self):
        t=timeline(['N',*range(32),'N'],deleted=10)
        self.assertTrue(any(e.kind=='INVALID' for e in t.events))
        self.assertEqual(t.summary['observed_missing_sectors'],0)
    def test_missing(self):
        t=timeline(['N',*[s for s in range(32) if s!=9],'N'])
        self.assertEqual(t.events[-1].rotation_miss,1)
        self.assertEqual(t.summary['missing_by_sector'][9],1)
    def test_ambiguous(self):
        t=timeline(['N',0,1,0,'N'])
        self.assertTrue(any(e.kind=='AMBIGUOUS' for e in t.events))
        self.assertEqual(t.summary['evaluated_rotations'],0)
    def test_unindexed(self):
        self.assertFalse(timeline(['N',0,'N'],indexed=False).summary['record_index_verified'])
    def test_no_partial(self):
        self.assertEqual(timeline(['N',0,1]).summary['evaluated_rotations'],0)
if __name__=='__main__':unittest.main(verbosity=2)
