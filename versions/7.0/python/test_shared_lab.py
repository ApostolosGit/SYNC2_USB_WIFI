"""Shared synthetic LAB fixture; no hardware or network."""
import io
import unittest
from pathlib import Path
from AIRCAT500_OfflineAudit_v5 import analyze_stream
from aircat_lab_replay import read_timeline
FIXTURE=Path(__file__).resolve().parents[1]/'android/app/src/test/resources/shared_lab.csv'
class SharedLab(unittest.TestCase):
    def test_common_fixture(self):
        with FIXTURE.open(encoding='utf-8-sig',newline='') as f:
            a=analyze_stream(f)
        with FIXTURE.open(encoding='utf-8-sig',newline='') as f:
            b=read_timeline(f)
        self.assertEqual(a,b.summary)
        for key,value in dict(frames=100,gaps=2,invalid_rows=1,interrupted_rotations=2,evaluated_rotations=3,perfect_rotations=2,observed_missing_sectors=1).items():
            self.assertEqual(a[key],value,key)
        self.assertEqual(a['missing_by_sector'][31],1)
    def test_long_offline(self):
        def rows():
            yield 'capture_event,capture_segment,source_us,frame_no,udp_payload_hex,capture_connection,reason,capture_index\n'
            for i in range(33001):
                s=i%33
                p='1940FD000000' if not s else f'0C40FD{s-1:02X}'
                yield f'FRAME,0,{i*125000},{i},{p},LAB TCP v5,,{i+1}\n'
        a=analyze_stream(rows())
        self.assertEqual((a['frames'],a['perfect_rotations'],a['gaps'],a['observed_missing_sectors']),(33001,1000,0,0))
if __name__=='__main__':unittest.main(verbosity=2)
