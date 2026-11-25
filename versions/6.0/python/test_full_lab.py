"""Regression tests for the full GUI's isolated synthetic TCP LAB path."""
import ast
import csv
import io
import pathlib
import struct
import sys
import unittest
import zlib
from types import SimpleNamespace

import aircat_tcp_lab as tcp
import AIRCAT500_Analyzer_v6_0 as app
import AIRCAT500_OfflineAudit_v5 as audit

def wire(k,seq,sid,tick,p=b''):
    h=tcp.HEADER.pack(b'AC5T',5,k,len(p),seq,sid,tick,0)
    return h[:24]+struct.pack('<I',zlib.crc32(h[:24]+p)&0xffffffff)+p

def fixture(sec):
    body=bytes((0xfd,0,0,0)) if sec==32 else bytes((0xfd,sec))
    h=bytes((0x19 if sec==32 else 0x0c,0x40,0x10,2))
    return b'\x32\x32\x32\x01'+h+body.replace(b'\x10',b'\x10\x10')+b'\x10\x03'+app.crc16_kermit(h+body+b'\x03').to_bytes(2,'little')

class FakeSocket:
    def __init__(self, chunks):self.chunks=iter(chunks);self.closed=False
    def settimeout(self,timeout):pass
    def sendall(self,data):pass
    def recv(self,size):return next(self.chunks,b'')
    def shutdown(self,how):self.closed=True
    def close(self):self.closed=True

class Tests(unittest.TestCase):
    def test_full_legacy_function_inventory(self):
        tree=ast.parse(pathlib.Path(app.__file__).read_text(encoding='utf-8'))
        actual=set()
        for node in tree.body:
            if isinstance(node,ast.FunctionDef):actual.add(node.name)
            elif isinstance(node,ast.ClassDef):
                actual.update(node.name+'.'+m.name for m in node.body if isinstance(m,ast.FunctionDef))
        expected=set(pathlib.Path(__file__).with_name('legacy_functions.txt').read_text().splitlines())
        self.assertFalse(expected-actual,sorted(expected-actual))
        self.assertEqual(app.APP_VERSION,'6.0 LAB')
        print('Legacy definitions checked:',len(expected))
    def test_decoder_fragmentation(self):
        d=tcp.Decoder();data=wire(0,0,1,0)+wire(1,1,1,125000,fixture(32))
        rows=[]
        for v in data:rows+=d.feed(bytes([v]))
        self.assertEqual([x[0] for x in rows],[0,1])
    def test_bad_crc(self):
        d=tcp.Decoder();data=bytearray(wire(0,0,1,0));data[24]^=1
        with self.assertRaises(ValueError):d.feed(data)
    def test_gap_before_next_frame(self):
        first=wire(1,0,1,0,fixture(32))
        later=wire(1,2,1,125000,fixture(3))
        sock=FakeSocket([first+later])
        r=tcp.WifiReceiver(_connector=lambda:sock).open()
        self.assertEqual(r.read(),fixture(32))
        self.assertEqual(r.read(),b'')
        self.assertEqual(r.read(),fixture(3))
        self.assertEqual(r.udp_lost,1)
        r.close()
    def test_reconnect(self):
        socks=iter([FakeSocket([wire(1,0,1,0,fixture(32)),b'']),
                    FakeSocket([wire(1,0,2,10,fixture(32))])])
        r=tcp.WifiReceiver(_connector=lambda:next(socks)).open()
        self.assertEqual(r.read(),fixture(32))
        self.assertEqual(r.read(),b'')
        r._retry_at=0
        self.assertEqual(r.read(),fixture(32))
        self.assertEqual(r.udp_lost,1)
        r.close()
    def test_synthetic_observer_clean_and_missing(self):
        o=app.LabBSCObserver()
        for s in [32,*[i for i in range(32) if i!=9],32]:
            _,valid=o.lab_feed(fixture(s))
            self.assertTrue(valid,s)
        self.assertEqual(o.counters()['lost_sectors'],1)
    def test_observer_gap(self):
        o=app.LabBSCObserver()
        for s in [32,0,1]:self.assertTrue(o.lab_feed(fixture(s))[1])
        o.lab_gap()
        for s in [18,19,32]:self.assertTrue(o.lab_feed(fixture(s))[1])
        self.assertEqual(o.counters()['lost_sectors'],0)
    def test_north_missing_wrap(self):
        o=app.LabBSCObserver()
        for s in [32,*range(32)]:self.assertTrue(o.lab_feed(fixture(s))[1])
        self.assertFalse(o.lab_feed(fixture(0))[1])
        self.assertTrue(o.lab_feed(fixture(32))[1])
        self.assertEqual(o.counters()['lost_sectors'],0)
    def test_gui_gap_reset(self):
        a=SimpleNamespace(live_state={'current_cycle_active':True,'current_cycle_sectors':[1,2],
            'valid_north_times':[1.0,2.0],'sector_memory':{1:[]},'sector_history':{1:[]}})
        app.AircatStatsApp._apply_live_record(a,{'_lab_gap':'test'},False)
        self.assertFalse(a.live_state['current_cycle_active'])
        self.assertEqual(a.live_state['valid_north_times'],[])
        self.assertEqual(a.live_state['lab_gaps'],1)
    def test_row_contract(self):
        a=SimpleNamespace(live_capture_source='wifi',live_udp_record_metadata={'capture_connection':'LAB TCP v5'})
        r=app.AircatStatsApp._live_udp_record_row(a,{'payload':b'','_lab_gap':'disconnect','_lab_segment':2,'_lab_index':4})
        self.assertEqual(len(r),len(app.LIVE_RECORD_CSV_FIELDS)+len(tcp.CSV_EXTRA))
        self.assertEqual(r[-5:],['GAP',2,'','disconnect',4])
        a.live_capture_source='usb'
        self.assertEqual(len(app.AircatStatsApp._live_udp_record_row(a,{})),len(app.LIVE_RECORD_CSV_FIELDS))
    def test_index_deleted(self):
        f=io.StringIO()
        w=csv.DictWriter(f,fieldnames=sorted(audit.REQUIRED|{'capture_index'}));w.writeheader()
        for index,sec in enumerate([32,*range(32),32],1):
            if sec==9:continue
            p=audit.NORTH if sec==32 else bytes((0x0c,0x40,0xfd,sec))
            w.writerow(dict(capture_event='FRAME',capture_segment=0,source_us=index*125000,frame_no=index,
                udp_payload_hex=p.hex(),capture_connection='LAB TCP v5',capture_index=index))
        f.seek(0);result=audit.analyze_stream(f)
        self.assertTrue(result['record_index_verified'])
        self.assertEqual(result['observed_missing_sectors'],0)
        self.assertGreater(result['gaps'],0)

if __name__=='__main__':unittest.main(verbosity=2)
