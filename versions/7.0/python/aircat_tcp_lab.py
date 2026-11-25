"""TCP transport for the isolated SYNC-LAB synthetic generator only.
No external clock/data acquisition or access to real radar systems.
"""
from __future__ import annotations
import collections, re, socket, struct, time, zlib, threading
SSID='SYNC-LAB'
DEVICE_IP='192.168.4.1'
DATA_PORT=5005
HEADER=struct.Struct('<4sBBHIIQI')
CSV_EXTRA=('capture_event','capture_segment','source_us','reason','capture_index')

class Decoder:
    def __init__(self): self.buffer=bytearray()
    def feed(self,data):
        self.buffer.extend(data)
        out=[]
        while len(self.buffer)>=HEADER.size:
            magic,v,k,n,seq,sid,us,crc=HEADER.unpack_from(self.buffer)
            if magic!=b'AC5T' or v!=5 or k not in (0,1,2) or n>8192 or (k!=1 and n):
                raise ValueError('TCP LAB invalid header')
            if len(self.buffer)<HEADER.size+n:break
            raw=bytes(self.buffer[:HEADER.size+n]);del self.buffer[:len(raw)]
            p=raw[HEADER.size:]
            if zlib.crc32(raw[:24]+p)&0xffffffff!=crc:raise ValueError('TCP LAB CRC32')
            out.append((k,seq,sid,us,p))
        return out

class Continuity:
    def __init__(self): self.seq=self.sid=self.tick=None
    def observe(self,k,seq,sid,tick):
        gap=(k==2 or (self.sid is not None and (sid!=self.sid or seq!=((self.seq+1)&0xffffffff)))
             or (k==1 and self.tick is not None and tick<self.tick))
        self.seq,self.sid=seq,sid
        if gap:self.tick=None
        if k==1:self.tick=tick
        return gap

class WifiReceiver:
    """Adapter for the original GUI. None=no data; empty bytes=gap.
    Legacy udp_* names are compatibility aliases, not UDP packets.
    """
    def __init__(self,pin='1234',*,_connector=None):
        if not re.fullmatch(r'\d{4}',str(pin)):raise ValueError('PIN must be four digits')
        self.pin=str(pin)
        self._connector=_connector or self._connect_lab
        self.data_socket=None
        self._closed=threading.Event()
        self._lock=threading.Lock()
        self._pending=collections.deque()
        self._decoder=Decoder();self._continuity=Continuity()
        self._retry_at=0.;self._backoff=1.
        self._last_rx=self._last_ping=0.
        self._anchor=None
        self.ack=False
        self.udp_received=self.udp_lost=self.udp_duplicates=0
        self.udp_invalid=self.udp_bad_crc32=self.udp_v2=0
        self.firmware_overflow=0;self.firmware_overflow_at_connect=None
        self.clock_hz=0
        self.link_reset=False;self.last_data_time=None
        self.source_us=self.source_epoch=None
        self.segment=0;self.gap_reason=''
    @staticmethod
    def _connect_lab():
        return socket.create_connection((DEVICE_IP,DATA_PORT),timeout=3)
    def open(self):
        self._retry_at=0
        return self
    def _detach(self):
        with self._lock:s,self.data_socket=self.data_socket,None
        if s is not None:
            try:s.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            try:s.close()
            except OSError:pass
    def _gap(self,reason):
        self.segment+=1;self.udp_lost+=1;self.link_reset=True;self.gap_reason=reason
        self._anchor=None;self.source_epoch=self.source_us=None
        return b''
    def _failed(self,reason):
        self._detach();self._pending.clear();self._decoder=Decoder();self._continuity=Continuity()
        self.ack=False;self._retry_at=time.monotonic()+self._backoff;self._backoff=min(10.,self._backoff*2)
        return self._gap(reason)
    def read(self):
        self.link_reset=False
        if self._closed.is_set():return None
        now=time.monotonic()
        if self.data_socket is None:
            if now<self._retry_at:
                self._closed.wait(min(.25,self._retry_at-now));return None
            try:
                s=self._connector();s.settimeout(.25)
                with self._lock:
                    if self._closed.is_set():s.close();return None
                    self.data_socket=s
                s.sendall(('AIRCAT_TCP_V5 '+self.pin+'\n').encode('ascii'))
                self._last_rx=self._last_ping=time.monotonic()
            except OSError as exc:return self._failed('TCP LAB connect: '+str(exc))
        s=self.data_socket
        if s is None:return None
        try:
            now=time.monotonic()
            if now-self._last_rx>=10:raise TimeoutError('TCP LAB inactivity')
            if now-self._last_ping>=2:s.sendall(b'P\n');self._last_ping=now
            if not self._pending:
                try:raw=s.recv(8192)
                except socket.timeout:return None
                if not raw:raise ConnectionError('TCP LAB EOF')
                self._pending.extend(self._decoder.feed(raw))
            if not self._pending:return None
            k,seq,sid,tick,p=self._pending.popleft()
            self._last_rx=time.monotonic();self.ack=True;self._backoff=1.
            if k!=3 and self._continuity.observe(k,seq,sid,tick):
                if k==1:self._pending.appendleft((3,seq,sid,tick,p))
                return self._gap('LAB continuity boundary')
            if k==0:return None
            if k==2:return self._gap('LAB source discontinuity')
            if self._anchor is None:self._anchor=time.time()-tick/1000000.
            self.source_us=tick;self.source_epoch=self._anchor+tick/1000000.
            self.udp_received+=1;self.last_data_time=time.monotonic()
            return p
        except (OSError,ValueError) as exc:
            if self._closed.is_set():return None
            if isinstance(exc,ValueError):
                self.udp_invalid+=1
                if 'CRC32' in str(exc):self.udp_bad_crc32+=1
            return self._failed(str(exc))
    @property
    def firmware_overflow_since_connect(self):return 0
    def close(self):
        self._closed.set();self._detach()
