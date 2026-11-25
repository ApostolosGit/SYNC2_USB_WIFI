"""6.0 offline synthetic LAB replay and charts. No sockets or device access."""
from dataclasses import dataclass
from math import cos, sin, pi
from AIRCAT500_OfflineAudit_v5 import Audit, analyze_stream, NORTH

@dataclass(frozen=True)
class Event:
    kind: str
    source_us: int | None
    segment: int | None
    sector: int | None
    mask: int
    evaluated: int
    missing: int
    gaps: int
    ambiguous: int
    reason: str = ''
    rotation_miss: int | None = None
    period_us: int | None = None

@dataclass(frozen=True)
class Timeline:
    events: tuple
    summary: dict

class ReplayAudit(Audit):
    def __init__(self):
        super().__init__()
        self._events=[]
        self._reason=''
    def emit(self, kind, sector=None, rotation_miss=None, period_us=None):
        if len(self._events)>=250000:
            raise ValueError('LAB replay limit: 250,000 events; no partial report produced.')
        self._events.append(Event(kind,self._tick,self._segment,sector,
            sum(1<<n for n in self._seen) if self._active else 0,
            self.evaluated_rotations,self.observed_missing_sectors,self.gaps,
            self.ambiguous_rotations,self._reason,rotation_miss,period_us))
    def gap(self, invalid=False):
        super().gap(invalid)
        self.emit('INVALID' if invalid else 'GAP')
    def accept(self,row):
        self._reason=(row.get('reason') or '')[:300]
        try:
            if row.get('capture_event')=='GAP':
                super().accept(row)
                return
            # The separate LAB player accepts only synthetic NORTH/sector fixtures.
            try: p=bytes.fromhex(row.get('udp_payload_hex',''))
            except (TypeError,ValueError):p=b''
            if not (p==NORTH or (len(p)==4 and p[:3]==b'\x0c\x40\xfd' and p[3]<32)):
                self._reason='Unsupported or malformed synthetic fixture'
                self.gap(True);return
            before=(self.frames,self.evaluated_rotations,self.observed_missing_sectors,
                    self.ambiguous_rotations,len(self.source_intervals_us))
            super().accept(row)
            if self.frames==before[0]:return
            if self.ambiguous_rotations!=before[3]:
                self._reason='Duplicate/reversed sector; rotation excluded'
                self.emit('AMBIGUOUS');return
            rotation_miss=self.observed_missing_sectors-before[2] if self.evaluated_rotations>before[1] else None
            period=self.source_intervals_us[-1] if len(self.source_intervals_us)>before[4] else None
            self.emit('NORTH' if p==NORTH else 'SECTOR',None if p==NORTH else p[3],rotation_miss,period)
        finally:self._reason=''

def read_timeline(stream):
    a=ReplayAudit()
    summary=analyze_stream(stream,a)
    return Timeline(tuple(a._events),summary)

def load_timeline(path):
    with open(path,encoding='utf-8-sig',newline='') as f:return read_timeline(f)

def show_lab_replay(owner,timeline):
    import tkinter as tk
    from tkinter import ttk
    events=timeline.events
    win=tk.Toplevel(owner);win.title('AIRCAT500 6.0 — Synthetic LAB Replay')
    win.geometry('760x680')
    ttk.Label(win,text='Synthetic LAB only | No inference of physical radar fault',wraplength=700).pack(pady=5)
    status=tk.StringVar();ttk.Label(win,textvariable=status,wraplength=720,justify='left').pack(fill='x',padx=12)
    canvas=tk.Canvas(win,bg='white',height=390,highlightthickness=0);canvas.pack(fill='both',expand=True,padx=10,pady=5)
    state={'index':0,'playing':False,'direction':1,'timer':None,'drawing':False}
    slider=tk.IntVar(value=0)
    speed=tk.StringVar(value='1x')
    def draw(*_):
        if not events:
            status.set('No synthetic events');return
        e=events[state['index']]
        canvas.delete('all')
        w=max(canvas.winfo_width(),20);h=max(canvas.winfo_height(),20)
        cx=w/2;cy=h/2;r=max(10,min(w,h)/2-35)
        for i in range(32):
            x0=cx-r;y0=cy-r;x1=cx+r;y1=cy+r
            canvas.create_arc(x0,y0,x1,y1,start=90-(i+1)*11.25,extent=11.25,style='pieslice',
                fill='#b4d8c1' if e.mask & (1<<i) else '#f2f3f4',outline='#b7bcc2')
            th=(i+.5)*2*pi/32
            canvas.create_text(cx+(r+17)*sin(th),cy-(r+17)*cos(th),text=f'{i:02X}',font=('TkDefaultFont',8))
        if e.sector is not None:
            th=(e.sector+.5)*2*pi/32
            canvas.create_line(cx,cy,cx+r*sin(th),cy-r*cos(th),fill='#245c91',width=3)
        if e.kind in ('GAP','INVALID','AMBIGUOUS'):
            canvas.create_text(cx,cy,text=e.kind,fill='#a45a13',font=('TkDefaultFont',16,'bold'))
        tick='unknown' if e.source_us is None else f'{e.source_us/1e6:.6f} s'
        note='Indexed CSV' if timeline.summary.get('record_index_verified') else 'Legacy CSV: continuity incomplete'
        status.set(f'{state["index"]+1}/{len(events)}  {e.kind}  segment {e.segment if e.segment is not None else "—"}  source {tick}\n'
            f'Evaluated: {e.evaluated} | Observed miss: {e.missing} | Gaps: {e.gaps} | Ambiguous: {e.ambiguous}\n{note} {e.reason}')
        state['drawing']=True;slider.set(state['index']);state['drawing']=False
    def jump(v):
        if not state['drawing'] and events:
            state['index']=min(len(events)-1,max(0,int(float(v))));draw()
    def pause():
        state['playing']=False
        if state['timer'] is not None:
            try:win.after_cancel(state['timer'])
            except tk.TclError:pass
            state['timer']=None
    def step(direction):
        pause()
        if events:state['index']=max(0,min(len(events)-1,state['index']+direction));draw()
    def tick():
        state['timer']=None
        if not state['playing'] or not events:return
        i=state['index'];j=i+state['direction']
        if not 0<=j<len(events):pause();return
        state['index']=j;draw();schedule()
    def schedule():
        if not state['playing'] or not events:return
        i=state['index'];j=i+state['direction']
        if not 0<=j<len(events):pause();return
        a,b=events[i],events[j]
        delay=200
        if a.source_us is not None and b.source_us is not None and a.segment==b.segment:
            delay=abs(b.source_us-a.source_us)/1000
        rate=float(speed.get().rstrip('x'))
        state['timer']=win.after(max(20,min(2000,int(delay/rate))),tick)
    def play(direction):
        pause();state['playing']=True;state['direction']=direction;schedule()
    ttk.Scale(win,from_=0,to=max(0,len(events)-1),variable=slider,command=jump).pack(fill='x',padx=10)
    row=ttk.Frame(win);row.pack(pady=8)
    for label,cmd in [('<<',lambda:play(-1)),('Previous',lambda:step(-1)),('Pause',pause),
                      ('Next',lambda:step(1)),('Play >>',lambda:play(1)),('Charts',lambda:show_lab_charts(win,timeline))]:
        ttk.Button(row,text=label,command=cmd).pack(side='left',padx=2)
    ttk.Combobox(row,textvariable=speed,values=('0.5x','1x','2x','4x','8x'),state='readonly',width=6).pack(side='left',padx=3)
    ttk.Label(win,text='Playback pacing is capped for display; no time is inferred across gaps.').pack(pady=4)
    canvas.bind('<Configure>',draw)
    win.protocol('WM_DELETE_WINDOW',lambda:(pause(),win.destroy()))
    draw()

def show_lab_charts(owner,timeline):
    import tkinter as tk
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    win=tk.Toplevel(owner);win.title('AIRCAT500 6.0 — Synthetic LAB Charts');win.geometry('1100x760')
    fig=Figure(figsize=(10,7),layout='constrained')
    ax1,ax2,ax3,ax4=fig.subplots(2,2).flat
    summary=timeline.summary
    ax1.bar(range(32),summary['missing_by_sector']);ax1.set_title('Observed missing IDs by sector')
    ax1.set_xticks(range(0,32,4),[f'{i:02X}' for i in range(0,32,4)])
    rotations=[(i+1,e) for i,e in enumerate(timeline.events) if e.rotation_miss is not None]
    ax2.scatter([i for i,e in rotations],[e.rotation_miss for i,e in rotations],s=12)
    ax2.set_title('Missing IDs per evaluated interval');ax2.set_xlabel('Replay event index')
    times=[(i,e.period_us/1e6) for i,e in rotations if e.period_us is not None]
    ax3.scatter([i for i,_ in times],[v for _,v in times],s=12)
    ax3.set_title('Source NORTH intervals (s)');ax3.set_xlabel('Replay event index')
    ax4.bar(['GAP/invalid','Ambiguous','Evaluated'],[summary['gaps'],summary['ambiguous_rotations'],summary['evaluated_rotations']])
    ax4.set_title('Continuity categories (separate counts)')
    fig.suptitle('Synthetic LAB only — source timing, no arrival-time inference')
    c=FigureCanvasTkAgg(fig,master=win);c.draw();c.get_tk_widget().pack(fill='both',expand=True)
    NavigationToolbar2Tk(c,win).update()
