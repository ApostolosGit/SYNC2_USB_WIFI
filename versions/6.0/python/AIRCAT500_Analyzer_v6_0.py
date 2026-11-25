# AIRCAT500 Analyzer v6.0 LAB | full v40.0 GUI + synthetic TCP LAB; legacy USB/LAN/offline retained
from __future__ import annotations

import bisect
import csv
import json
import math
import multiprocessing
import os
import platform
from pathlib import Path
import queue
import re
import shutil
import struct
import statistics
import subprocess
import threading
import time
import tkinter as tk
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, date
from tkinter import filedialog, messagebox, scrolledtext, ttk
from tkinter import font as tkfont
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.ticker import AutoMinorLocator, MultipleLocator, MaxNLocator


# ===== BEGIN EMBEDDED SYNC2WIFI v20 MODULE (no external .py required) =====
"""SYNC2WIFI v20 transport and independent serial-line monitor.
Uses the separate AC5T TCP LAB adapter for synthetic data only.
No third-party Python packages are required for Wi-Fi transport.
"""
import datetime as _wifi_datetime
import json
import os
from pathlib import Path
import queue
import re
import socket
import struct
import zlib
import subprocess
import tempfile
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from xml.sax.saxutils import escape as xml_escape

SSID = 'SYNC-LAB'
DEVICE_IP = '192.168.4.1'
HELLO_PORT = 5006
DATA_PORT = 5005
HELLO_PREFIX = b'AIRCAT_HELLO_V1 '
ACK_PREFIX = b'AIRCAT_ACK_V1'
_HEADER = struct.Struct('<4sBBHIII')  # Wi-Fi legacy v1 (20 bytes)
_HEADER_V2 = struct.Struct('<4sBBHIIII') # Wi-Fi v2 + CRC32 (24 bytes)


def _run_netsh(*args, timeout=12):
    if os.name != 'nt':
        raise OSError('Η αυτόματη σύνδεση Wi-Fi υποστηρίζεται στα Windows. Συνδέσου χειροκίνητα στο SSID SYNC-LAB.')
    kwargs = {'stdout':subprocess.PIPE, 'stderr':subprocess.STDOUT, 'text':True,
              'encoding':'utf-8','errors':'replace','timeout':timeout}
    if hasattr(subprocess,'CREATE_NO_WINDOW'):
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
    return subprocess.run(['netsh','wlan',*args], **kwargs)


def _request_fresh_wlan_scan():
    """Ask the Windows WLAN service to scan its real radio interfaces.

    A saved Windows profile is NOT an available AP.  The netsh network list
    is also cached, so issue WLAN API WlanScan first.  An unconfirmed scan
    never produces a green/verified result in the UI.
    """
    if os.name != 'nt':
        return False, 'Η αυτόματη σάρωση υποστηρίζεται μόνο σε Windows.'
    try:
        import ctypes
        from ctypes import wintypes
        class GUID(ctypes.Structure):
            _fields_=[('Data1',wintypes.DWORD),('Data2',wintypes.WORD),
                      ('Data3',wintypes.WORD),('Data4',ctypes.c_ubyte*8)]
        class WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_=[('InterfaceGuid',GUID),
                      ('strInterfaceDescription',ctypes.c_wchar*256),
                      ('isState',wintypes.DWORD)]
        wlan=ctypes.WinDLL('wlanapi')
        wlan.WlanOpenHandle.argtypes=[wintypes.DWORD,ctypes.c_void_p,
                                       ctypes.POINTER(wintypes.DWORD),
                                       ctypes.POINTER(wintypes.HANDLE)]
        wlan.WlanOpenHandle.restype=wintypes.DWORD
        wlan.WlanEnumInterfaces.argtypes=[wintypes.HANDLE,ctypes.c_void_p,
                                           ctypes.POINTER(ctypes.c_void_p)]
        wlan.WlanEnumInterfaces.restype=wintypes.DWORD
        wlan.WlanScan.argtypes=[wintypes.HANDLE,ctypes.POINTER(GUID),
                                 ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]
        wlan.WlanScan.restype=wintypes.DWORD
        wlan.WlanFreeMemory.argtypes=[ctypes.c_void_p]
        wlan.WlanCloseHandle.argtypes=[wintypes.HANDLE,ctypes.c_void_p]
        negotiated=wintypes.DWORD()
        handle=wintypes.HANDLE()
        rc=wlan.WlanOpenHandle(2,None,ctypes.byref(negotiated),ctypes.byref(handle))
        if rc:
            return False, f'Windows WLAN API: σφάλμα {rc} (WlanOpenHandle).'
        ptr=ctypes.c_void_p()
        try:
            rc=wlan.WlanEnumInterfaces(handle,None,ctypes.byref(ptr))
            if rc:
                return False, f'Windows WLAN API: σφάλμα {rc} (WlanEnumInterfaces).'
            if not ptr.value:
                return False, 'Δεν υπάρχει Wi-Fi προσαρμογέας.'
            count=ctypes.c_uint32.from_address(ptr.value).value
            if not count:
                return False, 'Δεν υπάρχει ενεργή διασύνδεση Wi-Fi.'
            start=ptr.value+8  # DWORD count, DWORD index, then WLAN_INTERFACE_INFO[]
            items=ctypes.cast(start,ctypes.POINTER(WLAN_INTERFACE_INFO))
            errors=[]
            requested=0
            for i in range(min(count,32)):
                rc=wlan.WlanScan(handle,ctypes.byref(items[i].InterfaceGuid),None,None,None)
                if rc == 0:
                    requested+=1
                else:
                    errors.append(str(rc))
            if requested:
                return True, ''
            reason=', '.join(errors)
            return False, ('Δεν ήταν δυνατή νέα σάρωση Wi-Fi'
                           + (f' (σφάλματα Windows: {reason})' if reason else '')
                           + '. Έλεγξε Wi-Fi/Location permissions.')
        finally:
            if ptr.value:
                wlan.WlanFreeMemory(ptr)
            wlan.WlanCloseHandle(handle,None)
    except (OSError,AttributeError,ValueError) as exc:
        return False, f'Αποτυχία πραγματικής σάρωσης WLAN: {exc}'


def _parse_real_bssid_ssids(netsh_output):
    """Return only SSIDs with an actual BSSID reported in Windows scan.

    Rejects profile lines, SSID-only sections, hidden SSIDs and fake defaults.
    SSID and BSSID field names are stable even in localized netsh output.
    """
    names=[]
    current=None
    has_bssid=False
    def flush():
        if current and has_bssid and current not in names:
            names.append(current)
    for line in netsh_output.splitlines():
        found=re.match(r'^\s*SSID\s+\d+\s*:\s*(.*?)\s*$',line,re.I)
        if found:
            flush()
            current=found.group(1).strip()
            has_bssid=False
        elif current and re.match(r'^\s*BSSID\s+\d+\s*:\s*'
                                  r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}\s*$',line,re.I):
            has_bssid=True
    flush()
    return names


def scan_wifi_networks():
    """Return (current radio scan SSIDs, diagnostics) without injecting SYNC-LAB.

    The scan is proof only that Windows *reported* an AP; full proof is the
    subsequent association to SYNC-LAB, 192.168.4.x IP and firmware ACK.
    """
    success,problem=_request_fresh_wlan_scan()
    if not success:
        return [], problem
    time.sleep(2.0)  # WlanScan is asynchronous. Let the radio scan update.
    try:
        result=_run_netsh('show','networks','mode=bssid')
    except (OSError,subprocess.TimeoutExpired) as exc:
        return [], f'Αποτυχία ανάγνωσης διαθέσιμων δικτύων: {exc}'
    if result.returncode:
        return [], f'Η σάρωση Windows απέτυχε: {result.stdout[-200:].strip()}'
    return _parse_real_bssid_ssids(result.stdout), ''


def available_ssids():
    # Backward-compatible API, but never returns the preselected SSID by default.
    names,_=scan_wifi_networks()
    return names


def saved_sync_profile():
    try:
        result = _run_netsh('show','profiles')
        # The profile name is after a colon, regardless of Greek/English labels.
        return any(line.split(':',1)[-1].strip()==SSID for line in result.stdout.splitlines() if ':' in line)
    except (OSError,subprocess.TimeoutExpired):
        return False


def current_wifi_ssids():
    """Report actual associated WLAN SSIDs, not just available networks."""
    if os.name != 'nt':
        return []
    try:
        result = _run_netsh('show', 'interfaces', timeout=7)
        # netsh labels the actual network 'SSID :', not 'SSID 1 :'.
        return [v.strip() for v in re.findall(
            r'^\s*SSID\s*:\s*(.*?)\s*$', result.stdout, re.M | re.I) if v.strip()]
    except (OSError, subprocess.TimeoutExpired):
        return []


def wifi_local_route_ip(host=DEVICE_IP):
    """Which LOCAL IPv4 address Windows would use for a packet to ESP32?"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((host, HELLO_PORT))  # UDP connect selects route; sends no data.
        return sock.getsockname()[0]
    except OSError:
        return ''
    finally:
        sock.close()


def wifi_connection_diagnostic():
    """Short, safe, non-mutating diagnostic; never returns any credentials."""
    source = wifi_local_route_ip()
    if os.name == 'nt':
        ssids = current_wifi_ssids()
        wlan = ', '.join(ssids) if ssids else '(δεν επιβεβαιώθηκε)'
        return f'Συνδεδεμένο Wi-Fi: {wlan}; Τοπική IP προς ESP32: {source or "καμία"}'
    return f'Τοπική IP προς ESP32: {source or "καμία"}'


def _wifi_correct_address(value):
    try:
        octets = [int(part) for part in value.split('.')]
        return (len(octets) == 4 and octets[:3] == [192, 168, 4]
                and 2 <= octets[3] <= 254)
    except (TypeError, ValueError):
        return False


def wait_for_sync_association(timeout=30.0, progress=None):
    """netsh connect is asynchronous: don't open the UDP receiver before DHCP.

    Return the local IP of the selected WLAN interface. On Windows, require
    BOTH association to SSID SYNC-LAB and the expected 192.168.4.x route.
    """
    if os.name != 'nt':
        return wifi_local_route_ip()
    deadline = time.monotonic() + timeout
    last_ssids = []
    last_ip = ''
    while time.monotonic() < deadline:
        last_ssids = current_wifi_ssids()
        last_ip = wifi_local_route_ip()
        if SSID in last_ssids and _wifi_correct_address(last_ip):
            return last_ip
        if progress:
            try:
                progress('Αναμονή σύνδεσης SYNC-LAB και DHCP... '
                         f'(Wi-Fi: {", ".join(last_ssids) or "—"}; IP: {last_ip or "—"})')
            except Exception:
                pass
        time.sleep(1.0)
    raise ConnectionError(
        'Τα Windows δέχτηκαν το αίτημα σύνδεσης αλλά ΔΕΝ συνδέθηκαν '
        'πραγματικά στο SYNC-LAB με IP 192.168.4.x.\n'
        f'Wi-Fi τώρα: {", ".join(last_ssids) or "μη επιβεβαιωμένο"}\n'
        f'Τοπική IP προς ESP32: {last_ip or "—"}\n'
        'Έλεγξε ότι το ESP32 εκπέμπει SYNC-LAB, ότι φορτώθηκε το Wi-Fi firmware, '
        'ότι ο κωδικός είναι σωστός και ότι τα Windows δεν επέστρεψαν '
        'αυτόματα σε άλλο Wi-Fi με Internet.')


def connect_windows_wifi(ssid, password, reuse_profile=False):
    """Connect via Windows WLAN; Windows manages persistent credentials.

    If the user enters a new passphrase, a temporary profile XML containing
    it is created with restrictive permissions and erased immediately.
    No password is saved in the application, reports or firmware diagnostics.
    """
    if os.name != 'nt':
        raise OSError('Η αυτόματη σύνδεση Wi-Fi γίνεται μόνο σε Windows.')
    if ssid != SSID:
        raise ValueError('Η παρούσα έκδοση υποστηρίζει αποκλειστικά το SSID SYNC-LAB.')
    if not reuse_profile:
        if len(password) < 8 or len(password) > 63:
            raise ValueError('Ο κωδικός Wi-Fi WPA2 απαιτεί 8–63 χαρακτήρες.')
        xml = f'''<?xml version="1.0" encoding="utf-8"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{xml_escape(ssid)}</name><SSIDConfig><SSID><name>{xml_escape(ssid)}</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType><connectionMode>manual</connectionMode>
  <MSM><security><authEncryption><authentication>WPA2PSK</authentication>
  <encryption>AES</encryption><useOneX>false</useOneX></authEncryption>
  <sharedKey><keyType>passPhrase</keyType><protected>false</protected>
  <keyMaterial>{xml_escape(password)}</keyMaterial></sharedKey></security></MSM>
</WLANProfile>'''
        name = None
        try:
            with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',suffix='.xml',delete=False) as f:
                name=f.name
                f.write(xml)
            result=_run_netsh('add','profile',f'filename={name}','user=current')
            if result.returncode:
                raise RuntimeError('Τα Windows δεν δέχτηκαν το προφίλ Wi-Fi: '+result.stdout[-250:])
        finally:
            if name:
                try: Path(name).unlink(missing_ok=True)
                except OSError: pass
    result=_run_netsh('connect',f'name={ssid}',f'ssid={ssid}')
    if result.returncode:
        raise RuntimeError('Αποτυχία σύνδεσης στο SSID SYNC-LAB: '+result.stdout[-250:])
    # Only netsh accepting the command is NOT proof that Wi-Fi has joined.
    # An AP without Internet can be rejected/abandoned by Windows.
    return wait_for_sync_association()


# TCP-only synthetic LAB receiver, isolated from the legacy USB/LAN paths.
from aircat_tcp_lab import WifiReceiver, CSV_EXTRA
from AIRCAT500_OfflineAudit_v5 import analyze_file as analyze_lab_file


def create_wifi_source_dialog(parent, on_confirm):
    """Show genuinely reported SSIDs; do not fabricate SYNC-LAB as a menu item.

    Scanning and WLAN joining happen on worker threads; Tk is touched only
    by the UI thread. Confirm is disabled until a real SSID is selected.
    """
    win=tk.Toplevel(parent)
    win.title('SYNC2WIFI — Σύνδεση Wi-Fi')
    win.transient(parent)
    win.configure(bg='#ededed')
    win.geometry('510x370')
    frm=ttk.Frame(win,padding=16)
    frm.pack(fill='both',expand=True)
    ttk.Label(frm,text='Διαθέσιμα Wi-Fi δίκτυα',font=('Segoe UI',12,'bold')).pack(anchor='w',pady=(0,7))
    pick=tk.StringVar(value='')  # no imaginary pre-selected SSID
    networks=ttk.Combobox(frm,textvariable=pick,values=[],state='disabled')
    networks.pack(fill='x',pady=(0,6))
    status=tk.StringVar(value='Πραγματική σάρωση Wi-Fi σε εξέλιξη...')
    ttk.Label(frm,textvariable=status,wraplength=465).pack(anchor='w')
    has_profile=saved_sync_profile()  # ONLY a credential setting, NOT availability
    reuse=tk.BooleanVar(value=has_profile)
    row=ttk.Frame(frm);row.pack(fill='x',pady=(10,3))
    ttk.Label(row,text='Κωδικός Wi-Fi:').pack(side='left')
    password=tk.StringVar(value='')
    passwd_entry=ttk.Entry(row,textvariable=password,show='*',width=22)
    passwd_entry.pack(side='left',padx=10)
    ttk.Checkbutton(frm,text='Χρήση αποθηκευμένου κωδικού Windows',variable=reuse).pack(anchor='w')
    def reuse_change(*_):
        if reuse.get() and has_profile:
            password.set('********')
            passwd_entry.configure(state='disabled')
        else:
            password.set('')
            passwd_entry.configure(state='normal')
    reuse.trace_add('write',reuse_change)
    reuse_change()
    pinrow=ttk.Frame(frm);pinrow.pack(fill='x',pady=(10,8))
    ttk.Label(pinrow,text='PIN συσκευής:').pack(side='left')
    pin_var=tk.StringVar(value='1234')
    ttk.Entry(pinrow,textvariable=pin_var,show='*',width=8).pack(side='left',padx=9)
    buttons=ttk.Frame(frm);buttons.pack(fill='x',pady=(8,0))
    ttk.Button(buttons,text='Άκυρο',command=win.destroy).pack(side='right')
    confirm=ttk.Button(buttons,text='Confirm / Σύνδεση',state='disabled')
    confirm.pack(side='right',padx=8)
    visible=set()
    scanning=[False]
    latest=[0]

    def update_confirm(*_):
        confirm.configure(state='normal' if not scanning[0] and
                          pick.get() == SSID and SSID in visible else 'disabled')
    pick.trace_add('write',update_confirm)

    def discover():
        if scanning[0]:
            return
        scanning[0]=True
        latest[0]+=1
        generation=latest[0]
        pick.set('')
        visible.clear()
        networks.configure(values=[],state='disabled')
        confirm.configure(state='disabled')
        status.set('Νέα σάρωση του Wi-Fi προσαρμογέα...')
        refresh.configure(state='disabled')
        scan_result=queue.Queue(maxsize=1)
        def job():
            try:
                scan_result.put(scan_wifi_networks())
            except Exception as exc:
                scan_result.put(([],f'Σφάλμα σάρωσης: {exc}'))
        def poll_result():
            if not win.winfo_exists() or generation!=latest[0]:
                return
            try:
                names,error=scan_result.get_nowait()
            except queue.Empty:
                win.after(80,poll_result)
                return
            scanning[0]=False
            refresh.configure(state='normal')
            if error:
                networks.configure(values=[],state='disabled')
                status.set('Δεν επαληθεύτηκε σάρωση: '+error)
                return
            visible.update(names)
            networks.configure(values=names,state='readonly' if names else 'disabled')
            if SSID in visible:
                pick.set(SSID)
                status.set('Τα Windows αναφέρουν το SYNC-LAB στη σάρωση. '
                           'Η παρουσία του επιβεβαιώνεται κατά τη σύνδεση.')
            elif names:
                status.set('Το SYNC-LAB ΔΕΝ εντοπίστηκε. Διαθέσιμα: '
                           + ', '.join(names[:6]) + '. Πάτησε Ανανέωση.')
            else:
                status.set('Δεν εντοπίστηκε κανένα Wi-Fi με ενεργό BSSID. '
                           'Έλεγξε ότι το AP είναι ενεργό και πάτησε Ανανέωση.')
            update_confirm()
        threading.Thread(target=job,daemon=True).start()
        win.after(80,poll_result)

    def begin():
        if scanning[0] or pick.get()!=SSID or SSID not in visible:
            messagebox.showerror('SYNC2WIFI',
                 'Το SSID SYNC-LAB δεν εντοπίστηκε σε διαθέσιμα Wi-Fi. Πάτησε Ανανέωση SSID.',
                 parent=win)
            return
        pin=pin_var.get()
        if not re.fullmatch(r'\d{4}',pin):
            messagebox.showerror('PIN','Απαιτείται τετραψήφιο PIN.',parent=win)
            return
        keep=reuse.get() and has_profile
        pw='' if keep else password.get()
        already_joined=(SSID in current_wifi_ssids() and
                        _wifi_correct_address(wifi_local_route_ip()))
        if not already_joined and not keep and not 8<=len(pw)<=63:
            messagebox.showerror('Wi-Fi','Ο κωδικός χρειάζεται 8–63 χαρακτήρες.',parent=win)
            return
        confirm.configure(state='disabled')
        refresh.configure(state='disabled')
        status.set('Σύνδεση στο SYNC-LAB / επαλήθευση IP 192.168.4.x...')
        join_result=queue.Queue(maxsize=1)
        def work():
            try:
                if not already_joined:
                    connect_windows_wifi(SSID,pw,keep)
                else:
                    wait_for_sync_association(timeout=8)
                result=None
            except Exception as exc:
                result=str(exc)
            join_result.put(result)
        def poll_join():
            if not win.winfo_exists():
                return
            try:
                result=join_result.get_nowait()
            except queue.Empty:
                win.after(80,poll_join)
                return
            if result:
                status.set('Η σύνδεση δεν επαληθεύτηκε.')
                refresh.configure(state='normal')
                update_confirm()
                messagebox.showerror('SYNC2WIFI',result,parent=win)
            else:
                win.destroy()
                on_confirm(pin)
        threading.Thread(target=work,daemon=True).start()
        win.after(80,poll_join)
    confirm.configure(command=begin)
    refresh=ttk.Button(frm,text='Ανανέωση SSID',command=discover)
    refresh.pack(anchor='w',pady=(8,0))
    win.after(50,discover)
    win.lift();win.focus_force()
    return win


# Shared monitor tiles. Diagnostic counters are intentionally SEPARATE from
# positive metrics. An error counter of zero is good; red headings identify
# exactly which measurements represent faults, not a failure state.
MONITOR_GOOD = [
    ('bytes', 'Bytes'), ('rate', 'Bytes / sec'),
    ('clock_hz', 'CLOCK GPIO17 (Hz)'), ('clock_total', 'CLOCK edges'),
    ('sync', 'SYNC x3 + SOH'), ('north', 'North headers'),
    ('sector', 'Sector headers'), ('extension', 'Extension headers'),
    ('valid_frames', 'VALID FRAMES'), ('valid_pct', 'CRC VALID %'),
    ('rotations', 'Ολοκληρωμένες περιστροφές'),
    ('perfect_rotations', 'Πλήρεις περιστροφές 32/32'),
    ('unique', 'Sectors τρέχ. περιστροφής'),
    ('frames', 'Frames με CRC πεδίο'),
]
MONITOR_PROBLEMS = [
    ('crc_errors', 'CRC ERRORS'), ('framing_errors', 'FRAMING ERRORS'),
    ('lost_sectors', 'LOST SECTORS (clean)'),
    ('uncertain_sectors', 'SECTOR GAPS (CRC suspect)'),
    ('uncertain_rotations', 'CRC-uncertain rotations'),
    ('duplicates', 'Διπλοί sectors'), ('order_errors', 'Σφάλματα σειράς'),
    ('overflow', 'Device overflow (bytes)'),
]
MONITOR_WIFI_GOOD = [
    ('udp_rx', 'TCP records'), ('udp_duplicates', 'TCP duplicates'),
    ('fw_ovf_session', 'FW overflow since connect'),
]
MONITOR_WIFI_PROBLEMS = [
    ('udp_lost', 'TCP gaps'), ('udp_invalid', 'TCP invalid'),
    ('udp_crc32', 'TCP CRC32 BAD'), ('overflow', 'FW OVERFLOW TOTAL'),
    ('fw_ovf_session', 'FW OVERFLOW SINCE CONNECT'),
]


def build_monitor_metric_sections(parent, vars_map, *, is_wifi=False):
    """Same four-column grouped stats layout in both Serial Monitoring modes."""
    good = [(k, lab) for k, lab in MONITOR_GOOD if k in vars_map]
    if is_wifi:
        good += [(k, lab) for k, lab in MONITOR_WIFI_GOOD
                 if k in vars_map and k != 'fw_ovf_session']
    bad = [(k, lab) for k, lab in MONITOR_PROBLEMS if k in vars_map]
    if is_wifi:
        bad = [(k, lab) for k, lab in bad if k != 'overflow']
        bad += [(k, lab) for k, lab in MONITOR_WIFI_PROBLEMS if k in vars_map]
    def section(title, defs, error):
        outer = ttk.LabelFrame(parent, text=title, padding=(4, 5))
        outer.pack(fill='x', pady=(0, 8))
        for j,(key,description) in enumerate(defs):
            tile=tk.Frame(outer,bg='#f8f8f8',highlightbackground='#bcbcbc',highlightthickness=1)
            tile.grid(row=j//4,column=j%4,padx=3,pady=3,sticky='nsew')
            tk.Label(tile,text=description,fg='#b4232d' if error else '#333333',
                     bg='#f8f8f8',font=('Segoe UI',9,'bold' if error else 'normal'),
                     anchor='w').pack(fill='x',padx=10,pady=(6,0))
            tk.Label(tile,textvariable=vars_map[key],fg='#151515',bg='#f8f8f8',
                     font=('Segoe UI',15,'bold'),anchor='w').pack(fill='x',padx=10,pady=(0,6))
        for col in range(4):outer.columnconfigure(col,weight=1,uniform='monitor_tiles')
        return outer
    ok_section=section('ΚΑΝΟΝΙΚΗ ΛΕΙΤΟΥΡΓΙΑ / ΜΕΤΡΗΣΕΙΣ',good,False)
    error_section=section('ΣΦΑΛΜΑΤΑ / ΠΙΘΑΝΕΣ ΑΠΩΛΕΙΕΣ',bad,True)
    return ok_section,error_section


class WifiLineMonitor(tk.Toplevel):
    """WiFi raw-serial monitor: CRC, HEX, sector counters, save byte-perfect .bin."""
    def __init__(self,parent,observer_class,pin='1234',on_close=None):
        super().__init__(parent)
        self.title(f'SYNC2WIFI v{APP_VERSION} — Radar Serial Line Monitoring')
        self.geometry('1220x1050')
        self.minsize(990,760)
        self._on_close=on_close
        self.pin=pin
        self.observer=observer_class()
        self._lab_raw_halted=False
        self.stop_flag=threading.Event()
        self.stream_queue=queue.Queue(maxsize=250)
        self.rx=None
        self.save_file=None
        self.save_path=None
        self.save_lock=threading.Lock()
        self.record_start_mono=None
        self.record_bytes=0
        self.record_started_at=None
        self.drop_display=0
        self.connection_error=False
        self.count_bytes=0
        self._build()
        self.protocol('WM_DELETE_WINDOW',self.on_close)
        self.thread=threading.Thread(target=self._read,daemon=True)
        self.thread.start()
        self.after(200,self._poll)

    def _build(self):
        self.configure(bg='#ededed')
        body=ttk.Frame(self,padding=12)
        body.pack(fill='both',expand=True)
        ttk.Label(body,text='AIRCAT500  /  SYNC2WIFI Live Monitor',
                  font=('Segoe UI',19,'bold')).pack(anchor='w')
        ttk.Label(body,text='SYNC-LAB · TCP · synthetic data · CRC-16/KERMIT · CRC32').pack(anchor='w',pady=(2,10))
        controls=ttk.Frame(body)
        controls.pack(fill='x',pady=(0,7))
        ttk.Button(controls,text='Έλεγχος Wi-Fi',command=self.show_wifi_diagnostic).pack(side='left',padx=(0,9))
        ttk.Button(controls,text='Load BIN File',command=self.analyze_bin).pack(side='left',padx=(0,9))
        ttk.Button(controls,text='STOP',command=self.on_close).pack(side='left',padx=(0,9))
        self.status=tk.StringVar(value='Σύνδεση TCP LAB...')
        ttk.Label(body,textvariable=self.status).pack(anchor='w',pady=(0,7))
        recbar=ttk.Frame(body)
        recbar.pack(fill='x',pady=(0,10))
        self.record_button=tk.Button(recbar,text='Start Recording',command=self.choose_save,
            font=('Segoe UI',10,'bold'),fg='#171717',bg='#e0e0e0',
            activebackground='#cccccc',relief='raised',bd=1,padx=10,pady=5)
        self.record_button.pack(side='left')
        ttk.Label(recbar,text='Επιλογή φακέλου μετά το Start Recording · πλήρες RAW .bin και .meta.json').pack(side='left',padx=12)

        self.counters={k:tk.StringVar(value='0') for k in dict(MONITOR_GOOD + MONITOR_PROBLEMS + MONITOR_WIFI_GOOD + MONITOR_WIFI_PROBLEMS)}
        for k in ('clock_total','valid_pct','unique'):
            self.counters[k].set('—')
        build_monitor_metric_sections(body,self.counters,is_wifi=True)

        framebox=ttk.LabelFrame(body,text='AIRCAT500 — επαλήθευση CRC ανά frame · DLE/STX ... DLE/ETX + CRC1/CRC2')
        framebox.pack(fill='both',expand=True,pady=(2,6))
        cols=('time','type','sector','length','crc','rx_calc','bytes')
        self.tree=ttk.Treeview(framebox,columns=cols,show='headings',height=7)
        for key,name,width in zip(cols,
           ('Ώρα','Τύπος','Sector','Bytes','CRC STATUS','RX / CALC','Πρώτα bytes (HEX)'),
           (85,105,65,65,100,115,560)):
            self.tree.heading(key,text=name)
            self.tree.column(key,width=width,stretch=(key=='bytes'))
        self.tree.tag_configure('crc_bad',foreground='#ad2424')
        self.tree.tag_configure('crc_ok',foreground='#145d3c')
        self.tree.tag_configure('framing_bad',foreground='#9b6b0b')
        self.tree.pack(side='left',fill='both',expand=True)
        ybar=ttk.Scrollbar(framebox,orient='vertical',command=self.tree.yview)
        self.tree.configure(yscrollcommand=ybar.set)
        ybar.pack(side='right',fill='y')
        # No Live HEX widget: both sources use only this frame table.
        ttk.Label(body,text='* LAB: gaps invalidate incomplete rotations. RAW BIN stops at first gap.',
                  foreground='#393939').pack(anchor='w')

    def show_wifi_diagnostic(self):
        rx=self.rx
        text='Synthetic TCP LAB only. Source timestamps, separate continuity gaps.'
        if rx:
            text+=f'\nTCP records: {rx.udp_received}; TCP gaps: {rx.udp_lost}'
            text+=f'\nTransport CRC32: {rx.udp_bad_crc32}; last gap: {rx.gap_reason or "—"}'
        messagebox.showinfo('TCP LAB',text,parent=self)

    def analyze_bin(self):
        """Offline CRC report for saved raw SYNC2WIFI byte streams."""
        filename=filedialog.askopenfilename(parent=self,title='Load BIN File — SYNC2WIFI',
                                            filetypes=[('RAW AIRCAT BIN','*.bin'),('All files','*.*')])
        if not filename:return
        self.status.set('Offline ανάλυση αρχείου '+Path(filename).name)
        def work():
            try:
                obs=type(self.observer)()
                with open(filename,'rb') as f:
                    while True:
                        data=f.read(65536)
                        if not data:break
                        obs.feed(data)
                result=obs.counters()
                text=('Αρχείο: '+Path(filename).name+'\n'
                      +'Bytes: '+str(result['total'])+'\n'
                      +'VALID FRAMES: '+str(result['valid_frames'])+'\n'
                      +'CRC ERRORS: '+str(result['crc_errors'])+'\n'
                      +'FRAMING ERRORS: '+str(result['framing_errors'])+'\n'
                      +'LOST SECTORS: '+str(result['lost_sectors'])+'\n'
                      +'UNCERTAIN: '+str(result['uncertain_sectors'])+'\n'
                      +'Completed NORTH cycles: '+str(result['completed_rotations']))
            except Exception as e:
                text='Σφάλμα ανάγνωσης BIN: '+str(e)
            try:
                self.after(0,lambda:messagebox.showinfo('AIRCAT RAW BIN',text,parent=self)
                           if self.winfo_exists() else None)
            except tk.TclError:pass
        threading.Thread(target=work,daemon=True).start()

    def choose_save(self):
        """Start/stop a raw capture without interrupting the Wi-Fi receiver."""
        if self.record_start_mono is not None:
            self._end_recording()
            return
        path=filedialog.asksaveasfilename(
            parent=self,title='Start Recording — SYNC2WIFI',
            defaultextension='.bin',
            initialfile='AIRCAT500_SYNC2WIFI_'+_wifi_datetime.datetime.now().strftime('%Y%m%d_%H%M%S')+'.bin',
            filetypes=[('RAW AIRCAT capture','*.bin'),('All files','*.*')])
        if not path:return
        try:
            handle=open(path,'wb',buffering=65536)
        except OSError as exc:
            messagebox.showerror('Recording',f'Αδυναμία δημιουργίας αρχείου:\n{exc}',parent=self)
            return
        with self.save_lock:
            self._lab_raw_halted=False
            self.save_file=handle
            self.save_path=path
            self.record_bytes=0
            self.record_started_at=_wifi_datetime.datetime.now().astimezone().isoformat(timespec='seconds')
            self.record_start_mono=time.monotonic()
        self.status.set('Recording RAW: '+path)
        self._tick_record_button()

    def _tick_record_button(self):
        started=self.record_start_mono
        if started is None:
            self.record_button.configure(text='Start Recording',fg='#171717',bg='#e0e0e0',
                                         activeforeground='#171717',activebackground='#cccccc')
        else:
            elapsed=int(max(0,time.monotonic()-started))
            hrs,rem=divmod(elapsed,3600)
            mins,secs=divmod(rem,60)
            self.record_button.configure(text=f'Recording {hrs:02}:{mins:02}:{secs:02}',
                                         fg='#cc1515',bg='#ffe4e4',
                                         activeforeground='#b00000',activebackground='#ffd5d5')

    def _end_recording(self):
        with self.save_lock:
            handle=self.save_file
            if handle is None:
                return
            self.save_file=None
            path=self.save_path
            count=self.record_bytes
            started=self.record_started_at
            self.record_start_mono=None
            self.save_path=None
            try:
                handle.flush()
                handle.close()
            except OSError as exc:
                self.status.set(f'Πρόβλημα αποθήκευσης: {exc}')
        rx=self.rx
        meta={
            'capture_device':'SYNC2WIFI-LAB','capture_connection':'LAB TCP v5',
            'raw_stopped_on_gap':self._lab_raw_halted,
            'ssid':SSID,'data_ip':DEVICE_IP,
            'start_time':started,
            'end_time':_wifi_datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
            'bytes_recorded':count,'udp_received':rx.udp_received if rx else None,
            'udp_lost':rx.udp_lost if rx else None,
            'udp_invalid':rx.udp_invalid if rx else None,
            'udp_crc32_fail':rx.udp_bad_crc32 if rx else None,
            'udp_duplicates':rx.udp_duplicates if rx else None,
            'firmware_overflow':rx.firmware_overflow if rx else None,
            'firmware_overflow_at_connect':rx.firmware_overflow_at_connect if rx else None,
            'firmware_overflow_since_connect':rx.firmware_overflow_since_connect if rx else None,
            'AIRCAT':self.observer.counters()}
        try:
            Path(path+'.meta.json').write_text(json.dumps(meta,ensure_ascii=False,indent=2),encoding='utf-8')
        except (OSError,TypeError,ValueError) as exc:
            self.status.set(f'Αποθήκευση BIN OK, metadata error: {exc}')
        else:
            self.status.set(f'RAW BIN αποθηκεύτηκε: {Path(path).name} ({count:,} bytes)')
        self._tick_record_button()

    def _read(self):
        receiver=WifiReceiver(pin=self.pin)
        self.rx=receiver
        try:
            receiver.open()
            while not self.stop_flag.is_set():
                data=receiver.read()
                if data is None:continue
                if self.stop_flag.is_set():break
                if not data:
                    self.observer.lab_gap()
                    events=[]
                    valid=False
                    reason=receiver.gap_reason
                else:
                    events,valid=self.observer.lab_feed(data)
                    reason='LAB BSC integrity or rotation boundary uncertain'
                    self.count_bytes+=len(data)
                with self.save_lock:
                    if not valid:
                        if self.save_file is not None:
                            self._lab_raw_halted=True
                    elif self.save_file is not None and not self._lab_raw_halted:
                        self.save_file.write(data)
                        self.record_bytes+=len(data)
                if not valid:
                    try:self.stream_queue.put_nowait(('LAB_GAP',reason))
                    except queue.Full:self.drop_display+=1
                if events:
                    try:self.stream_queue.put_nowait((b'',events))
                    except queue.Full:self.drop_display+=1
        except Exception as exc:
            self.stream_queue.put(('ERROR',str(exc)))
        finally:
            receiver.close()
            try:self.after(0,self._end_recording)
            except (tk.TclError,RuntimeError):pass

    def _poll(self):
        if not self.winfo_exists():return
        if self._lab_raw_halted and self.save_file is not None:
            self._end_recording()  # never concatenate across a LAB gap in a RAW BIN
        for _ in range(100):
            try:data,events=self.stream_queue.get_nowait()
            except queue.Empty:break
            if data=='LAB_GAP':
                self.status.set('LAB continuity gap: '+events)
                continue
            if data=='ERROR':
                self.connection_error=True
                self.status.set('ERROR: '+events)
                continue
            for ev in events:
                tag=('crc_ok' if ev['result']=='CRC OK' else
                     'crc_bad' if ev['result']=='CRC FAIL' else 'framing_bad')
                self.tree.insert('','end',values=(
                    _wifi_datetime.datetime.now().strftime('%H:%M:%S'),ev['type'],
                    ev['sector'],ev.get('length',''),ev['result'],
                    f"{ev.get('rx_crc','')}/{ev.get('calc_crc','')}",ev['head']),tags=(tag,))
            if len(self.tree.get_children())>400:
                self.tree.delete(*self.tree.get_children()[:len(self.tree.get_children())-300])
            if events:self.tree.yview_moveto(1.0)
        c=self.observer.counters()
        r=self.rx
        values={
          'bytes':f'{self.count_bytes:,}',
          'sync':f"{c['sync']:,}",
          'north':f"{c['headers']['NORTH']:,}",
          'sector':f"{c['headers']['SECTOR']:,}",
          'extension':f"{c['headers']['EXTENSION']:,}",
          'frames':f"{c['framed']:,}",
          'valid_frames':f"{c['valid_frames']:,}",
          'framing_errors':f"{c['framing_errors']:,}",
          'crc_errors':f"{c['crc_errors']:,}",
          'valid_pct':f"{c['crc_pct']:.1f}%" if c['crc_pct'] is not None else '—',
          'rotations':f"{c['completed_rotations']:,}",
          'perfect_rotations':f"{c['perfect_rotations']:,}",
          'unique':f"{c['current_sector_unique']} / 32" if c['current_sector_unique'] is not None else '—',
          'lost_sectors':f"{c['lost_sectors']:,}",
          'uncertain_sectors':f"{c['uncertain_sectors']:,}",
          'uncertain_rotations':f"{c['uncertain_rotations']:,}",
          'duplicates':f"{c['duplicate_sectors']:,}",
          'order_errors':f"{c['order_errors']:,}",
        }
        now=time.monotonic()
        if not hasattr(self,'last_rate_clock'):
            self.last_rate_clock=now
            self.last_rate_bytes=self.count_bytes
        elapsed=now-self.last_rate_clock
        if elapsed>=0.5:
            values['rate']=f'{(self.count_bytes-self.last_rate_bytes)/elapsed:,.0f}'
            self.last_rate_clock=now
            self.last_rate_bytes=self.count_bytes
        if r:
            values.update({
              'clock_hz':f'{r.clock_hz:,}',
              'clock_total':'—', # UDP envelope supplies Hz, not cumulative edges.
              'udp_rx':f'{r.udp_received:,}',
              'udp_lost':f'{r.udp_lost:,}',
              'udp_invalid':f'{r.udp_invalid:,}',
              'udp_crc32':f'{r.udp_bad_crc32:,}',
              'udp_duplicates':f'{r.udp_duplicates:,}',
              'overflow':f'{r.firmware_overflow:,}',
              'fw_ovf_session':f'+{r.firmware_overflow_since_connect:,}',
            })
            if not self.connection_error:
                if r.ack and r.udp_received:self.status.set('TCP LAB — synthetic records')
                elif r.ack:self.status.set('TCP LAB — waiting for synthetic records')
                else:self.status.set('TCP LAB — connecting/reconnecting...')
        for k,v in values.items():
            if k in self.counters:self.counters[k].set(v)
        self._tick_record_button()
        self.after(200,self._poll)

    def on_close(self):
        self.stop_flag.set()
        if self.rx:self.rx.close()
        if self.thread.is_alive():
            self.thread.join(timeout=1.5)
        self._end_recording()
        if callable(self._on_close):self._on_close()
        self.destroy()
# ===== END EMBEDDED SYNC2WIFI v20 MODULE =====

APP_TITLE = "AIRCAT500 Analyzer"
APP_VERSION = "6.0 LAB"
USB_FW_EXPECTED_VERSION = "40.0"
APP_SIZE = "1240x660"

# These columns are written into every LivePlay CSV row.  Do not insert a freeform
# metadata line before the header: legacy CSV replay needs a standard first row.
LIVE_RECORD_CSV_FIELDS = [
    'frame_no', 'time_epoch', 'capture_time', 'udp_payload_hex',
    'length_bytes', 'aircat_type', 'aircat_type_name', 'aircat_addr',
    'sector', 'is_north', 'is_sector',
    'capture_device', 'capture_connection', 'capture_port',
    'usb_crc_fail_total', 'usb_framing_error_total',
]


def save_capture_metadata(path, metadata):
    """Write a small sidecar for RAW .bin without changing its actual bytes."""
    sidecar = Path(str(path) + '.meta.json')
    tmp = Path(str(sidecar) + '.tmp')
    with tmp.open('w', encoding='utf-8') as fp:
        json.dump(metadata, fp, ensure_ascii=False, indent=2)
        fp.write('\n')
    tmp.replace(sidecar)
    return sidecar

# License / expiry control.
# Για δοκιμή της λήξης χωρίς να αλλάξεις την ημερομηνία του υπολογιστή,
# άλλαξε προσωρινά το FORCE_LICENSE_EXPIRED_FOR_TEST σε True.
LICENSE_EXPIRY_DATE = date(2027, 3, 4)
LICENSE_WARNING_DAYS = 0  # no pre-expiry warning
FORCE_LICENSE_EXPIRED_FOR_TEST = False

AIRCAT_TYPES = {
    0x0C: "Radar Sector",
    0x0D: "Radar Extension",
    0x19: "North Signal",
    0x1C: "Processor State",
    0x2A: "Weather",
}

HEX_RE = re.compile(r'(?i)\b[0-9a-f]{2}\b')


def safe_mean(values):
    return (sum(values) / len(values)) if values else None


def safe_min(values):
    return min(values) if values else None


def safe_max(values):
    return max(values) if values else None


def safe_median(values):
    return statistics.median(values) if values else None


def fmt_float(value, digits=1, fallback="n/a"):
    if value is None:
        return fallback
    return f"{value:.{digits}f}"

def format_capture_time(ts):
    if ts is None:
        return "(χωρίς timestamp)"
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def format_duration_greek(start_ts, end_ts):
    if start_ts is None or end_ts is None or end_ts < start_ts:
        return "n/a"
    total_seconds = int(round(end_ts - start_ts))
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    return f"{hours} ώρες {minutes} λεπτά και {seconds} δευτερόλεπτα"


def extract_hex_bytes_from_text(text: str):
    if not text:
        return None

    pairs = HEX_RE.findall(text)
    if len(pairs) >= 4:
        try:
            return bytes(int(x, 16) for x in pairs)
        except Exception:
            pass

    compact = re.sub(r'[^0-9A-Fa-f]', '', text)
    if len(compact) >= 8 and len(compact) % 2 == 0:
        try:
            return bytes.fromhex(compact)
        except Exception:
            pass

    return None


def classify_aircat_payload(payload: bytes):
    if not payload or len(payload) < 2:
        return None

    msg_type = payload[0]
    addr = payload[1]

    result = {
        "is_aircat_like": False,
        "type": msg_type,
        "type_name": AIRCAT_TYPES.get(msg_type, "Unknown"),
        "addr": addr,
        "sector": None,
        "is_sector": False,
        "is_north": False,
        "record_count_20b": None,
        "record_remainder": None,
    }

    if msg_type in AIRCAT_TYPES and addr == 0x40:
        result["is_aircat_like"] = True

    if len(payload) >= 4 and payload[0] == 0x0C and payload[1] == 0x40 and payload[2] == 0xFD:
        result["is_sector"] = True
        result["sector"] = payload[3]
        data_len = max(0, len(payload) - 4)
        result["record_count_20b"] = data_len // 20
        result["record_remainder"] = data_len % 20
        result["is_aircat_like"] = True

    if payload[0] == 0x19 and payload[1] == 0x40:
        result["is_north"] = True
        result["is_aircat_like"] = True

    return result



def is_aircat_like_payload(payload: bytes) -> bool:
    if not payload or len(payload) < 2:
        return False
    info = classify_aircat_payload(payload)
    if info and info.get("is_aircat_like"):
        return True
    return payload[1] == 0x40


def is_known_aircat_payload(payload: bytes) -> bool:
    if not payload or len(payload) < 2:
        return False
    return payload[0] in AIRCAT_TYPES and payload[1] == 0x40




def _protocol_issue_entry(rec, location: str, problem: str, raw_bytes: bytes = b''):
    payload = rec.get('payload', b'') or b''
    return {
        'frame_no': rec.get('frame_no'),
        'time': rec.get('timestamp'),
        'location': location,
        'problem': problem,
        'prefix': payload[:8].hex().upper(),
        'raw': (raw_bytes or b'').hex().upper(),
    }


def _append_malformed(rec, malformed, location: str, problem: str, raw_bytes: bytes = b''):
    malformed.append(_protocol_issue_entry(rec, location, problem, raw_bytes))


def _append_unmapped(rec, unmapped, location: str, problem: str, raw_bytes: bytes = b''):
    unmapped.append(_protocol_issue_entry(rec, location, problem, raw_bytes))


def _parse_embedded_aircat_stream(data: bytes, rec, malformed, unmapped, location_prefix: str):
    if data is None:
        _append_malformed(rec, malformed, location_prefix, "Κενό embedded payload")
        return

    pos = 0
    total_len = len(data)

    while pos < total_len:
        remaining = total_len - pos
        key = data[pos]

        if key in (0xFE, 0xFF):
            if remaining < 2:
                _append_malformed(
                    rec,
                    malformed,
                    f"{location_prefix} / offset {pos}",
                    f"Truncated embedded track message 0x{key:02X}: λείπει το byte count",
                    data[pos:total_len]
                )
                return

            byte_count = data[pos + 1]
            if byte_count < 2:
                _append_malformed(
                    rec,
                    malformed,
                    f"{location_prefix} / offset {pos}",
                    f"Μη έγκυρο byte count {byte_count} για embedded message 0x{key:02X}",
                    data[pos:min(total_len, pos + 4)]
                )
                return

            if byte_count > remaining:
                _append_malformed(
                    rec,
                    malformed,
                    f"{location_prefix} / offset {pos}",
                    f"Embedded message 0x{key:02X} με byte count {byte_count} αλλά απομένουν μόνο {remaining} bytes",
                    data[pos:total_len]
                )
                return

            pos += byte_count
            continue

        if key == 0xFB:
            if remaining < 3:
                _append_malformed(
                    rec,
                    malformed,
                    f"{location_prefix} / offset {pos}",
                    "Truncated FB track cancellation: απαιτούνται τουλάχιστον 3 bytes",
                    data[pos:total_len]
                )
                return

            # Observed on captures: FB xx xx 00. Treat trailing 00 as likely valid/alignment byte.
            if remaining >= 4 and data[pos + 3] == 0x00:
                pos += 4
            else:
                pos += 3
            continue

        if key in (0xFD, 0xFC):
            block_txt = f" 0x{data[pos + 1]:02X}" if remaining >= 2 else ""
            _append_malformed(
                rec,
                malformed,
                f"{location_prefix} / offset {pos}",
                f"Απρόσμενο nested end-of-block marker 0x{key:02X}{block_txt} μέσα σε embedded stream",
                data[pos:min(total_len, pos + 4)]
            )
            return

        # Strong recurring patterns in captures: 0xFA and 0x00 appear as regular 4-byte elements.
        if key in (0xFA, 0x00):
            raw = data[pos:min(total_len, pos + 4)]
            if remaining >= 4:
                _append_unmapped(
                    rec,
                    unmapped,
                    f"{location_prefix} / offset {pos}",
                    f"Μη χαρτογραφημένο embedded element 0x{key:02X} (πιθανό valid 4-byte record)",
                    raw
                )
                pos += 4
                continue
            else:
                _append_unmapped(
                    rec,
                    unmapped,
                    f"{location_prefix} / offset {pos}",
                    f"Μη χαρτογραφημένο embedded element 0x{key:02X} στο τέλος stream",
                    raw
                )
                return

        _append_unmapped(
            rec,
            unmapped,
            f"{location_prefix} / offset {pos}",
            f"Μη χαρτογραφημένο embedded message key 0x{key:02X}",
            data[pos:min(total_len, pos + 8)]
        )
        return


def analyze_protocol_issues(ordered_records):
    malformed = []
    unmapped = []

    for rec in ordered_records:
        payload = rec.get('payload', b'') or b''
        if len(payload) < 2:
            continue

        msg_type = payload[0]
        addr = payload[1]
        looks_aircat = (addr == 0x40) or (msg_type in AIRCAT_TYPES)

        if not looks_aircat:
            continue

        if msg_type in AIRCAT_TYPES and addr != 0x40:
            _append_malformed(
                rec,
                malformed,
                "Top-level packet",
                f"Γνωστό AIRCAT type 0x{msg_type:02X} με μη αναμενόμενο address 0x{addr:02X}",
                payload[:8]
            )
            continue

        if addr != 0x40:
            _append_unmapped(
                rec,
                unmapped,
                "Top-level packet",
                f"Μη χαρτογραφημένο top-level AIRCAT-like στοιχείο 0x{msg_type:02X} / addr 0x{addr:02X}",
                payload[:8]
            )
            continue

        if msg_type == 0x19:
            if len(payload) < 4:
                _append_malformed(rec, malformed, "North", "North packet μικρότερο από 4 bytes", payload)
                continue
            if payload[2] != 0xFD:
                _append_malformed(rec, malformed, "North", f"North packet χωρίς FD marker στο byte 3 (βρέθηκε 0x{payload[2]:02X})", payload[:8])
            if payload[3] != 0x00:
                _append_malformed(rec, malformed, "North", f"North packet με μη μηδενικό block number 0x{payload[3]:02X}", payload[:8])
            continue

        if msg_type == 0x0C:
            if len(payload) < 4:
                _append_malformed(rec, malformed, "Sector", "Sector packet μικρότερο από 4 bytes", payload)
                continue
            if payload[2] != 0xFD:
                _append_malformed(rec, malformed, "Sector", f"Sector packet χωρίς FD marker στο byte 3 (βρέθηκε 0x{payload[2]:02X})", payload[:8])
                continue
            sector_no = payload[3]
            if sector_no > 0x1F:
                _append_malformed(rec, malformed, "Sector", f"Μη έγκυρος sector number 0x{sector_no:02X}", payload[:8])
            _parse_embedded_aircat_stream(payload[4:], rec, malformed, unmapped, f"Sector {sector_no:02X}")
            continue

        if msg_type == 0x0D:
            if len(payload) <= 2:
                _append_malformed(rec, malformed, "Radar Extension", "Radar Extension χωρίς embedded payload", payload)
                continue
            _parse_embedded_aircat_stream(payload[2:], rec, malformed, unmapped, "Radar Extension")
            continue

        if msg_type == 0x2A:
            if len(payload) < 3:
                _append_malformed(rec, malformed, "Weather", "Weather packet πολύ μικρό για βασικό έλεγχο", payload)
            continue

        if msg_type == 0x1C:
            if len(payload) < 3:
                _append_malformed(rec, malformed, "Processor State", "Processor State packet πολύ μικρό για βασικό έλεγχο", payload)
            continue

        _append_unmapped(
            rec,
            unmapped,
            "Top-level packet",
            f"Μη χαρτογραφημένο AIRCAT type/identifier 0x{msg_type:02X} / addr 0x{addr:02X}",
            payload[:8]
        )

    return malformed, unmapped






def _aircat_ssr_service_flags(msg: bytes):
    """Decode SSR service-byte flags used by AIRCAT500.

    Byte 3 of an SSR FF track contains P/F emergency state and the IP/SPI bit.
    According to the AIRCAT500 layout, P=0 and F=1 indicate emergency, while
    IP=1 indicates SPI detected in the SSR reply.
    """
    flags = {
        'spi': False,
        'emergency': False,
        'service_byte': None,
        'ssr_tpr_number': None,
    }
    if not msg or len(msg) <= 2:
        return flags
    service = msg[2] & 0xFF
    flags['service_byte'] = service
    flags['ssr_tpr_number'] = 2 if (service & 0x02) else 1
    p_bit = bool(service & 0x80)
    f_bit = bool(service & 0x40)
    flags['emergency'] = (not p_bit) and f_bit
    flags['spi'] = bool(service & 0x04)
    return flags


def _aircat_psr_service_flags(msg: bytes):
    """Decode PSR / Primary track service flags without creating alerts.

    AIRCAT500 primary track (FE) uses:
      Byte 3: 0 0 0 I BT AS 1/2 T
      Byte 4: quality bits plus AIR / AVR in the low bits.
    These fields are useful as aggregate diagnostics. We keep them out of
    detailed alert tables unless another existing alert already references the
    track.
    """
    flags = {
        'psr_service_byte': None,
        'psr_quality_byte': None,
        'psr_tpr_number': None,
        'tpr_number': None,
        'psr_associated_before': False,
        'psr_test_beacon': False,
        'psr_tvd900_test': False,
        'psr_invalid_dxdy': False,
        'psr_airport_slow': False,
        'psr_airport_fast': False,
    }
    if not msg or len(msg) <= 2:
        return flags
    service = msg[2] & 0xFF
    flags['psr_service_byte'] = service
    flags['psr_invalid_dxdy'] = bool(service & 0x10)
    flags['psr_test_beacon'] = bool(service & 0x08)
    flags['psr_associated_before'] = bool(service & 0x04)
    flags['psr_tpr_number'] = 2 if (service & 0x02) else 1
    flags['tpr_number'] = flags['psr_tpr_number']
    flags['psr_tvd900_test'] = bool(service & 0x01)
    if len(msg) > 3:
        qbyte = msg[3] & 0xFF
        flags['psr_quality_byte'] = qbyte
        # AIR / AVR are carried in the low bits of the quality byte layout.
        flags['psr_airport_fast'] = bool(qbyte & 0x02)
        flags['psr_airport_slow'] = bool(qbyte & 0x01)
    return flags


SPECIAL_MODE_A_ALERTS = {
    # Operationally significant Mode A/3 transponder codes. These become
    # target alerts in Replay / LivePlay and detailed Alerts tables.
    '7500': {
        'code': '7500',
        'short': 'HIJACK',
        'label': '7500 HIJACK',
        'description': 'Unlawful interference / hijack',
    },
    '7600': {
        'code': '7600',
        'short': 'RADIO COMM FAILURE',
        'label': '7600 RADIO COMM FAILURE',
        'description': 'Radio communication failure',
    },
    '7601': {
        'code': '7601',
        'short': 'RADIO FAILURE IFR/VMC',
        'label': '7601 RADIO FAILURE IFR/VMC',
        'description': 'Radio IFR/VMC failure',
    },
    '7700': {
        'code': '7700',
        'short': 'GENERAL EMERGENCY',
        'label': '7700 GENERAL EMERGENCY',
        'description': 'General emergency',
    },
}

SPECIAL_MODE_A_REPORT_CODES = {
    '7000': '7000 VFR',
    '7500': '7500 Unlawful interference / hijack',
    '7600': '7600 Radio communication failure',
    '7601': '7601 Radio IFR/VMC failure',
    '7700': '7700 General emergency',
}

SPECIAL_MODE_A_REPORT_ORDER = [
    '7000 VFR',
    '7500 Unlawful interference / hijack',
    '7600 Radio communication failure',
    '7601 Radio IFR/VMC failure',
    '7700 General emergency',
    'Other Mode A/3 codes',
]


def _normalize_mode_a_code(value):
    """Return a 4-digit Mode A string when possible."""
    if value is None:
        return None
    txt = str(value).strip()
    if not txt:
        return None
    # Mode A is normally a 4-octal-digit squawk. Keep only the direct numeric form.
    if txt.isdigit():
        return txt.zfill(4)[-4:]
    return None


def _special_mode_a_alert_info(value_or_track):
    """Return special 7500/7600/7601/7700 transponder-code info, or None."""
    if isinstance(value_or_track, dict):
        value = value_or_track.get('mode_a')
    else:
        value = value_or_track
    code = _normalize_mode_a_code(value)
    if not code:
        return None
    return SPECIAL_MODE_A_ALERTS.get(code)


def _special_mode_a_report_bucket(value):
    """Return report bucket for Mode A/3 transponder-code statistics."""
    code = _normalize_mode_a_code(value)
    if not code:
        return None
    return SPECIAL_MODE_A_REPORT_CODES.get(code) or 'Other Mode A/3 codes'


def _is_special_mode_a_alert_track(track):
    if not track or track.get('is_weather') or track.get('is_cancellation'):
        return False
    return _special_mode_a_alert_info(track) is not None


def _draw_special_mode_a_plus(canvas, tx, ty, color, tags=()):
    """Draw a large + symbol for special Mode A emergency squawks.

    The half-size is deliberately about twice the classic 4 px target symbol.
    """
    try:
        size = 8
        kwargs = {'fill': color, 'width': 2}
        if tags:
            kwargs['tags'] = tags
        canvas.create_line(tx - size, ty, tx + size, ty, **kwargs)
        canvas.create_line(tx, ty - size, tx, ty + size, **kwargs)
    except Exception:
        pass


def _emergency_flash_visible():
    """Return True during the ON phase of emergency flashing."""
    try:
        return (int(time.time() * 2) % 2) == 0
    except Exception:
        return True


def _track_status_flag_lines(track):
    """Return red target-alert flags drawn separately from normal labels."""
    if not track or track.get('is_weather') or track.get('is_cancellation'):
        return []
    lines = []
    if track.get('spi'):
        lines.append('SPI')
    if track.get('emergency'):
        lines.append('EMERGENCY')
    special = _special_mode_a_alert_info(track)
    if special:
        lines.append(special.get('label') or special.get('code') or '')
    return [line for line in lines if line]


def _is_red_target_alert_track(track):
    """Return True when the target should be emphasized in red for target alerts."""
    if not track or track.get('is_weather') or track.get('is_cancellation'):
        return False
    return bool(track.get('spi') or track.get('emergency') or _is_special_mode_a_alert_track(track))


def _decode_bcd_4_digits(raw: bytes):
    if raw is None or len(raw) < 2:
        return None
    digits = []
    for b in raw[:2]:
        digits.append((b >> 4) & 0x0F)
        digits.append(b & 0x0F)
    if any(d > 9 for d in digits):
        return None
    return digits[0] * 1000 + digits[1] * 100 + digits[2] * 10 + digits[3]

COORDINATE_SCALE_1_32 = "1/32 NM"
COORDINATE_SCALE_1_64 = "1/64 NM"
DEFAULT_COORDINATE_SCALE = COORDINATE_SCALE_1_32
DEFAULT_DISPLAY_RANGE_NM = 250.0
AIRCAT_RANGE_RINGS_NM = (60.0, 120.0, 180.0, 250.0)
AIRCAT_ZOOM_DETAIL_RINGS_NM = (30.0, 20.0, 10.0, 5.0)


def _draw_nm_range_rings(canvas, cx, cy, radius, visible_range_raw, scale_value, tags=()):
    """Draw fixed NM range rings and labels for the radar scope.

    At zoom=1 the outer ring corresponds to 250 NM. When zooming in, only
    rings that fit inside the currently visible range are drawn. A single
    zoom-detail ring is shown progressively: 30 NM after the 60 NM ring has
    disappeared, then 20 NM after 30 disappears, then 10 NM, then 5 NM.
    """
    try:
        divisor = _coordinate_scale_divisor(scale_value)
        visible_range_nm = float(visible_range_raw) / float(divisor)
    except Exception:
        return

    if visible_range_nm <= 0:
        return

    base_tags = tuple(tags) if isinstance(tags, (tuple, list)) else ((tags,) if tags else tuple())

    rings_to_draw = list(AIRCAT_RANGE_RINGS_NM)
    detail_ring_nm = None
    if visible_range_nm < 60.0:
        for ring_nm in AIRCAT_ZOOM_DETAIL_RINGS_NM:
            if visible_range_nm + 1e-9 >= ring_nm:
                detail_ring_nm = ring_nm
                break
    if detail_ring_nm is not None:
        rings_to_draw.insert(0, detail_ring_nm)

    for ring_nm in rings_to_draw:
        if ring_nm > visible_range_nm + 1e-9:
            continue

        rr = radius * (ring_nm / visible_range_nm)
        color = '#003366'
        label = f"{int(ring_nm)}NM"

        canvas.create_oval(
            cx - rr, cy - rr, cx + rr, cy + rr,
            outline=color, width=1, tags=base_tags
        )

        label_x = cx + rr - 4
        label_y = cy - 2
        canvas.create_text(
            label_x, label_y,
            text=label,
            anchor='sw',
            fill=color,
            font=('Arial', 9, 'bold'),
            tags=base_tags
        )


def _coordinate_scale_divisor(scale_value):
    """Return the AIRCAT500 coordinate divisor for display in NM.

    X/Y are decoded as signed raw values. Depending on the AIRCAT500 format,
    one raw unit may correspond to 1/32 NM or 1/64 NM.
    """
    txt = str(scale_value or DEFAULT_COORDINATE_SCALE).replace(" ", "").lower()
    if "1/64" in txt or "64" in txt:
        return 64.0
    return 32.0


def _display_range_raw_units(scale_value):
    """Return the raw AIRCAT500 range that corresponds to the fixed 250 NM display radius."""
    return DEFAULT_DISPLAY_RANGE_NM * _coordinate_scale_divisor(scale_value)


def _format_track_range_lines(track, scale_value):
    """Format range label using the fixed AIRCAT coordinate scale.

    The UI intentionally shows only the polar range line, not X/Y, to keep
    Replay/LivePlay labels compact.
    """
    if not track:
        return []

    try:
        divisor = _coordinate_scale_divisor(scale_value)
        x_raw = track.get('x')
        y_raw = track.get('y')

        if x_raw is not None and y_raw is not None:
            r_nm = math.hypot(float(x_raw), float(y_raw)) / divisor
            return [f"R={r_nm:.1f} NM"]

        rng = track.get('range')
        if rng is not None:
            r_nm = float(rng) / divisor
            return [f"R={r_nm:.1f} NM"]
    except Exception:
        return []

    return []


def _track_quality_max(track):
    """Return displayed max quality according to AIRCAT track kind."""
    if not track:
        return None
    return 7 if int(track.get('type', 0) or 0) == 0xFE else 127


def _signed_int8(value: int):
    value = int(value) & 0xFF
    return value - 256 if value & 0x80 else value


def _decode_mode_word(word: int):
    mode_type = (word >> 12) & 0x7
    payload = word & 0x0FFF

    if mode_type == 0x1:  # Mode A / 3
        digits = [
            (payload >> 9) & 0x7,
            (payload >> 6) & 0x7,
            (payload >> 3) & 0x7,
            payload & 0x7,
        ]
        return ("A", "".join(str(d) for d in digits))

    if mode_type == 0x3:  # Mode C
        n1 = (payload >> 8) & 0xF
        n2 = (payload >> 4) & 0xF
        n3 = payload & 0xF
        if n1 <= 9 and n2 <= 9 and n3 <= 9:
            hundreds = n1 * 100 + n2 * 10 + n3
            return ("C", f"{hundreds * 100}ft")
        if n1 == 0xF and n2 <= 9 and n3 <= 9:
            hundreds = n2 * 10 + n3
            return ("C", f"-{hundreds * 100}ft")
        return ("C", f"0x{payload:03X}")

    return (None, None)





SSR_CODE_WORD_TYPE_LABELS = {
    0x0: 'No answer (empty SSR code word)',
    0x1: 'Mode A/3 transponder code',
    0x2: 'B mode',
    0x3: 'C mode',
    0x4: 'D mode',
    0x5: '1 mode',
    0x6: '2 mode',
    0x7: 'Not used',
}


def _ssr_code_word_type_label(mode_type):
    try:
        mt = int(mode_type) & 0x07
    except Exception:
        return 'Unknown'
    return SSR_CODE_WORD_TYPE_LABELS.get(mt, f'Unknown {mt}')

def _decode_mode_word_info(word: int):
    """Decode AIRCAT SSR code word and keep the C validation/garbling bit.

    When optional byte 21 is not transmitted, the leading C bit in each
    transmitted code word is the basic validation bit: C=0 valid, C=1 invalid.
    When byte 21 is transmitted, byte 21 gives the detailed Mode A/C
    validation and the C bit is treated by the AIRCAT format as garbling info.
    """
    try:
        word = int(word) & 0xFFFF
    except Exception:
        return {'kind': None, 'value': None, 'c_bit': None, 'mode_type': None, 'mode_type_label': None, 'raw': None}

    c_bit = (word >> 15) & 0x01
    mode_type = (word >> 12) & 0x07
    payload = word & 0x0FFF

    if mode_type == 0x1:  # Mode A / 3
        digits = [
            (payload >> 9) & 0x7,
            (payload >> 6) & 0x7,
            (payload >> 3) & 0x7,
            payload & 0x7,
        ]
        return {'kind': 'A', 'value': ''.join(str(d) for d in digits), 'c_bit': c_bit, 'mode_type': mode_type, 'mode_type_label': _ssr_code_word_type_label(mode_type), 'raw': word}

    if mode_type == 0x3:  # Mode C
        n1 = (payload >> 8) & 0xF
        n2 = (payload >> 4) & 0xF
        n3 = payload & 0xF
        if n1 <= 9 and n2 <= 9 and n3 <= 9:
            hundreds = n1 * 100 + n2 * 10 + n3
            return {'kind': 'C', 'value': f'{hundreds * 100}ft', 'c_bit': c_bit, 'mode_type': mode_type, 'mode_type_label': _ssr_code_word_type_label(mode_type), 'raw': word}
        if n1 == 0xF and n2 <= 9 and n3 <= 9:
            hundreds = n2 * 10 + n3
            return {'kind': 'C', 'value': f'-{hundreds * 100}ft', 'c_bit': c_bit, 'mode_type': mode_type, 'mode_type_label': _ssr_code_word_type_label(mode_type), 'raw': word}
        return {'kind': 'C', 'value': f'0x{payload:03X}', 'c_bit': c_bit, 'mode_type': mode_type, 'mode_type_label': _ssr_code_word_type_label(mode_type), 'raw': word}

    return {'kind': None, 'value': None, 'c_bit': c_bit, 'mode_type': mode_type, 'mode_type_label': _ssr_code_word_type_label(mode_type), 'raw': word}


MODE_C_VALIDATION_DETAIL_LABELS = {
    (0, 0, 0): 'no change',
    (0, 0, 1): 'changed',
    (0, 1, 0): 'doubtful: Mode A same as Mode C',
    (0, 1, 1): 'doubtful: cone of silence',
    (1, 0, 0): 'garbled',
    (1, 0, 1): 'undefined bit sequence',
    (1, 1, 0): 'changing too abruptly',
    (1, 1, 1): 'altitude too high',
}

MODE_C_VALIDATION_SHORT_LABELS = {
    (0, 0, 0): None,
    (0, 0, 1): 'changed',
    (0, 1, 0): 'doubtful',
    (0, 1, 1): 'doubtful cone of silence',
    (1, 0, 0): 'garbled',
    (1, 0, 1): 'undefined',
    (1, 1, 0): 'abrupt',
    (1, 1, 1): 'altitude too high',
}


def _decode_ssr_validation_detail(validation_byte):
    """Decode optional AIRCAT byte 21 Mode A/C validation details."""
    if validation_byte is None:
        return None
    b = int(validation_byte) & 0xFF
    b4 = (b >> 4) & 0x01
    b3 = (b >> 3) & 0x01
    b2 = (b >> 2) & 0x01
    b1 = (b >> 1) & 0x01
    b0 = b & 0x01
    detail_key = (b3, b1, b0)
    detail = MODE_C_VALIDATION_DETAIL_LABELS.get(detail_key, 'unknown')
    short = MODE_C_VALIDATION_SHORT_LABELS.get(detail_key)
    mode_c_invalid = bool(b2)

    mode_c_parts = []
    if mode_c_invalid:
        mode_c_parts.append('invalid')
    if short:
        mode_c_parts.append(short)

    return {
        'validation_byte': b,
        'mode_a_status': 'invalid' if b4 else 'valid',
        'mode_a_invalid': bool(b4),
        'mode_c_status': ' '.join(dict.fromkeys(mode_c_parts)) if mode_c_parts else None,
        'mode_c_invalid': mode_c_invalid,
        'mode_c_detail': detail,
        'mode_c_detail_key': f'B3B1B0={b3}{b1}{b0}',
        'mode_c_b3b2b1b0': f'{b3}{b2}{b1}{b0}',
    }

def _decode_ssr_validation(validation_byte):
    detail = _decode_ssr_validation_detail(validation_byte)
    if not detail:
        return None, None
    return detail.get('mode_a_status'), detail.get('mode_c_status')


def _looks_like_ssr_validation_byte(value):
    """Return True when a byte looks like AIRCAT SSR Mode A/C validation byte.

    In the AIRCAT500 SSR track layout, byte 21 carries B4..B0 validation bits
    and its upper three bits are normally zero. Some captures omit byte 21; in
    that case the next byte in the stream may be the Log Sigma byte instead.
    """
    try:
        b = int(value) & 0xFF
    except Exception:
        return False
    return (b & 0xE0) == 0


def _decode_ssr_validation_and_log_sigma(msg: bytes):
    """Decode optional SSR validation and Log Sigma fields.

    AIRCAT500 SSR layout:
      byte 21: Mode A/C validation (optional in some captures)
      byte 22: Log Sigma amplitude, LSB = 10 mV, current range 0..250 = 0..2.5 V

    This helper handles both the full layout and captures where the validation
    byte is omitted, so Log Sigma may appear one byte earlier.
    """
    validation_byte = None
    log_sigma_v = None
    log_sigma_present = False

    if not msg or len(msg) <= 20:
        return validation_byte, log_sigma_v, log_sigma_present

    b20 = msg[20] & 0xFF

    if _looks_like_ssr_validation_byte(b20):
        validation_byte = b20
        if len(msg) > 21:
            log_raw = msg[21] & 0xFF
            log_sigma_v = min(log_raw, 250) * 0.01
            log_sigma_present = True
    else:
        # Byte 21 appears to be absent; byte index 20 is most likely Log Sigma.
        log_raw = b20
        log_sigma_v = min(log_raw, 250) * 0.01
        log_sigma_present = True

    return validation_byte, log_sigma_v, log_sigma_present



TRACKING_WINDOW_LABELS = {
    0b00: "Outside E3",
    0b01: "Inside E1",
    0b10: "Inside E2",
    0b11: "Inside E3",
}

TRACKING_WINDOW_SHORT_LABELS = {
    0b00: "OutE3",
    0b01: "E1",
    0b10: "E2",
    0b11: "E3",
}


def _decode_aircat_tracking_timing_word(word):
    """Decode AIRCAT500 Time Since North / tracking window / smoothing K.

    Primary FE uses bytes 15-16. SSR/MSSR FF uses bytes 23-24.
    Layout:
      bits 15..13 = smoothing K
      bits 12..11 = tracking window W1/W0
      bits 10..0  = time since North in 1/128 sec units
    """
    try:
        word = int(word) & 0xFFFF
    except Exception:
        return None

    k = (word >> 13) & 0x07
    window_bits = (word >> 11) & 0x03
    t_raw = word & 0x07FF
    t_sec = t_raw / 128.0

    return {
        'timing_word': word,
        'time_since_north_raw': t_raw,
        'time_since_north_sec': t_sec,
        'tracking_window_bits': window_bits,
        'tracking_window': TRACKING_WINDOW_LABELS.get(window_bits, "Unknown"),
        'tracking_window_short': TRACKING_WINDOW_SHORT_LABELS.get(window_bits, "Unknown"),
        'smoothing_k': k,
    }


def _extract_aircat_tracking_timing(msg, key):
    """Return decoded timing fields for FE / FF track messages, or {}."""
    try:
        key = int(key) & 0xFF
    except Exception:
        return {}

    try:
        if key == 0xFE and len(msg) >= 16:
            word = struct.unpack('>H', msg[14:16])[0]
            return _decode_aircat_tracking_timing_word(word) or {}
        if key == 0xFF and len(msg) >= 24:
            word = struct.unpack('>H', msg[22:24])[0]
            return _decode_aircat_tracking_timing_word(word) or {}
    except Exception:
        return {}
    return {}


def _format_time_since_north(value):
    if value is None or value == "":
        return ""
    try:
        return f"{float(value):.3f}s"
    except Exception:
        return str(value)


def _format_track_timing_summary(track):
    """Compact label text for decoded tracking timing."""
    if not isinstance(track, dict):
        return ""
    parts = []
    if track.get('time_since_north_sec') is not None:
        parts.append(f"TN:{_format_time_since_north(track.get('time_since_north_sec'))}")
    if track.get('tracking_window_short'):
        parts.append(f"W:{track.get('tracking_window_short')}")
    if track.get('smoothing_k') is not None:
        parts.append(f"K:{track.get('smoothing_k')}")
    return " ".join(parts)


def _decode_fb_track_candidates(data: bytes, pos: int, remaining: int):
    candidates = set()
    if remaining >= 2:
        candidates.add(data[pos + 1] & 0xFF)
    if remaining >= 3:
        b1 = data[pos + 1] & 0xFF
        b2 = data[pos + 2] & 0xFF
        candidates.add(((b1 << 8) | b2) & 0x01FF)
        candidates.add(((b2 & 0x01) << 8) | b1)
        candidates.add(((b1 & 0x01) << 8) | b2)
    return sorted(candidates)


def _is_low_quality_track(track):
    if not track or track.get('is_weather') or track.get('is_cancellation'):
        return False
    quality = track.get('quality')
    if quality is None:
        return False
    try:
        q = int(quality)
    except Exception:
        return False

    is_ssr = int(track.get('type') or 0) == 0xFF
    if is_ssr:
        # User-requested threshold: SSR is low quality for measurements below 95/127.
        return q < 95

    # PSR / primary FE keeps the previous practical threshold.
    return q <= 3


def _track_matches_cancellation(track, cancellation):
    if not track or not cancellation:
        return False
    track_no = track.get('track_no')
    if track_no is None:
        return False
    try:
        track_no = int(track_no)
    except Exception:
        return False
    candidates = cancellation.get('track_no_candidates') or []
    if not candidates and cancellation.get('track_no') is not None:
        candidates = [cancellation.get('track_no')]
    try:
        return track_no in {int(c) for c in candidates if c is not None}
    except Exception:
        return False


def _mark_cancelled_tracks(sector_memory, cancellation, current_scan=None):
    """Mark matching tracks as cancelled without removing them from display memory."""
    marked = 0
    if not sector_memory or not cancellation:
        return marked

    for _sector_no, mem_tracks in list(sector_memory.items()):
        for track in mem_tracks:
            if _track_matches_cancellation(track, cancellation):
                track['track_cancelled'] = True
                if current_scan is not None:
                    try:
                        track['_cancelled_scan'] = int(current_scan)
                    except Exception:
                        track['_cancelled_scan'] = current_scan
                marked += 1
    return marked


def _purge_expired_cancelled_tracks(sector_memory, current_scan, max_scans=3):
    """Remove cancelled tracks when they have not been updated for max_scans scans."""
    if not sector_memory:
        return 0
    try:
        scan_now = int(current_scan)
    except Exception:
        return 0

    removed = 0
    for sector_no, mem_tracks in list(sector_memory.items()):
        kept = []
        for track in mem_tracks:
            if track.get('track_cancelled'):
                try:
                    cancelled_scan = int(track.get('_cancelled_scan', scan_now))
                except Exception:
                    cancelled_scan = scan_now
                if scan_now - cancelled_scan >= max_scans:
                    removed += 1
                    continue
            kept.append(track)
        if kept:
            sector_memory[sector_no] = kept
        else:
            sector_memory.pop(sector_no, None)
    return removed


def _track_no_int(track):
    if not track or track.get('track_no') is None:
        return None
    try:
        return int(track.get('track_no'))
    except Exception:
        return None


def _track_label_offset_key(track):
    """Stable key for manual label offsets in Replay / LivePlay.

    The offset is a screen-pixel offset, not a radar-coordinate offset. This
    keeps manually moved labels visually stable while zooming or panning.
    """
    if not track or track.get('is_weather') or track.get('is_cancellation'):
        return None
    track_no = _track_no_int(track)
    if track_no is None:
        return None
    try:
        type_i = int(track.get('type', 0) or 0) & 0xFF
    except Exception:
        type_i = 0
    return f"{type_i:02X}_{track_no}"


def _track_label_canvas_tags(track, *extra_tags):
    key = _track_label_offset_key(track)
    tags = [t for t in extra_tags if t]
    if key:
        tags.extend(["track_label", f"track_label_key_{key}"])
    return tuple(tags)


def _find_track_label_key_from_canvas_event(canvas, event):
    """Return the track label key under the mouse pointer, if any."""
    if canvas is None or event is None:
        return None
    try:
        current_items = canvas.find_withtag("current")
        if not current_items:
            current_items = canvas.find_overlapping(event.x, event.y, event.x, event.y)
        for item in current_items:
            for tag in canvas.gettags(item):
                if isinstance(tag, str) and tag.startswith("track_label_key_"):
                    return tag.replace("track_label_key_", "", 1)
    except Exception:
        return None
    return None


def _raw_bytes_to_spaced_hex(raw_value):
    """Format raw bytes / hex text as uppercase hex with spaces between bytes."""
    if raw_value is None:
        return ""
    try:
        if isinstance(raw_value, (bytes, bytearray)):
            return " ".join(f"{b:02X}" for b in raw_value)
        txt = str(raw_value).strip()
        if not txt:
            return ""
        compact = re.sub(r"[^0-9A-Fa-f]", "", txt)
        if compact and len(compact) % 2 == 0:
            return " ".join(compact[i:i + 2].upper() for i in range(0, len(compact), 2))
        return txt
    except Exception:
        return str(raw_value)


def _track_raw_payload_text(track):
    """Return the target-specific raw AIRCAT track message payload as spaced hex."""
    if not isinstance(track, dict):
        return ""
    raw = track.get('raw_track_payload_hex')
    if raw:
        return _raw_bytes_to_spaced_hex(raw)
    raw = track.get('raw_track_payload')
    if raw:
        return _raw_bytes_to_spaced_hex(raw)
    return ""


def _scan_window_meta_text(frame_no=None, ts=None):
    """Compact packet metadata for current-scan raw windows."""
    parts = []
    if frame_no is not None:
        parts.append(f"Wireshark #{frame_no}")
    if ts is not None:
        try:
            parts.append(format_capture_time(ts))
        except Exception:
            parts.append(str(ts))
    return " | ".join(parts) if parts else "Packet"


def _aircat_track_entry_matches(track, type_i, track_no, raw_hex):
    """Return True when a raw FE/FF entry is the selected track payload."""
    if not isinstance(track, dict):
        return False
    try:
        selected_raw = _track_raw_payload_text(track)
        if selected_raw and raw_hex and selected_raw.strip().upper() == str(raw_hex).strip().upper():
            return True
    except Exception:
        pass
    try:
        if int(track.get('type', -1)) != int(type_i):
            return False
        if track.get('track_no') is None or track_no is None:
            return False
        return int(track.get('track_no')) == int(track_no)
    except Exception:
        return False


def _aircat_payload_scan_entries(payload: bytes, selected_track=None, stop_at_selected=False):
    """Return display entries for a sector/extension payload.

    FE/FF target messages are returned as blue entries. The selected target,
    when matched, is returned as bold-blue and can stop the listing so its raw
    payload is the last line in the window.
    """
    entries = []
    found_selected = False
    if not payload:
        return entries, found_selected

    if len(payload) >= 4 and payload[0] == 0x0C and payload[1] == 0x40 and payload[2] in (0xFD, 0xFC):
        data = payload[4:]
    elif len(payload) >= 2 and payload[0] == 0x0D and payload[1] == 0x40:
        data = payload[2:]
    else:
        return [{'text': f"  Raw payload: {_raw_bytes_to_spaced_hex(payload)}", 'tag': None}], found_selected

    pos = 0
    total_len = len(data)
    while pos < total_len:
        remaining = total_len - pos
        key = data[pos]

        if key in (0xFE, 0xFF):
            if remaining < 2:
                raw = data[pos:]
                entries.append({'text': f"  Truncated target 0x{key:02X}: {_raw_bytes_to_spaced_hex(raw)}", 'tag': 'target'})
                break
            byte_count = data[pos + 1]
            if byte_count < 2 or byte_count > remaining:
                raw = data[pos:]
                entries.append({'text': f"  Bad target 0x{key:02X} count={byte_count}: {_raw_bytes_to_spaced_hex(raw)}", 'tag': 'target'})
                break
            msg = data[pos:pos + byte_count]
            raw_hex = _raw_bytes_to_spaced_hex(msg)
            track_no = None
            try:
                if len(msg) >= 6:
                    track_no = struct.unpack('>H', msg[4:6])[0] & 0x01FF
            except Exception:
                track_no = None
            src = 'MSSR/SSR' if key == 0xFF else 'PSR'
            is_selected = _aircat_track_entry_matches(selected_track, key, track_no, raw_hex)
            tag = 'target_selected' if is_selected else 'target'
            entries.append({
                'text': f"  {src} Track #{track_no if track_no is not None else 'n/a'}: {raw_hex}",
                'tag': tag,
            })
            if is_selected:
                found_selected = True
                if stop_at_selected:
                    break
            pos += byte_count
            continue

        if key == 0xFB:
            take = 4 if remaining >= 4 and data[pos + 3] == 0x00 else min(3, remaining)
            raw = data[pos:pos + take]
            entries.append({'text': f"  Track cancellation: {_raw_bytes_to_spaced_hex(raw)}", 'tag': None})
            pos += take
            continue

        if key in (0xFA, 0x00):
            take = min(4, remaining)
            raw = data[pos:pos + take]
            entries.append({'text': f"  Embedded 0x{key:02X}: {_raw_bytes_to_spaced_hex(raw)}", 'tag': None})
            pos += take
            continue

        raw = data[pos:min(total_len, pos + 8)]
        entries.append({'text': f"  Embedded 0x{key:02X}: {_raw_bytes_to_spaced_hex(raw)}", 'tag': None})
        break

    return entries, found_selected


def _has_manual_label_offset(offset_x, offset_y):
    """Return True when a label has been manually dragged away from default."""
    try:
        return abs(float(offset_x or 0.0)) >= 1.0 or abs(float(offset_y or 0.0)) >= 1.0
    except Exception:
        return False


def _merge_pending_cancelled_tracks(previous_tracks, new_tracks, current_scan, max_scans=3):
    """Keep a cancelled track visible for up to max_scans unless a fresh update arrives."""
    previous_tracks = list(previous_tracks or [])
    new_tracks = list(new_tracks or [])
    try:
        scan_now = int(current_scan)
    except Exception:
        scan_now = 0

    updated_track_numbers = {_track_no_int(t) for t in new_tracks if _track_no_int(t) is not None}
    merged = list(new_tracks)

    for old_track in previous_tracks:
        if not old_track.get('track_cancelled'):
            continue
        old_track_no = _track_no_int(old_track)
        if old_track_no is not None and old_track_no in updated_track_numbers:
            continue
        try:
            cancelled_scan = int(old_track.get('_cancelled_scan', scan_now))
        except Exception:
            cancelled_scan = scan_now
        if scan_now - cancelled_scan < max_scans:
            merged.append(old_track)

    return merged


def _drop_cancelled_tracks_replaced_by_updates(sector_memory, new_tracks):
    """Remove old cancelled labels as soon as the same track number is updated anywhere."""
    if not sector_memory or not new_tracks:
        return 0
    updated_track_numbers = {_track_no_int(t) for t in new_tracks if _track_no_int(t) is not None}
    if not updated_track_numbers:
        return 0

    removed = 0
    for sector_no, mem_tracks in list(sector_memory.items()):
        kept = []
        for track in mem_tracks:
            if track.get('track_cancelled') and _track_no_int(track) in updated_track_numbers:
                removed += 1
                continue
            kept.append(track)
        if kept:
            sector_memory[sector_no] = kept
        else:
            sector_memory.pop(sector_no, None)
    return removed


def _parse_replay_tracks_from_payload(payload: bytes):
    tracks = []
    if not payload:
        return tracks

    if len(payload) >= 4 and payload[0] == 0x0C and payload[1] == 0x40 and payload[2] in (0xFD, 0xFC):
        data = payload[4:]
    elif len(payload) >= 2 and payload[0] == 0x0D and payload[1] == 0x40:
        data = payload[2:]
    else:
        return tracks

    pos = 0
    total_len = len(data)
    while pos < total_len:
        remaining = total_len - pos
        key = data[pos]

        if key in (0xFE, 0xFF):
            if remaining < 10:
                break
            byte_count = data[pos + 1]
            if byte_count < 10 or byte_count > remaining:
                break
            msg = data[pos:pos + byte_count]
            try:
                x = struct.unpack('>h', msg[6:8])[0]
                y = struct.unpack('>h', msg[8:10])[0]
                rng = math.hypot(x, y)
                angle_deg = math.degrees(math.atan2(-y, x))

                mode_a = None
                mode_c = None
                mode_a_status = None
                mode_c_status = None
                mode_a_c_bit = None
                mode_c_c_bit = None
                mode_a_validation_present = False
                mode_c_validation_present = False
                mode_a_validation_source = None
                mode_c_validation_source = None
                mode_a_invalid = None
                mode_c_invalid = None
                mode_c_validation_detail = None
                mode_c_validation_bits = None
                validation_byte = None
                log_sigma_v = None
                log_sigma_present = False
                ssr_code_word_types = []
                service_flags = _aircat_ssr_service_flags(msg) if key == 0xFF else {'spi': False, 'emergency': False, 'service_byte': None, 'ssr_tpr_number': None}
                psr_service_flags = _aircat_psr_service_flags(msg) if key == 0xFE else {}
                spi = bool(service_flags.get('spi'))
                emergency = bool(service_flags.get('emergency'))
                service_byte = service_flags.get('service_byte')
                tpr_number = service_flags.get('ssr_tpr_number') if key == 0xFF else psr_service_flags.get('psr_tpr_number')

                if key == 0xFF:
                    for off in (12, 14, 16):
                        if off + 2 <= len(msg):
                            word = struct.unpack('>H', msg[off:off + 2])[0]
                            mode_info = _decode_mode_word_info(word)
                            mode_type_label = mode_info.get('mode_type_label')
                            if mode_type_label:
                                ssr_code_word_types.append(mode_type_label)
                            mode_kind = mode_info.get('kind')
                            mode_value = mode_info.get('value')
                            if mode_kind == "A" and mode_a is None:
                                mode_a = mode_value
                                mode_a_c_bit = mode_info.get('c_bit')
                            elif mode_kind == "C" and mode_c is None:
                                mode_c = mode_value
                                mode_c_c_bit = mode_info.get('c_bit')

                    validation_byte, log_sigma_v, log_sigma_present = _decode_ssr_validation_and_log_sigma(msg)
                    validation_detail = _decode_ssr_validation_detail(validation_byte)

                    if validation_detail:
                        # Full optional byte 21 is present: use the detailed validation.
                        mode_a_status = validation_detail.get('mode_a_status')
                        mode_c_status = validation_detail.get('mode_c_status')
                        if mode_a is not None:
                            mode_a_validation_present = True
                            mode_a_validation_source = 'Byte 21'
                            mode_a_invalid = bool(validation_detail.get('mode_a_invalid'))
                        if mode_c is not None:
                            mode_c_validation_present = True
                            mode_c_validation_source = 'Byte 21'
                            mode_c_invalid = bool(validation_detail.get('mode_c_invalid'))
                            mode_c_validation_detail = validation_detail.get('mode_c_detail')
                            mode_c_validation_bits = validation_detail.get('mode_c_b3b2b1b0')
                    else:
                        # Byte 21 is absent: the leading C bit of each transmitted
                        # code word is the only basic valid/invalid indication.
                        if mode_a is not None and mode_a_c_bit is not None:
                            mode_a_validation_present = True
                            mode_a_validation_source = 'C bit'
                            mode_a_invalid = bool(mode_a_c_bit)
                            mode_a_status = 'invalid' if mode_a_invalid else 'valid'
                        if mode_c is not None and mode_c_c_bit is not None:
                            mode_c_validation_present = True
                            mode_c_validation_source = 'C bit'
                            mode_c_invalid = bool(mode_c_c_bit)
                            mode_c_status = 'invalid' if mode_c_invalid else None
                            mode_c_validation_detail = 'invalid from transmitted C bit' if mode_c_invalid else 'valid from transmitted C bit'
                            mode_c_validation_bits = f'C={int(mode_c_c_bit)}'

                track_no = struct.unpack('>H', msg[4:6])[0] & 0x01FF
                has_ssr_info = bool(mode_a or mode_c)
                is_psr_capable = (key == 0xFE)

                # Combined/associated indication according to AIRCAT500 fields:
                #   FE primary track: service-byte AS bit means associated/combined with SSR.
                #   FF SSR track: SA bit means secondary associated with primary.
                # The previous logic only treated FE as combined if Mode A/C fields were
                # present inside the FE message, so real combined targets could be missed.
                primary_associated = bool(key == 0xFE and psr_service_flags.get('psr_associated_before'))
                ssr_associated = bool(key == 0xFF and len(msg) > 4 and (msg[4] & 0x40))
                is_combined_track = bool(primary_associated or ssr_associated or (is_psr_capable and has_ssr_info))

                quality = None
                detection_misses = None
                maneuver = False
                dx = None
                dy = None
                speed_kt = None

                if len(msg) > 3:
                    if key == 0xFE:
                        quality = (msg[3] >> 2) & 0x07
                    else:
                        quality = msg[3] & 0x7F

                if len(msg) > 4:
                    detection_misses = (msg[4] >> 4) & 0x03
                    maneuver = bool(msg[4] & 0x04)

                if len(msg) > 11:
                    dx = _signed_int8(msg[10])
                    dy = _signed_int8(msg[11])

                if key == 0xFE and len(msg) >= 14:
                    speed_kt = _decode_bcd_4_digits(msg[12:14])
                elif key == 0xFF and len(msg) >= 20:
                    speed_kt = _decode_bcd_4_digits(msg[18:20])

                timing_info = _extract_aircat_tracking_timing(msg, key)

                # Log Sigma is decoded together with SSR validation above, because
                # some captures omit the validation byte and shift Log Sigma left.

                tracks.append({
                    'type': key,
                    'track_no': track_no,
                    'raw_track_payload_hex': _raw_bytes_to_spaced_hex(msg),
                    'raw_track_payload_len': len(msg),
                    'x': x,
                    'y': y,
                    'range': rng,
                    'angle_deg': angle_deg,
                    'mode_a': mode_a,
                    'mode_c': mode_c,
                    'mode_a_status': mode_a_status,
                    'mode_c_status': mode_c_status,
                    'mode_a_validation_present': mode_a_validation_present,
                    'mode_c_validation_present': mode_c_validation_present,
                    'mode_a_validation_source': mode_a_validation_source,
                    'mode_c_validation_source': mode_c_validation_source,
                    'mode_a_invalid': mode_a_invalid,
                    'mode_c_invalid': mode_c_invalid,
                    'mode_c_validation_detail': mode_c_validation_detail,
                    'mode_c_validation_bits': mode_c_validation_bits,
                    'validation_byte': validation_byte,
                    'service_byte': service_byte,
                    'psr_service_byte': psr_service_flags.get('psr_service_byte'),
                    'psr_quality_byte': psr_service_flags.get('psr_quality_byte'),
                    'psr_tpr_number': psr_service_flags.get('psr_tpr_number'),
                    'ssr_tpr_number': service_flags.get('ssr_tpr_number'),
                    'tpr_number': tpr_number,
                    'psr_associated_before': bool(psr_service_flags.get('psr_associated_before')),
                    'psr_test_beacon': bool(psr_service_flags.get('psr_test_beacon')),
                    'psr_tvd900_test': bool(psr_service_flags.get('psr_tvd900_test')),
                    'psr_invalid_dxdy': bool(psr_service_flags.get('psr_invalid_dxdy')),
                    'psr_airport_slow': bool(psr_service_flags.get('psr_airport_slow')),
                    'psr_airport_fast': bool(psr_service_flags.get('psr_airport_fast')),
                    'spi': spi,
                    'emergency': emergency,
                    'special_mode_a_alert': _special_mode_a_alert_info(mode_a) is not None,
                    'special_mode_a_code': (_special_mode_a_alert_info(mode_a) or {}).get('code'),
                    'special_mode_a_label': (_special_mode_a_alert_info(mode_a) or {}).get('label'),
                    'special_mode_a_description': (_special_mode_a_alert_info(mode_a) or {}).get('description'),
                    'quality': quality,
                    'detection_misses': detection_misses,
                    'maneuver': maneuver,
                    'dx': dx,
                    'dy': dy,
                    'speed_kt': speed_kt,
                    'log_sigma_v': log_sigma_v,
                    'log_sigma_present': log_sigma_present,
                    'ssr_code_word_types': list(ssr_code_word_types),
                    'timing_word': timing_info.get('timing_word'),
                    'time_since_north_raw': timing_info.get('time_since_north_raw'),
                    'time_since_north_sec': timing_info.get('time_since_north_sec'),
                    'tracking_window_bits': timing_info.get('tracking_window_bits'),
                    'tracking_window': timing_info.get('tracking_window'),
                    'tracking_window_short': timing_info.get('tracking_window_short'),
                    'smoothing_k': timing_info.get('smoothing_k'),
                    'psr': is_psr_capable,
                    'has_ssr': (key == 0xFF) or has_ssr_info,
                    'is_combined': is_combined_track,
                    'is_weather': False,
                    'is_cancellation': False,
                })
            except Exception:
                pass
            pos += byte_count
            continue

        if key == 0xFB:
            if remaining >= 3:
                candidates = _decode_fb_track_candidates(data, pos, remaining)
                tracks.append({
                    'type': 0xFB,
                    'track_no': candidates[0] if candidates else None,
                    'track_no_candidates': candidates,
                    'is_cancellation': True,
                    'is_weather': False,
                    'range': 0.0,
                    'angle_deg': 0.0,
                })
                if remaining >= 4 and data[pos + 3] == 0x00:
                    pos += 4
                else:
                    pos += 3
            elif remaining >= 2:
                candidates = _decode_fb_track_candidates(data, pos, remaining)
                tracks.append({
                    'type': 0xFB,
                    'track_no': candidates[0] if candidates else None,
                    'track_no_candidates': candidates,
                    'is_cancellation': True,
                    'is_weather': False,
                    'range': 0.0,
                    'angle_deg': 0.0,
                })
                pos += 2
            else:
                break
            continue

        if key in (0xFA, 0x00):
            if remaining >= 4:
                pos += 4
            else:
                break
            continue

        break

    return tracks


def _available_cpu_cores():
    """Return the number of logical CPU cores available to the program."""
    try:
        return max(1, int(os.cpu_count() or 1))
    except Exception:
        return 1


def _cpu_description():
    """Best-effort CPU model and nominal/current speed description."""
    model = ""
    speed = ""

    # Windows: registry usually gives the most useful display name and MHz.
    try:
        if os.name == "nt":
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0") as key:
                try:
                    model = str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
                except Exception:
                    pass
                try:
                    mhz = float(winreg.QueryValueEx(key, "~MHz")[0])
                    if mhz >= 1000:
                        speed = f"{mhz / 1000.0:.2f} GHz"
                    elif mhz > 0:
                        speed = f"{mhz:.0f} MHz"
                except Exception:
                    pass
    except Exception:
        pass

    # Linux: /proc/cpuinfo is available on most systems.
    if not model or not speed:
        try:
            if os.path.exists("/proc/cpuinfo"):
                with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
                    cpuinfo = f.read().splitlines()
                if not model:
                    for line in cpuinfo:
                        if line.lower().startswith("model name"):
                            model = line.split(":", 1)[1].strip()
                            break
                if not speed:
                    for line in cpuinfo:
                        if line.lower().startswith("cpu mhz"):
                            mhz = float(line.split(":", 1)[1].strip())
                            if mhz >= 1000:
                                speed = f"{mhz / 1000.0:.2f} GHz"
                            elif mhz > 0:
                                speed = f"{mhz:.0f} MHz"
                            break
        except Exception:
            pass

    # macOS / BSD fallback via sysctl when available.
    if not model:
        try:
            out = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True, stderr=subprocess.DEVNULL, timeout=1.0)
            model = out.strip()
        except Exception:
            pass
    if not speed:
        try:
            out = subprocess.check_output(["sysctl", "-n", "hw.cpufrequency"], text=True, stderr=subprocess.DEVNULL, timeout=1.0)
            hz = float(out.strip())
            if hz >= 1_000_000_000:
                speed = f"{hz / 1_000_000_000.0:.2f} GHz"
            elif hz >= 1_000_000:
                speed = f"{hz / 1_000_000.0:.0f} MHz"
        except Exception:
            pass

    if not model:
        try:
            model = platform.processor() or platform.machine() or "unknown CPU"
        except Exception:
            model = "unknown CPU"

    # Compact common Windows CPU branding so it fits cleanly in About.
    try:
        model = re.sub(r"\(R\)|\(TM\)", "", str(model))
        model = re.sub(r"\bCPU\b", "", model)
        model = re.sub(r"\s+", " ", model).strip()
        model = re.sub(r"\s*@\s*", " @ ", model)
        model = re.sub(r"GHz\b", "GHz", model)
    except Exception:
        pass

    # Many ProcessorNameString values already include the nominal speed.
    # Avoid showing "... @ 2.70GHz @ 2.69 GHz".
    if speed and not re.search(r"@\s*\d+(?:\.\d+)?\s*(?:GHz|MHz)", model, re.IGNORECASE):
        return f"{model} @ {speed}"
    return model


PARALLEL_REPLAY_MIN_SECTORS = 256

# Hidden replay chunking. The user still sees one continuous replay, but the
# expensive track decoding is done lazily in 30-minute windows plus a short
# warm-up before the selected position.
REPLAY_CHUNK_SECONDS = 30 * 60.0
REPLAY_CHUNK_WARMUP_SECONDS = 20.0


def _parse_replay_payload_worker(item):
    """Worker used by ProcessPoolExecutor for replay track decoding."""
    event_index, payload = item
    tracks = _parse_replay_tracks_from_payload(payload)
    max_range = 0.0
    try:
        real_tracks = [t for t in tracks if not t.get('is_cancellation')]
        if real_tracks:
            max_range = max(float(t.get('range', 0.0) or 0.0) for t in real_tracks)
    except Exception:
        max_range = 0.0
    return event_index, tracks, max_range


def parse_udp_payload_from_frame(frame: bytes):
    if len(frame) < 14:
        return None

    eth_type = struct.unpack('!H', frame[12:14])[0]
    offset = 14

    if eth_type in (0x8100, 0x88A8):
        if len(frame) < 18:
            return None
        eth_type = struct.unpack('!H', frame[16:18])[0]
        offset = 18

    if eth_type != 0x0800:
        return None

    if len(frame) < offset + 20:
        return None

    ver_ihl = frame[offset]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or ihl < 20:
        return None

    if len(frame) < offset + ihl + 8:
        return None

    protocol = frame[offset + 9]
    if protocol != 17:
        return None

    total_length = struct.unpack('!H', frame[offset + 2:offset + 4])[0]
    ip_payload_end = min(offset + total_length, len(frame))

    udp_offset = offset + ihl
    udp_len = struct.unpack('!H', frame[udp_offset + 4:udp_offset + 6])[0]
    payload_start = udp_offset + 8
    payload_end = min(payload_start + max(0, udp_len - 8), ip_payload_end)

    if payload_start > len(frame) or payload_end > len(frame) or payload_end < payload_start:
        return None

    return frame[payload_start:payload_end]


def load_from_pcap(path, progress_callback=None, udp_only=True):
    records = []
    file_size = os.path.getsize(path)

    def progress(fobj, msg):
        if progress_callback and file_size > 0:
            progress_callback(min(100.0, (fobj.tell() / file_size) * 100.0), msg)

    with open(path, 'rb') as f:
        magic = f.read(4)
        if len(magic) < 4:
            raise ValueError("Άδειο ή κατεστραμμένο PCAP αρχείο.")

        if magic == b'\xd4\xc3\xb2\xa1':
            endian = '<'
            micro = True
        elif magic == b'\xa1\xb2\xc3\xd4':
            endian = '>'
            micro = True
        elif magic == b'\x4d\x3c\xb2\xa1':
            endian = '<'
            micro = False
        elif magic == b'\xa1\xb2\x3c\x4d':
            endian = '>'
            micro = False
        else:
            raise ValueError("Μη υποστηριζόμενο PCAP format.")

        if len(f.read(20)) < 20:
            raise ValueError("Κατεστραμμένο PCAP header.")

        pkt_index = 0
        while True:
            hdr = f.read(16)
            if not hdr:
                break
            if len(hdr) < 16:
                break

            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + 'IIII', hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break

            pkt_index += 1
            frame_no = pkt_index

            divisor = 1_000_000 if micro else 1_000_000_000
            ts = ts_sec + (ts_frac / divisor)

            if udp_only:
                udp_payload = parse_udp_payload_from_frame(data)
                if udp_payload:
                    records.append({
                        'source': 'pcap',
                        'timestamp': ts,
                        'payload': udp_payload,
                        'frame_no': frame_no,
                    })
            else:
                records.append({
                    'source': 'pcap',
                    'timestamp': ts,
                    'payload': data,
                    'frame_no': frame_no,
                })

            if pkt_index % 500 == 0:
                progress(f, f"Φόρτωση PCAP... {pkt_index} packets")

    if progress_callback:
        progress_callback(100.0, "Η φόρτωση ολοκληρώθηκε.")
    return records


def _parse_pcapng_options(raw: bytes, endian: str):
    options = {}
    pos = 0
    while pos + 4 <= len(raw):
        code, length = struct.unpack(endian + 'HH', raw[pos:pos + 4])
        pos += 4
        if code == 0:
            break
        value = raw[pos:pos + length]
        pos += (length + 3) & ~3
        options.setdefault(code, []).append(value)
    return options


def load_from_pcapng(path, progress_callback=None, udp_only=True):
    records = []
    file_size = os.path.getsize(path)
    interfaces = []

    def progress(fobj, msg):
        if progress_callback and file_size > 0:
            progress_callback(min(100.0, (fobj.tell() / file_size) * 100.0), msg)

    with open(path, 'rb') as f:
        current_endian = '<'
        block_index = 0
        frame_no = 0

        while True:
            block_type_raw = f.read(4)
            if not block_type_raw:
                break
            if len(block_type_raw) < 4:
                break

            len_raw = f.read(4)
            if len(len_raw) < 4:
                break

            if block_type_raw == b'\x0A\x0D\x0D\x0A':
                bom = f.read(4)
                if bom == b'\x4d\x3c\x2b\x1a':
                    current_endian = '<'
                elif bom == b'\x1a\x2b\x3c\x4d':
                    current_endian = '>'
                else:
                    raise ValueError("Μη έγκυρο PCAPNG Section Header.")

                total_len = struct.unpack(current_endian + 'I', len_raw)[0]
                remaining = total_len - 12
                rest = f.read(remaining)
                if len(rest) < remaining:
                    break
            else:
                total_len = struct.unpack(current_endian + 'I', len_raw)[0]
                if total_len < 12:
                    break
                raw_block = f.read(total_len - 8)
                if len(raw_block) < total_len - 8:
                    break
                body = raw_block[:-4]

                block_type = struct.unpack(current_endian + 'I', block_type_raw)[0]

                if block_type == 0x00000001:
                    if len(body) >= 8:
                        content = body
                        linktype, _reserved, _snaplen = struct.unpack(current_endian + 'HHI', content[:8])
                        opts = _parse_pcapng_options(content[8:], current_endian)
                        tsresol = 1e-6
                        if 9 in opts and opts[9]:
                            b = opts[9][0][0]
                            if b & 0x80:
                                tsresol = 2 ** -(b & 0x7F)
                            else:
                                tsresol = 10 ** (-b)
                        interfaces.append({'linktype': linktype, 'tsresol': tsresol})

                elif block_type == 0x00000006:
                    if len(body) >= 20:
                        content = body
                        interface_id, ts_high, ts_low, cap_len, _pkt_len = struct.unpack(current_endian + 'IIIII', content[:20])
                        packet_data = content[20:20 + cap_len]
                        frame_no += 1
                        tsresol = 1e-6
                        if 0 <= interface_id < len(interfaces):
                            tsresol = interfaces[interface_id].get('tsresol', 1e-6)
                        ts = ((ts_high << 32) | ts_low) * tsresol
                        if udp_only:
                            udp_payload = parse_udp_payload_from_frame(packet_data)
                            if udp_payload:
                                records.append({
                                    'source': 'pcapng',
                                    'timestamp': ts,
                                    'payload': udp_payload,
                                    'frame_no': frame_no,
                                })
                        else:
                            records.append({
                                'source': 'pcapng',
                                'timestamp': ts,
                                'payload': packet_data,
                                'frame_no': frame_no,
                            })

                elif block_type == 0x00000003:
                    if len(body) >= 4:
                        content = body
                        packet_data = content[4:]
                        frame_no += 1
                        if udp_only:
                            udp_payload = parse_udp_payload_from_frame(packet_data)
                            if udp_payload:
                                records.append({
                                    'source': 'pcapng',
                                    'timestamp': None,
                                    'payload': udp_payload,
                                    'frame_no': frame_no,
                                })
                        else:
                            records.append({
                                'source': 'pcapng',
                                'timestamp': None,
                                'payload': packet_data,
                                'frame_no': frame_no,
                            })

                elif block_type == 0x00000002:
                    if len(body) >= 20:
                        content = body
                        interface_id, _drops = struct.unpack(current_endian + 'HH', content[:4])
                        ts_high, ts_low, cap_len, _pkt_len = struct.unpack(current_endian + 'IIII', content[4:20])
                        packet_data = content[20:20 + cap_len]
                        frame_no += 1
                        tsresol = 1e-6
                        if 0 <= interface_id < len(interfaces):
                            tsresol = interfaces[interface_id].get('tsresol', 1e-6)
                        ts = ((ts_high << 32) | ts_low) * tsresol
                        if udp_only:
                            udp_payload = parse_udp_payload_from_frame(packet_data)
                            if udp_payload:
                                records.append({
                                    'source': 'pcapng',
                                    'timestamp': ts,
                                    'payload': udp_payload,
                                    'frame_no': frame_no,
                                })
                        else:
                            records.append({
                                'source': 'pcapng',
                                'timestamp': ts,
                                'payload': packet_data,
                                'frame_no': frame_no,
                            })

            block_index += 1
            if block_index % 500 == 0:
                progress(f, f"Φόρτωση PCAPNG... {block_index} blocks")

    if progress_callback:
        progress_callback(100.0, "Η φόρτωση ολοκληρώθηκε.")
    return records


def load_from_csv(path, progress_callback=None):
    records = []
    file_size = os.path.getsize(path)

    def progress_percent(percent, msg):
        # Do not call f.tell() while iterating with csv.DictReader.
        # In TextIOWrapper, after next()/CSV iteration, tell() may raise:
        #     OSError: telling position disabled by next() call
        # Use a safe approximate percentage instead.
        if progress_callback:
            progress_callback(max(0.0, min(99.0, float(percent))), msg)

    def parse_optional_float(value):
        if value is None:
            return None
        txt = str(value).strip().replace(',', '.')
        if not txt:
            return None
        try:
            return float(txt)
        except Exception:
            return None

    def parse_optional_int(value, fallback):
        if value is None:
            return fallback
        txt = str(value).strip()
        if not txt:
            return fallback
        try:
            return int(float(txt))
        except Exception:
            return fallback

    def parse_capture_time(value):
        if value is None:
            return None
        txt = str(value).strip()
        if not txt or txt == "(χωρίς timestamp)":
            return None
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%d/%m/%Y %H:%M:%S.%f",
            "%d/%m/%Y %H:%M:%S",
        ):
            try:
                return datetime.strptime(txt, fmt).timestamp()
            except Exception:
                pass
        return None

    def first_existing(row, names):
        for name in names:
            if name in row and row[name] not in (None, ""):
                return row[name]
        return None

    with open(path, 'r', encoding='utf-8-sig', newline='') as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample)
        except Exception:
            dialect = csv.excel

        reader = csv.DictReader(f, dialect=dialect)
        fieldnames = reader.fieldnames or []
        if 'capture_event' in fieldnames:
            raise ValueError('TCP LAB CSV requires the continuity-aware audit')
        approx_bytes_seen = len((dialect.delimiter.join(fieldnames) + "\n").encode('utf-8', errors='ignore'))
        row_count = 0
        for row in reader:
            # Approximate progress without using f.tell() during CSV iteration.
            try:
                approx_line = dialect.delimiter.join(str(row.get(name, "")) for name in fieldnames)
                approx_bytes_seen += len((approx_line + "\n").encode('utf-8', errors='ignore'))
            except Exception:
                approx_bytes_seen += 0

            payload = None
            # Keep the LivePlay recorder column first, so timestamps / frame numbers
            # are not accidentally treated as hex payloads when replaying a saved CSV.
            likely_cols = [
                'udp_payload_hex', 'UDP Payload Hex', 'udp.payload',
                'Message Payload', 'Payload', 'Data', 'Info', 'Hex', 'Bytes',
                'message', 'payload'
            ]
            for col in likely_cols:
                if col in row and row[col]:
                    payload = extract_hex_bytes_from_text(row[col])
                    if payload:
                        break

            if payload is None:
                for value in row.values():
                    if value:
                        payload = extract_hex_bytes_from_text(str(value))
                        if payload:
                            break

            if payload:
                timestamp = parse_optional_float(first_existing(row, [
                    'time_epoch', 'frame.time_epoch', 'timestamp', 'Timestamp', 'Time Epoch'
                ]))
                if timestamp is None:
                    timestamp = parse_capture_time(first_existing(row, [
                        'capture_time', 'Capture Time', 'time', 'Time'
                    ]))

                frame_no = parse_optional_int(first_existing(row, [
                    'frame_no', 'frame.number', 'No.', 'No', 'Frame'
                ]), row_count + 1)

                records.append({
                    'source': 'csv',
                    'timestamp': timestamp,
                    'payload': payload,
                    'frame_no': frame_no,
                    'capture_device': (row.get('capture_device') or '').strip(),
                    'capture_connection': (row.get('capture_connection') or '').strip(),
                    'capture_port': (row.get('capture_port') or '').strip(),
                    'usb_crc_fail_total': parse_optional_int(row.get('usb_crc_fail_total'), None),
                    'usb_framing_error_total': parse_optional_int(row.get('usb_framing_error_total'), None),
                })

            row_count += 1
            if row_count % 500 == 0:
                pct = (approx_bytes_seen / file_size * 100.0) if file_size > 0 else 0.0
                progress_percent(pct, f"Φόρτωση CSV... {row_count} γραμμές")

    if progress_callback:
        progress_callback(100.0, "Η φόρτωση ολοκληρώθηκε.")
    return records



# Classic sequential file analysis.  v8.13 deliberately removes the experimental
# multi-core file analysis path and keeps the original progress behaviour.
def analyze_records(records, progress_callback=None):
    ordered_records = []
    for idx, rec in enumerate(records):
        r = dict(rec)
        r['_index'] = idx
        ordered_records.append(r)

    if ordered_records and all(rec.get('timestamp') is not None for rec in ordered_records):
        ordered_records.sort(key=lambda rec: (rec.get('timestamp'), rec['_index']))

    known_origins = sorted({
        str(rec.get('capture_device', '')).strip()
        for rec in ordered_records if str(rec.get('capture_device', '')).strip()
    })
    known_connections = sorted({
        str(rec.get('capture_connection', '')).strip()
        for rec in ordered_records if str(rec.get('capture_connection', '')).strip()
    })
    known_ports = sorted({
        str(rec.get('capture_port', '')).strip()
        for rec in ordered_records if str(rec.get('capture_port', '')).strip()
    })
    stats = {
        'capture_devices': known_origins,
        'capture_connections': known_connections,
        'capture_ports': known_ports,
        'total_records': len(records),
        'filter_mode': 'UDP only',
        'aircat_like': 0,
        'sector_packets': 0,
        'north_packets': 0,
        'type_counts': {},
        'unknown_prefix_counts': {},
        'unknown_prefix_first_frame': {},
        'rotation_intervals_sec': [],
        'north_intervals_sec': [],
        'good_sector_steps': 0,
        'bad_sector_steps': 0,
        'considered_norths': 0,  # valid + internal invalid only
        'valid_norths': 0,
        'invalid_norths': 0,     # only norths closed by next north with != 32 sectors
        'invalid_north_details': [],
        'ignored_before_first_north': 0,
        'ignored_before_first_north_sectors': 0,
        'ignored_in_invalid_cycles': 0,
        'ignored_in_invalid_cycle_sectors': 0,
        'ignored_eof_cycle_packets': 0,
        'ignored_eof_cycle_sectors': 0,
        'ignored_eof_cycle_north_time': None,
        'ignored_eof_cycle_north_frame_no': None,
        'accepted_records': 0,
        'cycle_results': [],
        'first_valid_north_time': None,
        'last_valid_north_time': None,
        'north_timing_alerts': [],
        'north_protocol_alerts': [],
        'malformed_packets': [],
        'decoder_unmapped_elements': [],
        'missing_sector_counts': {i: 0 for i in range(32)},
        'sector_without_prev_north_counts': {i: 0 for i in range(32)},
        'out_of_order_valid_cycle_counts': {i: 0 for i in range(32)},
        'out_of_order_valid_cycle_events': [],
        'aircat_alert_events': [],
        'aircat_alert_counts': {},
        'aircat_alert_counts_by_source': {},
        # Denominator for AIRCAT alert percentages. Counts decoded target
        # messages by source, so percentages are relative to the available
        # target population (low+high quality), not to the alert row total.
        'aircat_track_counts_by_source': {},
        'tracking_window_counts_by_source': {},
        'smoothing_k_counts_by_source': {},
        'log_sigma_counts_by_source': {},
        # Detailed optional field event rows for the Alerts window.
        # These do not increase alert counters; they are diagnostic tabs with
        # Wireshark frame number and timestamp.
        'tracking_window_events': [],
        'smoothing_k_events': [],
        'log_sigma_events': [],
        'mode_c_byte21_events': [],
        'tpr_counts_by_source': {},
        'mode_a_validation_counts_by_source': {},
        'mode_c_validation_counts_by_source': {},
        'mode_c_byte21_detail_counts_by_source': {},
        'mode_validation_source_counts_by_source': {},
        'psr_service_counts_by_source': {},
        'ssr_code_word_type_counts_by_source': {},
        'special_mode_a_code_counts_by_source': {},
    }

    malformed_packets, decoder_unmapped_elements = analyze_protocol_issues(ordered_records)
    stats['malformed_packets'] = malformed_packets
    stats['decoder_unmapped_elements'] = decoder_unmapped_elements

    total = max(1, len(ordered_records))
    current_cycle = None
    valid_north_times = []
    previous_sector = None

    def _check_protocol_valid_cycle(cycle):
        sector_list = [int(s) for s in cycle.get('sector_packets', []) if s is not None and 0 <= int(s) < 32]
        seen = set(sector_list)
        missing_sectors = [s for s in range(32) if s not in seen]

        if len(sector_list) != 32:
            return False, "sector count != 32", None, None, missing_sectors

        for expected_sector, actual_sector in enumerate(sector_list):
            if actual_sector != expected_sector:
                return False, "sector order != 00..1F", expected_sector, actual_sector, missing_sectors

        return True, "", None, None, missing_sectors

    def _append_protocol_north_alert(cycle, reason, expected_sector=None, actual_sector=None, missing_sectors=None):
        stats['north_protocol_alerts'].append({
            'north_frame_no': cycle.get('north_frame_no'),
            'time': cycle.get('north_time'),
            'sector_count': len(cycle.get('sector_packets', [])),
            'kind': 'north missing valid sectors',
            'reason': reason,
            'expected_sector': expected_sector,
            'actual_sector': actual_sector,
            'missing_sectors': list(missing_sectors or []),
        })

    def _alert_hex(value):
        if value is None:
            return ""
        try:
            return f"0x{int(value) & 0xFF:02X}"
        except Exception:
            return str(value)

    def _track_source_label(track):
        """Return user-facing AIRCAT target source used in alert tables/reports."""
        if not isinstance(track, dict):
            return "Other"
        inferred_source = track.get('inferred_source')
        if inferred_source in ("PSR", "MSSR"):
            return inferred_source
        if track.get('is_cancellation'):
            return "Other"
        try:
            track_type = int(track.get('type') or 0)
        except Exception:
            track_type = 0
        if track_type == 0xFE:
            return "PSR"
        if track_type == 0xFF:
            return "MSSR"
        return "Other"

    def _append_aircat_alert(kind, packet, track, sector=None, detail=""):
        track_no = track.get('track_no') if isinstance(track, dict) else None
        try:
            track_no = int(track_no) if track_no is not None else ""
        except Exception:
            pass

        quality = track.get('quality') if isinstance(track, dict) else None
        quality_max = _track_quality_max(track) if isinstance(track, dict) else None
        quality_txt = ""
        if quality is not None:
            quality_txt = str(quality)
            if quality_max is not None:
                quality_txt = f"{quality}/{quality_max}"

        payload = packet.get('payload', b'') or b''
        track_source = _track_source_label(track)
        evt = {
            'kind': kind,
            'track_source': track_source,
            'frame_no': packet.get('frame_no'),
            'time': packet.get('time'),
            'sector': sector,
            'track_type': _alert_hex(track.get('type')) if isinstance(track, dict) else "",
            'track_no': track_no,
            'mode_a': track.get('mode_a', '') if isinstance(track, dict) else "",
            'mode_c': track.get('mode_c', '') if isinstance(track, dict) else "",
            'quality': quality_txt,
            'service_byte': _alert_hex(track.get('service_byte')) if isinstance(track, dict) else "",
            'validation_byte': _alert_hex(track.get('validation_byte')) if isinstance(track, dict) else "",
            'validation_source': track.get('mode_a_validation_source') or track.get('mode_c_validation_source') or "" if isinstance(track, dict) else "",
            'mode_c_validation_detail': track.get('mode_c_validation_detail', '') if isinstance(track, dict) else "",
            'mode_c_validation_bits': track.get('mode_c_validation_bits', '') if isinstance(track, dict) else "",
            'time_since_north': _format_time_since_north(track.get('time_since_north_sec')) if isinstance(track, dict) else "",
            'tracking_window': track.get('tracking_window', '') if isinstance(track, dict) else "",
            'smoothing_k': track.get('smoothing_k', '') if isinstance(track, dict) else "",
            'details': detail,
            'payload_prefix': payload[:8].hex().upper(),
        }
        stats['aircat_alert_events'].append(evt)
        stats['aircat_alert_counts'][kind] = int(stats['aircat_alert_counts'].get(kind, 0) or 0) + 1
        by_source = stats['aircat_alert_counts_by_source'].setdefault(kind, {})
        by_source[track_source] = int(by_source.get(track_source, 0) or 0) + 1

    def _append_aircat_detail_event(container_key, packet, track, sector=None, detail=""):
        """Append a diagnostic row for optional AIRCAT fields without counting it as an alert."""
        track_no = track.get('track_no') if isinstance(track, dict) else None
        try:
            track_no = int(track_no) if track_no is not None else ""
        except Exception:
            pass

        quality = track.get('quality') if isinstance(track, dict) else None
        quality_max = _track_quality_max(track) if isinstance(track, dict) else None
        quality_txt = ""
        if quality is not None:
            quality_txt = str(quality)
            if quality_max is not None:
                quality_txt = f"{quality}/{quality_max}"

        log_sigma_txt = ""
        if isinstance(track, dict) and track.get('log_sigma_present'):
            try:
                log_sigma_txt = f"{float(track.get('log_sigma_v')):.2f} V"
            except Exception:
                log_sigma_txt = str(track.get('log_sigma_v', ''))

        payload = packet.get('payload', b'') or b''
        validation_source = ""
        if isinstance(track, dict):
            validation_source = track.get('mode_a_validation_source') or track.get('mode_c_validation_source') or ""

        evt = {
            'kind': container_key,
            'track_source': _track_source_label(track),
            'frame_no': packet.get('frame_no'),
            'time': packet.get('time'),
            'sector': sector,
            'track_type': _alert_hex(track.get('type')) if isinstance(track, dict) else "",
            'track_no': track_no,
            'mode_a': track.get('mode_a', '') if isinstance(track, dict) else "",
            'mode_c': track.get('mode_c', '') if isinstance(track, dict) else "",
            'quality': quality_txt,
            'service_byte': _alert_hex(track.get('service_byte')) if isinstance(track, dict) else "",
            'validation_byte': _alert_hex(track.get('validation_byte')) if isinstance(track, dict) else "",
            'validation_source': validation_source,
            'mode_c_validation_detail': track.get('mode_c_validation_detail', '') if isinstance(track, dict) else "",
            'mode_c_validation_bits': track.get('mode_c_validation_bits', '') if isinstance(track, dict) else "",
            'time_since_north': _format_time_since_north(track.get('time_since_north_sec')) if isinstance(track, dict) else "",
            'tracking_window': track.get('tracking_window', '') if isinstance(track, dict) else "",
            'smoothing_k': track.get('smoothing_k', '') if isinstance(track, dict) else "",
            'log_sigma': log_sigma_txt,
            'details': detail,
            'payload_prefix': payload[:8].hex().upper(),
        }
        stats.setdefault(container_key, []).append(evt)

    def _increment_nested_count(container_key, source, bucket):
        if source is None or bucket is None or bucket == "":
            return
        root = stats.setdefault(container_key, {})
        source_counts = root.setdefault(str(source), {})
        source_counts[str(bucket)] = int(source_counts.get(str(bucket), 0) or 0) + 1

    def _increment_aircat_track_denominator(source):
        if source is None or source == "":
            return
        counts = stats.setdefault('aircat_track_counts_by_source', {})
        source_key = str(source)
        counts[source_key] = int(counts.get(source_key, 0) or 0) + 1

    # Track cancellation (FB) records carry a cancelled track number but not an
    # explicit FE/FF source byte. Keep the last decoded source per track number
    # so the report can split cancellations into PSR/MSSR when it is safe.
    analysis_track_source_by_no = {}

    def _track_number_candidates_for_source_inference(track):
        if not isinstance(track, dict):
            return []
        raw_candidates = []
        if track.get('track_no_candidates'):
            raw_candidates.extend(track.get('track_no_candidates') or [])
        elif track.get('track_no') is not None:
            raw_candidates.append(track.get('track_no'))
        out = []
        for candidate in raw_candidates:
            try:
                candidate_i = int(candidate)
            except Exception:
                continue
            if candidate_i not in out:
                out.append(candidate_i)
        return out

    def _infer_cancellation_source_from_previous_tracks(track):
        sources = []
        for candidate in _track_number_candidates_for_source_inference(track):
            source = analysis_track_source_by_no.get(candidate)
            if source in ('PSR', 'MSSR') and source not in sources:
                sources.append(source)
        if len(sources) == 1:
            return sources[0]
        return None

    def _remember_track_source(track, source):
        if source not in ('PSR', 'MSSR'):
            return
        try:
            track_no = int(track.get('track_no'))
        except Exception:
            return
        analysis_track_source_by_no[track_no] = source

    def _collect_aircat_track_alerts(packet, sector=None):
        info = packet.get('info', {}) or {}
        if not (info.get('is_sector') or int(info.get('type', -1) or -1) == 0x0D):
            return

        tracks = _parse_replay_tracks_from_payload(packet.get('payload', b'') or b'')
        for track in tracks:
            if not track:
                continue

            if track.get('is_cancellation'):
                inferred_source = _infer_cancellation_source_from_previous_tracks(track)
                if inferred_source:
                    track = dict(track)
                    track['inferred_source'] = inferred_source
                    detail = f"AIRCAT FB track cancellation message | source inferred from previous track #{track.get('track_no')}"
                else:
                    detail = 'AIRCAT FB track cancellation message | source not inferred'
                _append_aircat_alert('Track cancellation', packet, track, sector, detail)
                continue

            track_source = _track_source_label(track)
            _remember_track_source(track, track_source)
            if not track.get('is_cancellation'):
                _increment_aircat_track_denominator(track_source)
            if track.get('tracking_window'):
                _increment_nested_count('tracking_window_counts_by_source', track_source, track.get('tracking_window'))
                _append_aircat_detail_event(
                    'tracking_window_events',
                    packet,
                    track,
                    sector,
                    f"Tracking Window: {track.get('tracking_window')}"
                )
            if track.get('smoothing_k') is not None:
                _increment_nested_count('smoothing_k_counts_by_source', track_source, track.get('smoothing_k'))
                _append_aircat_detail_event(
                    'smoothing_k_events',
                    packet,
                    track,
                    sector,
                    f"Smoothing K={track.get('smoothing_k')}"
                )
            if track.get('log_sigma_present'):
                _increment_nested_count('log_sigma_counts_by_source', track_source, 'present')
                try:
                    _log_sigma_detail = f"Log Sigma={float(track.get('log_sigma_v')):.2f} V"
                except Exception:
                    _log_sigma_detail = f"Log Sigma={track.get('log_sigma_v')}"
                _append_aircat_detail_event('log_sigma_events', packet, track, sector, _log_sigma_detail)
            if track.get('tpr_number') is not None:
                _increment_nested_count('tpr_counts_by_source', track_source, f"TPR {track.get('tpr_number')}")
            for ssr_code_type in track.get('ssr_code_word_types') or []:
                _increment_nested_count('ssr_code_word_type_counts_by_source', track_source, ssr_code_type)

            special_mode_a_bucket = _special_mode_a_report_bucket(track.get('mode_a'))
            if special_mode_a_bucket:
                _increment_nested_count('special_mode_a_code_counts_by_source', track_source, special_mode_a_bucket)

            if track_source == 'PSR' and track.get('psr_tpr_number') is not None:
                _increment_nested_count('psr_service_counts_by_source', 'PSR', f"TPR {track.get('psr_tpr_number')}")
                if track.get('psr_associated_before'):
                    _increment_nested_count('psr_service_counts_by_source', 'PSR', 'AS combined before')
                if track.get('psr_test_beacon'):
                    _increment_nested_count('psr_service_counts_by_source', 'PSR', 'BT test beacon')
                if track.get('psr_tvd900_test'):
                    _increment_nested_count('psr_service_counts_by_source', 'PSR', 'TVD900 test plot')
                if track.get('psr_invalid_dxdy'):
                    _increment_nested_count('psr_service_counts_by_source', 'PSR', 'Invalid DX/DY')
                if track.get('psr_airport_slow'):
                    _increment_nested_count('psr_service_counts_by_source', 'PSR', 'Slow airport track')
                if track.get('psr_airport_fast'):
                    _increment_nested_count('psr_service_counts_by_source', 'PSR', 'Fast airport/outside track')

            if track.get('mode_a_validation_present'):
                _increment_nested_count('mode_a_validation_counts_by_source', track_source, 'invalid' if track.get('mode_a_invalid') else 'valid')
                _increment_nested_count('mode_validation_source_counts_by_source', track_source, track.get('mode_a_validation_source') or 'unknown')
            if track.get('mode_c_validation_present'):
                _increment_nested_count('mode_c_validation_counts_by_source', track_source, 'invalid' if track.get('mode_c_invalid') else 'valid')
                _increment_nested_count('mode_validation_source_counts_by_source', track_source, track.get('mode_c_validation_source') or 'unknown')
                if track.get('mode_c_validation_source') == 'Byte 21':
                    _increment_nested_count('mode_c_byte21_detail_counts_by_source', track_source, track.get('mode_c_validation_detail') or 'unknown')
                    detail_txt = track.get('mode_c_validation_detail') or 'unknown'
                    bits_txt = track.get('mode_c_validation_bits') or ''
                    suffix = f" | {bits_txt}" if bits_txt else ''
                    _append_aircat_detail_event(
                        'mode_c_byte21_events',
                        packet,
                        track,
                        sector,
                        f"Mode C Byte 21: {detail_txt}{suffix}"
                    )


            if track.get('spi'):
                _append_aircat_alert('SPI', packet, track, sector, 'SSR SPI flag detected')

            if track.get('emergency'):
                _append_aircat_alert('EMG', packet, track, sector, 'SSR emergency P/F state detected')

            special_mode_a = _special_mode_a_alert_info(track)
            if special_mode_a:
                code = special_mode_a.get('code', '')
                desc = special_mode_a.get('description', '')
                _append_aircat_alert(f'Mode A {code}', packet, track, sector, f'Mode A {code}: {desc}')

            if track.get('maneuver'):
                _append_aircat_alert('Maneuver', packet, track, sector, 'Maneuver flag set')

            mode_a_status = track.get('mode_a_status')
            if track.get('mode_a_validation_present') and track.get('mode_a_invalid'):
                src_txt = track.get('mode_a_validation_source') or 'validation'
                _append_aircat_alert('Mode A invalid', packet, track, sector, f"Mode A invalid ({src_txt})")

            mode_c_status = track.get('mode_c_status')
            if track.get('mode_c_validation_present') and track.get('mode_c_invalid'):
                src_txt = track.get('mode_c_validation_source') or 'validation'
                detail_txt = track.get('mode_c_validation_detail') or mode_c_status or 'invalid'
                bits_txt = track.get('mode_c_validation_bits') or ''
                suffix = f" | {bits_txt}" if bits_txt else ''
                _append_aircat_alert('Mode C invalid', packet, track, sector, f"Mode C invalid ({src_txt}): {detail_txt}{suffix}")

            if _is_low_quality_track(track):
                q = track.get('quality')
                qmax = _track_quality_max(track)
                qtxt = f"{q}/{qmax}" if qmax is not None else str(q)
                _append_aircat_alert('Low quality', packet, track, sector, f"Low track quality Q={qtxt}")

    def accept_valid_cycle(cycle):
        nonlocal previous_sector
        stats['considered_norths'] += 1
        stats['valid_norths'] += 1
        valid_north_times.append({'time': cycle['north_time'], 'frame_no': cycle.get('north_frame_no')})
        if stats['first_valid_north_time'] is None:
            stats['first_valid_north_time'] = cycle['north_time']
        stats['last_valid_north_time'] = cycle['north_time']
        stats['cycle_results'].append({'time': cycle['north_time'], 'frame_no': cycle.get('north_frame_no'), 'valid': True})

        expected_sector_in_cycle = 0

        for packet in cycle['packets']:
            info = packet['info']
            payload = packet['payload']
            stats['accepted_records'] += 1
            if info.get('is_aircat_like'):
                stats['aircat_like'] += 1

            type_key = f"0x{info['type']:02X} {info['type_name']}"
            stats['type_counts'][type_key] = stats['type_counts'].get(type_key, 0) + 1
            if info['type'] not in AIRCAT_TYPES:
                prefix = payload[:4].hex().upper()
                stats['unknown_prefix_counts'][prefix] = stats['unknown_prefix_counts'].get(prefix, 0) + 1
                if prefix not in stats['unknown_prefix_first_frame']:
                    stats['unknown_prefix_first_frame'][prefix] = packet.get('frame_no')

            _collect_aircat_track_alerts(packet, sector=info.get('sector'))

            if info.get('is_sector'):
                stats['sector_packets'] += 1
                sector = info['sector']
                if previous_sector is not None:
                    expected = (previous_sector + 1) % 32
                    if sector == expected:
                        stats['good_sector_steps'] += 1
                    else:
                        stats['bad_sector_steps'] += 1
                previous_sector = sector

                if sector is not None and 0 <= int(sector) < 32:
                    sector_i = int(sector)
                    if sector_i != expected_sector_in_cycle:
                        stats['out_of_order_valid_cycle_counts'][sector_i] += 1
                        stats['out_of_order_valid_cycle_events'].append({
                            'frame_no': packet.get('frame_no'),
                            'time': cycle.get('north_time'),
                            'north_frame_no': cycle.get('north_frame_no'),
                            'expected_sector': expected_sector_in_cycle,
                            'actual_sector': sector_i,
                        })
                    expected_sector_in_cycle = (sector_i + 1) % 32

            if info.get('is_north'):
                stats['north_packets'] += 1

        protocol_valid, protocol_reason, protocol_expected, protocol_actual, protocol_missing = _check_protocol_valid_cycle(cycle)
        if not protocol_valid:
            # A count of 32 does NOT guarantee 32 different sectors. A
            # repeated sector can replace a missing one without changing the
            # number of packets, so account for absent IDs here as well.
            for missing_sector in protocol_missing:
                stats['missing_sector_counts'][missing_sector] += 1
            _append_protocol_north_alert(
                cycle,
                protocol_reason,
                expected_sector=protocol_expected,
                actual_sector=protocol_actual,
                missing_sectors=protocol_missing,
            )

    def reject_internal_invalid_cycle(cycle):
        stats['considered_norths'] += 1
        stats['invalid_norths'] += 1
        sector_count = len(cycle['sector_packets'])
        stats['ignored_in_invalid_cycles'] += len(cycle['packets'])
        stats['ignored_in_invalid_cycle_sectors'] += sector_count
        reason = ('Βρέθηκε επόμενο North πριν συμπληρωθούν 32 sectors'
                  if sector_count < 32 else 'Επιπλέον/διπλοί sectors πριν από το επόμενο North')

        sector_list = [int(s) for s in cycle['sector_packets'] if s is not None and 0 <= int(s) < 32]

        # Split the received sectors into scan buckets. The first bucket belongs to the
        # explicit north of the cycle. Every later bucket is treated as a scan without
        # a preceding north signal.
        buckets = []
        current_bucket = []
        prev_sector_local = None
        for sector in sector_list:
            # Duplicate/out-of-order sectors do not begin new scans.
            looks_like_scan_wrap = (prev_sector_local is not None and 0 <= sector <= 7
                                    and prev_sector_local >= 20 and prev_sector_local - sector >= 16)
            if current_bucket and looks_like_scan_wrap:
                buckets.append(current_bucket)
                current_bucket = [sector]
            else:
                current_bucket.append(sector)
            prev_sector_local = sector
        if current_bucket:
            buckets.append(current_bucket)

        main_bucket = buckets[0] if buckets else []
        seen_main = set(main_bucket)
        missing_sectors = [s for s in range(32) if s not in seen_main]
        for sector in missing_sectors:
            stats['missing_sector_counts'][sector] += 1

        sectors_without_prev_north = []
        for extra_bucket in buckets[1:]:
            for sector in extra_bucket:
                stats['sector_without_prev_north_counts'][sector] += 1
                sectors_without_prev_north.append(sector)

        stats['cycle_results'].append({'time': cycle['north_time'], 'frame_no': cycle.get('north_frame_no'), 'valid': False})
        stats['invalid_north_details'].append({
            'frame_no': cycle.get('north_frame_no'),
            'time': cycle['north_time'],
            'sector_count': sector_count,
            'reason': reason,
            'missing_sectors': missing_sectors,
            'sector_without_prev_north': sectors_without_prev_north,
        })

        protocol_valid, protocol_reason, protocol_expected, protocol_actual, protocol_missing = _check_protocol_valid_cycle(cycle)
        if not protocol_valid:
            _append_protocol_north_alert(
                cycle,
                protocol_reason,
                expected_sector=protocol_expected,
                actual_sector=protocol_actual,
                missing_sectors=protocol_missing,
            )

    def reject_eof_incomplete_cycle(cycle):
        # Anything after the last valid North of the capture is ignored completely.
        # It does NOT contribute to:
        #   - missing_sector_counts
        #   - sector_without_prev_north_counts
        #   - out_of_order_valid_cycle_counts
        stats['ignored_eof_cycle_packets'] += len(cycle['packets'])
        stats['ignored_eof_cycle_sectors'] += len(cycle['sector_packets'])
        stats['ignored_eof_cycle_north_time'] = cycle['north_time']
        stats['ignored_eof_cycle_north_frame_no'] = cycle.get('north_frame_no')

    def finalize_cycle(cycle, closed_by_eof=False):
        if cycle is None:
            return
        sector_count = len(cycle['sector_packets'])
        if sector_count == 32:
            accept_valid_cycle(cycle)
        else:
            if closed_by_eof:
                reject_eof_incomplete_cycle(cycle)
            else:
                reject_internal_invalid_cycle(cycle)

    for idx, rec in enumerate(ordered_records, start=1):
        current_payload = rec['payload']
        info = classify_aircat_payload(current_payload)

        if not info:
            if current_cycle is None:
                stats['ignored_before_first_north'] += 1
            else:
                current_cycle['packets'].append({
                    'payload': current_payload,
                    'frame_no': rec.get('frame_no'),
                    'time': rec.get('timestamp'),
                    'info': {
                        'type': current_payload[0] if current_payload else 0,
                        'type_name': 'Unknown',
                        'is_aircat_like': False,
                        'is_sector': False,
                        'is_north': False,
                    }
                })
            continue

        if current_cycle is None:
            if info['is_north']:
                current_cycle = {
                    'north_time': rec.get('timestamp'),
                    'north_frame_no': rec.get('frame_no'),
                    'packets': [{'payload': current_payload, 'frame_no': rec.get('frame_no'), 'time': rec.get('timestamp'), 'info': info}],
                    'sector_packets': [],
                }
            else:
                # Anything before the first North is ignored completely.
                # It does NOT contribute to sector_without_prev_north or any other
                # per-sector error counters.
                stats['ignored_before_first_north'] += 1
                if info['is_sector']:
                    stats['ignored_before_first_north_sectors'] += 1
        else:
            if info['is_north']:
                previous_cycle = current_cycle
                current_cycle = {
                    'north_time': rec.get('timestamp'),
                    'north_frame_no': rec.get('frame_no'),
                    'packets': [{'payload': current_payload, 'frame_no': rec.get('frame_no'), 'time': rec.get('timestamp'), 'info': info}],
                    'sector_packets': [],
                }
                finalize_cycle(previous_cycle, closed_by_eof=False)
            else:
                current_cycle['packets'].append({'payload': current_payload, 'frame_no': rec.get('frame_no'), 'time': rec.get('timestamp'), 'info': info})
                if info['is_sector']:
                    current_cycle['sector_packets'].append(info['sector'])

        if progress_callback and idx % 500 == 0:
            progress_callback((idx / total) * 100.0, f"Ανάλυση... {idx}/{total} packets")

    if current_cycle is not None:
        finalize_cycle(current_cycle, closed_by_eof=True)

    # North timing must be based on consecutive real North signals, not only on
    # consecutive *valid* cycles.  If a cycle has a sector missing problem but
    # its North was actually received, that North must remain a timing reference.
    # Otherwise the next valid North may look like a doubled interval and create
    # a false Scan missed.  Use all North cycle_results inside the valid capture
    # period, including invalid sector cycles, and keep EOF partial cycles out.
    north_points = [c for c in stats['cycle_results'] if c.get('time') is not None]
    first_valid_time = stats.get('first_valid_north_time')
    last_valid_time = stats.get('last_valid_north_time')
    if first_valid_time is not None and last_valid_time is not None:
        north_points = [
            c for c in north_points
            if first_valid_time <= c.get('time') <= last_valid_time
        ]

    for i in range(1, len(north_points)):
        prev_cycle = north_points[i - 1]
        curr_cycle = north_points[i]
        delta = curr_cycle['time'] - prev_cycle['time']
        if delta > 0:
            stats['north_intervals_sec'].append(delta)
            stats['rotation_intervals_sec'].append(delta)

    expected_interval = safe_median(stats['north_intervals_sec'])
    if expected_interval and expected_interval > 0:
        for i in range(1, len(north_points)):
            dt = north_points[i]['time'] - north_points[i - 1]['time']
            if dt <= 0:
                continue
            ratio = dt / expected_interval
            if ratio > 1.05 or ratio < 0.95:
                if ratio > 1.05:
                    est_cycles = max(1, round(ratio))
                    missed = max(est_cycles - 1, 0)
                else:
                    missed = 0
                stats['north_timing_alerts'].append({
                    'frame_no_prev': north_points[i - 1].get('frame_no'),
                    'time_prev': north_points[i - 1]['time'],
                    'frame_no_curr': north_points[i].get('frame_no'),
                    'time_curr': north_points[i]['time'],
                    'interval': dt,
                    'ratio': ratio,
                    'estimated_missed_scans': missed,
                    'kind': "north missed time",
                })

    collect_usb_capture_diagnostics(ordered_records, stats)

    if progress_callback:
        progress_callback(100.0, "Η ανάλυση ολοκληρώθηκε.")
    return stats



def _north_timing_scan_missed_alerts(stats):
    """North timing alerts that represent a real missed scan, not simple jitter."""
    alerts = stats.get('north_timing_alerts', []) or []
    result = []
    for item in alerts:
        try:
            ratio = float(item.get('ratio') or 0.0)
        except Exception:
            ratio = 0.0
        if ratio > 1.9:
            result.append(item)
    return result


def _north_timing_jitter_alerts(stats):
    """North timing alerts with >=5% timing variation, excluding real scan misses."""
    alerts = stats.get('north_timing_alerts', []) or []
    result = []
    for item in alerts:
        try:
            ratio = float(item.get('ratio') or 0.0)
        except Exception:
            ratio = 0.0
        variation_pct = abs(ratio - 1.0) * 100.0
        if round(variation_pct, 1) > 5.0 and ratio <= 1.9:
            result.append(item)
    return result


def count_distinct_scan_faults(stats):
    """Count fault occurrences without counting an incomplete cycle twice.

    A missing sector is one observable fault. The NORTH cycle containing that
    sector is an *affected cycle*, not another independent fault. A protocol
    alert with zero absent sectors (e.g. duplicate/order-only issue) is counted
    once, since it otherwise has no sector-missing entry. Scan missed is a
    separate North timing fault. The result is an event count, not a diagnosis
    of the physical cause.
    """
    missing = sum(int(v or 0) for v in (stats.get('missing_sector_counts') or {}).values())
    timing = len(_north_timing_scan_missed_alerts(stats))
    protocol_without_missing = sum(
        1 for item in (stats.get('north_protocol_alerts') or [])
        if not item.get('missing_sectors')
    )
    return timing + missing + protocol_without_missing


def collect_usb_capture_diagnostics(records, stats):
    """Recover reader-side CRC/framing telemetry from new LivePlay CSV rows.

    Bad CRC BSC frames are never forwarded to the radar payload decoder, so
    the offline decoder cannot see them in a CSV of CRC-valid payloads. New
    recordings therefore carry a cumulative snapshot on each accepted row.
    Older CSV files have no such columns and explicitly remain 'unavailable'.
    """
    samples = [r for r in records
               if r.get('usb_crc_fail_total') is not None and
               r.get('usb_framing_error_total') is not None]
    if not samples:
        stats['usb_diagnostics_available'] = False
        return
    stats['usb_diagnostics_available'] = True
    stats['usb_crc_fail_delta'] = max(0, int(samples[-1]['usb_crc_fail_total']) -
                                       int(samples[0]['usb_crc_fail_total']))
    stats['usb_framing_delta'] = max(0, int(samples[-1]['usb_framing_error_total']) -
                                     int(samples[0]['usb_framing_error_total']))
    # For each invalid North-to-North cycle, identify missing sector IDs that
    # coincide with CRC/framing failures inside that interval. Correlation is
    # NOT proof of the source of the loss.
    norths = []
    for rec in samples:
        info = classify_aircat_payload(rec.get('payload') or b'')
        if info and info.get('is_north'):
            norths.append(rec)
    pending = {int(e['frame_no']): e
               for e in stats.get('invalid_north_details', [])
               if e.get('frame_no') is not None}
    suspect = 0
    for start, end in zip(norths, norths[1:]):
        alert = pending.get(int(start.get('frame_no') or -1))
        if not alert:
            continue
        failed = (int(end['usb_crc_fail_total']) > int(start['usb_crc_fail_total']) or
                  int(end['usb_framing_error_total']) > int(start['usb_framing_error_total']))
        if failed:
            suspect += len(set(alert.get('missing_sectors') or []))
    stats['usb_crc_associated_sector_gaps'] = suspect


def build_report(stats, filename):
    lines = []

    def _as_int(value):
        try:
            return int(value or 0)
        except Exception:
            return 0

    def _pct(num, den):
        try:
            return (float(num) / float(den) * 100.0) if den else 0.0
        except Exception:
            return 0.0

    def _format_error_interval(count, duration_seconds):
        """Format an error rate as one event per elapsed time interval."""
        count_i = _as_int(count)
        try:
            duration_seconds = float(duration_seconds or 0.0)
        except Exception:
            duration_seconds = 0.0

        if count_i <= 0:
            return "0"
        if duration_seconds <= 0:
            return "n/a"

        interval_sec = max(1.0, duration_seconds / float(count_i))

        if interval_sec < 60.0:
            secs = max(1, int(round(interval_sec)))
            unit = "δευτερόλεπτο" if secs == 1 else "δευτερόλεπτα"
            return f"1/{secs} {unit}"

        total_minutes = max(1, int(round(interval_sec / 60.0)))
        if total_minutes < 60:
            unit = "λεπτό" if total_minutes == 1 else "λεπτά"
            return f"1/{total_minutes}{unit}"

        hours = total_minutes // 60
        minutes = total_minutes % 60
        hour_unit = "ώρα" if hours == 1 else "ώρες"
        if minutes:
            minute_unit = "λεπτό" if minutes == 1 else "λεπτά"
            return f"1/{hours}{hour_unit} και {minutes} {minute_unit}"
        return f"1/{hours}{hour_unit}"

    def _alert_line(label, psr, mssr, other, total, denominator_by_source=None):
        total_i = _as_int(total)
        denominator_by_source = denominator_by_source or {}

        def _den(name):
            return _as_int(denominator_by_source.get(name, 0))

        def _alert_part(name, value, width):
            value_i = _as_int(value)
            den_i = _den(name)
            if value_i and den_i:
                return f"{name}={value_i:<5} ({_pct(value_i, den_i):5.1f}%)".ljust(width)
            return f"{name}={value_i:<5}".ljust(width)

        total_den = _den('Total')
        if total_i and total_den:
            total_txt = f"Total={total_i} ({_pct(total_i, total_den):.1f}%)"
        else:
            total_txt = f"Total={total_i}"

        return (
            f"  {label + ':':<24} "
            f"{_alert_part('PSR', psr, 21)} | "
            f"{_alert_part('MSSR', mssr, 22)} | "
            f"{_alert_part('Other', other, 21)} | "
            f"{total_txt}"
        )

    def _source_counts_line(source, tpr1, tpr2):
        total_src = _as_int(tpr1) + _as_int(tpr2)
        return f"  {source + ':':<5} TPR 1={_as_int(tpr1):<2} | TPR 2={_as_int(tpr2):>7}  | Total={total_src}"

    total_records = _as_int(stats.get('total_records'))
    stats_base = _as_int(stats.get('accepted_records')) if _as_int(stats.get('accepted_records')) else total_records

    first_ts = stats.get('first_valid_north_time')
    last_ts = stats.get('last_valid_north_time')
    duration_hours = None
    duration_seconds = None
    duration_txt = "n/a"
    if first_ts is not None and last_ts is not None:
        duration_txt = format_duration_greek(first_ts, last_ts)
        if last_ts > first_ts:
            duration_seconds = last_ts - first_ts
            duration_hours = duration_seconds / 3600.0

    known_sum = 0
    unknown_sum = 0
    for key, count in sorted((stats.get('type_counts') or {}).items(), key=lambda x: (-_as_int(x[1]), x[0])):
        if 'Unknown' in str(key):
            unknown_sum += _as_int(count)
        else:
            known_sum += _as_int(count)

    processor_state_0x1c_packets = _as_int((stats.get('type_counts') or {}).get('0x1C Processor State'))

    considered_norths = _as_int(stats.get('considered_norths'))
    valid_norths = _as_int(stats.get('valid_norths'))
    invalid_norths = _as_int(stats.get('invalid_norths'))
    valid_pct = _pct(valid_norths, considered_norths)
    invalid_pct = _pct(invalid_norths, considered_norths)

    good_sector_steps = _as_int(stats.get('good_sector_steps'))
    bad_sector_steps = _as_int(stats.get('bad_sector_steps'))
    total_transitions = good_sector_steps + bad_sector_steps
    ok_pct = _pct(good_sector_steps, total_transitions)

    missing_sector_counts = stats.get('missing_sector_counts', {}) or {}
    sector_without_prev_north_counts = stats.get('sector_without_prev_north_counts', {}) or {}
    out_of_order_valid_cycle_counts = stats.get('out_of_order_valid_cycle_counts', {}) or {}

    total_missing_sector = sum(_as_int(v) for v in missing_sector_counts.values())
    total_sector_without_prev_north = sum(_as_int(v) for v in sector_without_prev_north_counts.values())
    total_out_of_order_valid = sum(_as_int(v) for v in out_of_order_valid_cycle_counts.values())
    total_scan_missed = len(_north_timing_scan_missed_alerts(stats))
    total_north_missing_valid_sectors = len(stats.get('north_protocol_alerts', []) or [])
    total_invalid_north_cycles = total_scan_missed + total_north_missing_valid_sectors
    total_errors = count_distinct_scan_faults(stats)

    lines.append(f"Αρχείο: {filename}")
    if stats.get('capture_devices'):
        lines.append('Συσκευή καταγραφής: ' + ', '.join(stats['capture_devices']))
    else:
        lines.append('Συσκευή καταγραφής: μη διαθέσιμη στα δεδομένα του αρχείου')
    if stats.get('capture_connections'):
        lines.append('Διεπαφή: ' + ', '.join(stats['capture_connections']))
    if stats.get('capture_ports'):
        lines.append('Θύρα / Προσαρμογέας: ' + ', '.join(stats['capture_ports']))
    lines.append(f"Ημερομηνία ανάλυσης: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Filter: {stats.get('filter_mode', 'UDP packets only')}")
    lines.append("=" * 82)

    if first_ts is not None and last_ts is not None:
        lines.append(f"Περίοδος valid καταγραφής: {format_capture_time(first_ts)} -> {format_capture_time(last_ts)}")
        lines.append(f"Διάρκεια: {duration_txt}")
    lines.append("")

    lines.append(f"Packets φορτωμένα: {total_records}")
    lines.append(f"Ignored before first North: {_as_int(stats.get('ignored_before_first_north'))}")
    lines.append(f"Ignored after last valid North / EOF partial cycle: {_as_int(stats.get('ignored_eof_cycle_packets'))}")
    lines.append("")

    if stats.get('rotation_intervals_sec'):
        avg_rot = safe_mean(stats.get('rotation_intervals_sec') or [])
        min_rot = safe_min(stats.get('rotation_intervals_sec') or [])
        max_rot = safe_max(stats.get('rotation_intervals_sec') or [])
        rpm = 60.0 / avg_rot if avg_rot and avg_rot > 0 else None
        lines.append("Στατιστικά περιστροφής με βάση τα valid North messages:")
        lines.append(f"  Min:  {fmt_float(min_rot, 1)} s")
        lines.append(f"  Avg:  {fmt_float(avg_rot, 1)} s")
        lines.append(f"  Max:  {fmt_float(max_rot, 1)} s")
        lines.append(f"  Calculated RPM: {fmt_float(rpm, 1)}")
        lines.append("")

    lines.append("Σύνοψη μηνυμάτων:")
    aircat_like = _as_int(stats.get('aircat_like'))
    aircat_pct = _pct(aircat_like, stats_base)
    lines.append(f"  AIRCAT-like: {aircat_like} ({aircat_pct:.2f}%)")
    lines.append(f"  Known:       {known_sum:<8}")
    lines.append(f"  Sector:      {_as_int(stats.get('sector_packets')):<7}")
    lines.append(f"| Unknown:     {unknown_sum}")
    lines.append("    Τύποι: ")

    known_type_items = []
    unknown_type_total = 0
    for key, count in sorted((stats.get('type_counts') or {}).items(), key=lambda x: (-_as_int(x[1]), x[0])):
        if 'Unknown' in str(key):
            unknown_type_total += _as_int(count)
        elif str(key) == '0x1C Processor State':
            # Processor State is reported explicitly just before Unknown types.
            continue
        else:
            known_type_items.append((key, _as_int(count)))

    # Keep all message-type counts visually aligned in one fixed column.
    # This avoids the count shifting left/right when the capture is small
    # (e.g. 98/314) or large (e.g. 558272).
    type_count_column = 32

    def _format_type_report_line(label, count, pct):
        prefix = f"    {label}="
        spaces = max(1, type_count_column - len(prefix))
        return f"{prefix}{' ' * spaces}{count} ({pct:.2f}%)"

    for key, count in known_type_items:
        pct = _pct(count, stats_base)
        lines.append(_format_type_report_line(key, count, pct))

    # Show Processor State 0x1C as part of the type list, immediately before Unknown.
    processor_pct = _pct(processor_state_0x1c_packets, stats_base)
    lines.append(_format_type_report_line("0x1C Processor State", processor_state_0x1c_packets, processor_pct))

    if unknown_type_total:
        pct_unknown_types = _pct(unknown_type_total, stats_base)
        lines.append(_format_type_report_line("Unknown types", unknown_type_total, pct_unknown_types))
    lines.append("")

    lines.append("Σύνοψη κύκλων North / sectors:")
    lines.append(f"  North examined:   {considered_norths}")
    lines.append(f"  valid 32 sectors: {valid_norths} ({valid_pct:.2f}%)")
    lines.append(f"  invalid:          {invalid_norths} ({invalid_pct:.2f}%)")
    if total_transitions:
        lines.append(f"  Accepted sector sequence OK: {good_sector_steps} ({ok_pct:.2f}%)")
        lines.append(f"  Discontinuities: {bad_sector_steps}")
    lines.append("")

    lines.append("Σύνοψη σφαλμάτων:")
    lines.append(f"  Scan missed:                 {total_scan_missed}")
    lines.append(f"  North missing valid sectors: {total_north_missing_valid_sectors}")
    lines.append(f"  Invalid North cycles:        {total_invalid_north_cycles}")
    lines.append("")
    lines.append(f"  Sector missing συνολικά   :  {total_missing_sector}")
    lines.append(f"  Sector without prev North :  {total_sector_without_prev_north}")
    lines.append(f"  Out-of-order sectors μέσα σε valid cycle συνολικά: {total_out_of_order_valid}")
    lines.append(f"  Συνολικά σφάλματα (χωρίς διπλομέτρηση): {total_errors}")
    lines.append("  Σημ.: Invalid North cycles = διαγνωστικός αριθμός επηρεασμένων κύκλων,")
    lines.append("         όχι πρόσθετα σφάλματα πάνω από τα missing sectors.")
    lines.append("  Για λεπτομέρειες ανά sector ανατρέξτε στα ραβδοδιαγράμματα.")
    lines.append("")

    if stats.get('usb_record_sidecar'):
        side = stats['usb_record_sidecar']
        device_name = 'SYNC2WIFI' if side.get('capture_device') == 'SYNC2WIFI' else 'SYNC2USB'
        lines.append(f"{device_name} — πλήρεις μετρητές από το Record sidecar:")
        if device_name == 'SYNC2WIFI':
            lines.append(f"  Wi-Fi UDP packets received:  {_as_int(side.get('wifi_udp_packets_received'))}")
            lines.append(f"  Wi-Fi UDP packets lost:      {_as_int(side.get('wifi_udp_packets_lost'))}")
            lines.append(f"  Wi-Fi UDP invalid:           {_as_int(side.get('wifi_udp_invalid'))}")
            lines.append(f"  Wi-Fi UDP CRC32 rejected:    {_as_int(side.get('wifi_udp_crc32_bad'))}")
            lines.append(f"  Wi-Fi UDP duplicate ignored: {_as_int(side.get('wifi_udp_duplicates'))}")
            lines.append(f"  Firmware overflow total:     {_as_int(side.get('wifi_firmware_overflow'))}")
            if side.get('wifi_firmware_overflow_since_connect') is not None:
                lines.append(f"  Firmware overflow since link: {_as_int(side.get('wifi_firmware_overflow_since_connect'))}")
        lines.append(f"  CRC FAIL στην καταγραφή:       {_as_int(side.get('crc_errors_during_recording'))}")
        lines.append(f"  BSC framing στην καταγραφή:    {_as_int(side.get('framing_errors_during_recording'))}")
        lines.append(f"  Sector gaps κοντά σε σφάλματα: {_as_int(side.get('crc_associated_sector_gaps_during_recording'))}")
        lines.append("  Τα gap IDs δεν προστίθενται στα missing sectors δεύτερη φορά.")
        lines.append("  Τα απορριφθέντα CRC frames δεν καταγράφονται ως payload στο CSV.")
        lines.append("  Η ένδειξη συσχέτισης δεν αποδεικνύει βλάβη του μετατροπέα.")
        lines.append("")
    elif stats.get('usb_diagnostics_available'):
        lines.append("USB / SYNC2USB — διαγνωστικά καταγραφής:")
        lines.append(f"  CRC FAIL (μεταβολή μετρητή): {stats.get('usb_crc_fail_delta', 0)}")
        lines.append(f"  BSC framing (μεταβολή):      {stats.get('usb_framing_delta', 0)}")
        lines.append(f"  Missing sector IDs κοντά σε CRC/framing: {stats.get('usb_crc_associated_sector_gaps', 0)}")
        lines.append("  Τα απορριφθέντα CRC frames δεν υπάρχουν ως payload rows στο CSV.")
        lines.append("  Τα CRC-suspect gaps είναι συσχέτιση, ΟΧΙ επιπλέον missing sectors")
        lines.append("  ούτε απόδειξη αιτίας (RADAR / μετατροπέας / USB / PC).")
        lines.append("  Οι μετρητές περιγράφουν το διάστημα των αποθηκευμένων έγκυρων frames.")
        lines.append("")
    elif 'SYNC2USB' in ' '.join(stats.get('capture_devices') or []):
        lines.append("USB / SYNC2USB: δεν υπάρχουν CRC diagnostics σε αυτό το παλαιότερο CSV.")
        lines.append("  Το LivePlay αποθηκεύει μόνο CRC-valid payloads: τα απορριφθέντα")
        lines.append("  CRC frames δεν μπορούν να ανακτηθούν από αυτή την καταγραφή.")
        lines.append("")

    lines.append("Πίνακες σφαλμάτων:")
    lines.append(f"  Scan missed alerts:            {total_scan_missed}")
    lines.append(f"  Protocol / sector-count alerts:{len(stats.get('north_protocol_alerts', []) or [])}")
    lines.append(f"  Malformed packets: {len(stats.get('malformed_packets', []) or [])}")
    lines.append(f"  Decoder unmapped elements: {len(stats.get('decoder_unmapped_elements', []) or [])}")
    lines.append("  Για αναλυτικές εγγραφές χρησιμοποίησε το κουμπί «Πίνακες σφαλμάτων».")
    lines.append("")

    if duration_seconds and duration_seconds > 0:
        lines.append("Μέση τιμή Ρυθμού σφαλμάτων:")
        lines.append(f"  {'Scan missed':<34}{_format_error_interval(total_scan_missed, duration_seconds)}")
        lines.append(f"  {'North missing valid sectors':<34}{_format_error_interval(total_north_missing_valid_sectors, duration_seconds)}")
        lines.append(f"  {'Invalid North cycles (diagn.)':<34}{_format_error_interval(total_invalid_north_cycles, duration_seconds)}")
        lines.append(f"  {'Σφάλματα χωρίς διπλομέτρηση':<34}{_format_error_interval(total_errors, duration_seconds)}")
        lines.append("  Οι ρυθμοί των επιμέρους διαγνωστικών δεν αθροίζονται.")
        lines.append("")

    if stats.get('unknown_prefix_counts'):
        total_unknown_prefix_packets = sum(_as_int(v) for v in (stats.get('unknown_prefix_counts') or {}).values())
        unique_unknown_prefixes = len(stats.get('unknown_prefix_counts') or {})
        pct_unknown_prefix_packets = _pct(total_unknown_prefix_packets, stats_base)
        lines.append(f"Άλλα / άγνωστα prefixes αθροιστικά: {total_unknown_prefix_packets} packets ({pct_unknown_prefix_packets:.2f}%) | unique prefixes: {unique_unknown_prefixes}")
        lines.append("  Για αναλυτικά prefixes ανατρέξτε στους Πίνακες σφαλμάτων -> Unknown prefixes.")
        lines.append("")

    alert_counts = stats.get('aircat_alert_counts', {}) or {}
    alert_counts_by_source = stats.get('aircat_alert_counts_by_source', {}) or {}
    alert_denominator_by_source = {
        'PSR': _as_int((stats.get('aircat_track_counts_by_source') or {}).get('PSR')),
        'MSSR': _as_int((stats.get('aircat_track_counts_by_source') or {}).get('MSSR')),
        'Other': _as_int((stats.get('aircat_track_counts_by_source') or {}).get('Other')),
    }
    alert_denominator_by_source['Total'] = sum(alert_denominator_by_source.values())
    lines.append("Σύνοψη AIRCAT alerts:")
    if alert_counts:
        alert_order = [
            'Low quality', 'Maneuver', 'Track cancellation', 'SPI', 'EMG',
            'Mode A 7500', 'Mode A 7600', 'Mode A 7601', 'Mode A 7700'
        ]
        seen_alerts = set()
        for alert_kind in alert_order:
            if alert_kind not in alert_counts:
                continue
            split = alert_counts_by_source.get(alert_kind, {}) or {}
            lines.append(_alert_line(('Low quality <95/127' if alert_kind == 'Low quality' else alert_kind), split.get('PSR', 0), split.get('MSSR', 0), split.get('Other', 0), alert_counts.get(alert_kind, 0), alert_denominator_by_source))
            seen_alerts.add(alert_kind)
        for alert_kind, alert_count in sorted(alert_counts.items(), key=lambda x: (-_as_int(x[1]), x[0])):
            if alert_kind in seen_alerts:
                continue
            split = alert_counts_by_source.get(alert_kind, {}) or {}
            lines.append(_alert_line(('Low quality <95/127' if alert_kind == 'Low quality' else alert_kind), split.get('PSR', 0), split.get('MSSR', 0), split.get('Other', 0), alert_count, alert_denominator_by_source))
    else:
        lines.append("  Δεν βρέθηκαν AIRCAT alerts.")
    lines.append("  Για αναλυτικές εγγραφές χρησιμοποίησε το κουμπί «Alerts».")
    lines.append("")

    tpr_counts = stats.get('tpr_counts_by_source', {}) or {}
    lines.append("Σύνοψη TPR source (αθροιστικά):")
    if tpr_counts:
        for source in ('PSR', 'MSSR', 'Other'):
            src_counts = tpr_counts.get(source, {}) or {}
            if not src_counts:
                continue
            lines.append(_source_counts_line(source, src_counts.get('TPR 1', 0), src_counts.get('TPR 2', 0)))
    else:
        lines.append("  Δεν βρέθηκαν TPR στοιχεία σε αυτό το αρχείο/capture.")
    lines.append("")

    psr_service_counts = stats.get('psr_service_counts_by_source', {}) or {}
    lines.append("Σύνοψη PSR service byte (αθροιστικά μόνο):")
    psr_counts = psr_service_counts.get('PSR', {}) if isinstance(psr_service_counts, dict) else {}
    if psr_counts:
        tpr1 = _as_int(psr_counts.get('TPR 1'))
        tpr2 = _as_int(psr_counts.get('TPR 2'))
        total_psr_service = tpr1 + tpr2
        lines.append(f"  PSR service records: Total={total_psr_service} | TPR 1={tpr1} | TPR 2={tpr2}")
        lines.append("  Flags: ")
        lines.append(f"       AS combined before={_as_int(psr_counts.get('AS combined before'))}")
        lines.append(f"       BT test beacon={_as_int(psr_counts.get('BT test beacon'))}")
        lines.append(f"       TVD900 test plot={_as_int(psr_counts.get('TVD900 test plot'))}")
        lines.append(f"       Invalid DX/DY={_as_int(psr_counts.get('Invalid DX/DY'))}")
        lines.append(f"       Slow airport track={_as_int(psr_counts.get('Slow airport track'))}")
        lines.append(f"       Fast airport/outside track={_as_int(psr_counts.get('Fast airport/outside track'))}")
    else:
        lines.append("  Δεν βρέθηκαν PSR service byte στοιχεία σε αυτό το αρχείο/capture.")
    lines.append("")

    def _validation_report_lines(title, counts_key):
        counts_root = stats.get(counts_key, {}) or {}
        lines.append(title)
        if counts_root:
            for source in ('PSR', 'MSSR', 'Other'):
                src_counts = counts_root.get(source, {}) or {}
                if not src_counts:
                    continue
                valid = _as_int(src_counts.get('valid'))
                invalid = _as_int(src_counts.get('invalid'))
                total_val = valid + invalid
                pct_invalid = _pct(invalid, total_val)
                lines.append(f"  {source}: valid={valid} | invalid={invalid} | Total={total_val} | invalid={pct_invalid:.2f}%")
            source_counts = stats.get('mode_validation_source_counts_by_source', {}) or {}
            source_parts = []
            for source in ('PSR', 'MSSR', 'Other'):
                src = source_counts.get(source, {}) or {}
                if src:
                    source_parts.append(f"{source}: " + ", ".join(f"{k}={_as_int(v)}" for k, v in sorted(src.items())))
            if source_parts:
                lines.append("  Sources: " + " | ".join(source_parts))
        else:
            lines.append("  Not transmitted / not available in this capture.")
        lines.append("")

    _validation_report_lines("Σύνοψη Mode A validation (dynamic):", 'mode_a_validation_counts_by_source')
    _validation_report_lines("Σύνοψη Mode C validation (dynamic):", 'mode_c_validation_counts_by_source')

    special_mode_a_counts = stats.get('special_mode_a_code_counts_by_source', {}) or {}
    lines.append("Special Mode A/3 Transponder Codes:")
    if special_mode_a_counts:
        display_pairs = [
            ('7000 VFR', '7000 VFR'),
            ('7500 Unlawful interference / hijack', '7500 Unlawful interference/hijack'),
            ('7600 Radio communication failure', '7600 Radio communication failure'),
            ('7601 Radio IFR/VMC failure', '7601 Radio IFR/VMC failure'),
            ('7700 General emergency', '7700 General emergency'),
            ('Other Mode A/3 codes', 'Other Mode A/3 codes'),
        ]
        for source in ('MSSR', 'PSR', 'Other'):
            src_counts = special_mode_a_counts.get(source, {}) or {}
            if not src_counts:
                continue
            total_src = sum(_as_int(v) for v in src_counts.values())
            lines.append(f"{source}: ")
            for key, label in display_pairs:
                lines.append(f"{label + ':':<38}{_as_int(src_counts.get(key))}")
            lines.append("-" * 42)
            lines.append(f"{'Total=':<38}{total_src}")
            lines.append("")
    else:
        lines.append("Δεν βρέθηκαν Mode A/3 transponder codes σε αυτό το αρχείο/capture.")
        lines.append("")

    ssr_code_word_counts = stats.get('ssr_code_word_type_counts_by_source', {}) or {}
    lines.append("Σύνοψη SSR code word types (bytes 13-18):")
    if ssr_code_word_counts:
        aggregate = {}
        for _source, src_counts in ssr_code_word_counts.items():
            for label, value in (src_counts or {}).items():
                aggregate[label] = _as_int(aggregate.get(label)) + _as_int(value)
        display_order = ['No answer (empty SSR code word)', 'Mode A/3 transponder code', 'B mode', 'C mode', 'D mode', '1 mode', '2 mode', 'Not used']
        total_ssr_words = 0
        seen = set()
        previous_value = None

        def _ssr_word_line(label, value):
            nonlocal previous_value
            value = _as_int(value)
            suffix = ""
            if previous_value is not None:
                suffix = f"({value - previous_value:+d})"
            previous_value = value
            return f"{label + '=':<35}{str(value) + suffix}"

        for label in display_order:
            if label not in aggregate:
                continue
            value = _as_int(aggregate.get(label))
            total_ssr_words += value
            seen.add(label)
            lines.append(_ssr_word_line(label, value))
        for label, value in sorted(aggregate.items()):
            if label in seen:
                continue
            value = _as_int(value)
            total_ssr_words += value
            lines.append(_ssr_word_line(label, value))
        lines.append("-" * 39)
        lines.append(f"{'Total=':<35}{total_ssr_words}")
    else:
        lines.append("SSR code words: not transmitted / not available in this capture.")
    lines.append("")

    lines.append("Optional details:")
    byte21_details = stats.get('mode_c_byte21_detail_counts_by_source', {}) or {}
    lines.append("Mode C Byte 21 detail counts:")
    if byte21_details:
        for source in ('PSR', 'MSSR', 'Other'):
            src_counts = byte21_details.get(source, {}) or {}
            if not src_counts:
                continue
            total_src = sum(_as_int(v) for v in src_counts.values())
            detail_parts = [f"{k}={_as_int(v)}" for k, v in sorted(src_counts.items(), key=lambda x: (-_as_int(x[1]), x[0]))]
            lines.append(f"  {source}: " + " | ".join(detail_parts) + f" | Total={total_src}")
    else:
        lines.append("  Byte 21 Mode C validation details: not transmitted in this capture.")
    lines.append("")

    tracking_counts = stats.get('tracking_window_counts_by_source', {}) or {}
    lines.append("Σύνοψη Tracking Window (optional AIRCAT field):")
    if tracking_counts:
        for source in ('PSR', 'MSSR', 'Other'):
            src_counts = tracking_counts.get(source, {}) or {}
            if not src_counts:
                continue
            total_src = sum(_as_int(v) for v in src_counts.values())
            lines.append(
                f"  {source}: "
                f"Inside E1={_as_int(src_counts.get('Inside E1'))} | "
                f"Inside E2={_as_int(src_counts.get('Inside E2'))} | "
                f"Inside E3={_as_int(src_counts.get('Inside E3'))} | "
                f"Outside E3={_as_int(src_counts.get('Outside E3'))} | "
                f"Total={total_src}"
            )
    else:
        lines.append("  Δεν μεταδίδονται optional Tracking Window fields σε αυτό το αρχείο/capture.")
    lines.append("")

    k_counts = stats.get('smoothing_k_counts_by_source', {}) or {}
    lines.append("Σύνοψη Smoothing K (optional AIRCAT field):")
    if k_counts:
        for source in ('PSR', 'MSSR', 'Other'):
            src_counts = k_counts.get(source, {}) or {}
            if not src_counts:
                continue
            total_src = sum(_as_int(v) for v in src_counts.values())
            k_parts = [f"K={k}:{_as_int(src_counts.get(str(k)))}" for k in range(0, 8)]
            lines.append(f"  {source}: " + " | ".join(k_parts) + f" | Total={total_src}")
    else:
        lines.append("  Δεν μεταδίδονται optional Smoothing K fields σε αυτό το αρχείο/capture.")
    lines.append("")

    log_sigma_counts = stats.get('log_sigma_counts_by_source', {}) or {}
    lines.append("Σύνοψη Log Sigma amplitude (optional AIRCAT field):")
    if log_sigma_counts:
        total_log = 0
        for source in ('PSR', 'MSSR', 'Other'):
            src_counts = log_sigma_counts.get(source, {}) or {}
            if not src_counts:
                continue
            total_src = sum(_as_int(v) for v in src_counts.values())
            total_log += total_src
            lines.append(f"  {source}: present={total_src}")
        lines.append(f"  Total={total_log}")
    else:
        lines.append("  Log Sigma amplitude: not transmitted in this capture.")

    return "\n".join(lines)


# Integrated USB/SYNC2USB Monitor (adapted from independently tested GUI v0.7).
# pyserial is optional for file analysis and Ethernet LivePlay; required only for USB.
from collections import deque
from pathlib import Path
try:
    import serial
    from serial.tools import list_ports
except ImportError:
    serial = None
    list_ports = None

def parse_diagnostic_line(line: str) -> dict[str, str]:
    """Parse UART0 telemetry from v0.5 and legacy v0.4, never from USB data.

    Fields are `key=value` tokens. The special prefix makes v0.5 recognizable;
    v0.4 prints tokens beginning `clock=...` instead.
    """
    line = line.strip()
    if line.startswith('AIRCAT_DIAG '):
        line = line[len('AIRCAT_DIAG '):]
    elif not line.startswith('clock='):
        return {}
    fields = {}
    for token in line.split():
        if token.count('=') == 1:
            key, value = token.split('=', 1)
            if key and value:
                fields[key] = value
    return fields if 'clock' in fields else {}


def parse_wifi_control_line(line: str) -> dict[str, str]:
    """Service UART0 ACK, never from the native USB binary DATA channel."""
    if line.startswith('AIRCAT_WIFI_CTRL '):
        tokens = line[len('AIRCAT_WIFI_CTRL '):]
        source = 'ACK'
    elif line.startswith('AIRCAT_WIFI '):
        # Periodic firmware telemetry is a fallback if the UART ACK was lost.
        tokens = line[len('AIRCAT_WIFI '):]
        source = 'TELEMETRY'
    else:
        return {}
    fields = {}
    for token in tokens.split():
        if token.count('=') == 1:
            key, value = token.split('=', 1)
            if key and value:
                fields[key] = value
    if fields.get('enabled') not in ('0', '1') or fields.get('ap') not in ('0', '1'):
        return {}
    fields['result'] = fields.get('result', source)
    return fields


def clock_classification(hz: float | None, recent: bool, enabled: bool) -> tuple[str, str]:
    """Return label and label color. A frequency match alone is not proof of radar."""
    if not enabled:
        return 'Διαγνωστική COM δεν επιλέχθηκε', '#7c8996'
    if not recent:
        return 'ΑΝΑΜΟΝΗ ΔΙΑΓΝΩΣΤΙΚΩΝ', '#8c6d29'
    if hz is None:
        return 'ΑΝΑΜΟΝΗ ΜΕΤΡΗΣΗΣ', '#8c6d29'
    if hz < 5:
        return 'NO CLOCK — GPIO17', '#bb3030'
    if abs(hz - 19200) <= 19200 * 0.02:
        return 'CLOCK OK ≈ 19.200 Hz', '#157f53'
    return 'CLOCK ΕΚΤΟΣ 19.200 Hz', '#b26b13'



# Most SYNC2USB native USB Serial/JTAG interfaces advertise Espressif VID 303A.
# External USB-UART bridges have different USB vendor IDs. Windows COM numbers
# are arbitrary and must NEVER be used to infer DATA / CLOCK roles.
USB_BRIDGE_VIDS = {0x1A86, 0x10C4, 0x0403, 0x067B, 0x04D8}


def usb_role_scores(port) -> tuple[int, int]:
    """Return (native-USB data, external USB-UART diagnostics) scores.

    Uses USB metadata only; this doesn't verify that the firmware is working.
    Input may be a pyserial ListPortInfo or a test double.
    """
    vid = getattr(port, 'vid', None)
    pid = getattr(port, 'pid', None)
    desc = ' '.join(str(getattr(port, key, '') or '') for key in
                    ('description', 'manufacturer', 'product', 'interface', 'hwid')).lower()
    data_score = 0
    diag_score = 0
    if vid == 0x303A:
        data_score = 110
        if pid in (0x1001, 0x0002):
            data_score += 20
    if 'usb jtag/serial' in desc or 'usb jtag serial' in desc or 'usb-serial-jtag' in desc:
        data_score = max(data_score, 105)
    if 'espressif' in desc and ('serial' in desc or 'usb' in desc):
        data_score = max(data_score, 80)
    if vid in USB_BRIDGE_VIDS:
        diag_score = 100
    if any(term in desc for term in
           ('ch340', 'ch341', 'ch343', 'ch910', 'cp210', 'ft232', 'ftdi',
            'usb-uart', 'usb uart', 'usb-serial ch', 'silicon labs', 'wch.cn')):
        diag_score = max(diag_score, 90)
    if data_score >= 80:
        diag_score = 0
    return data_score, diag_score


def detect_usb_ports(ports) -> tuple[str, str, str]:
    """Return (data_port, diag_port, message), or empty fields when uncertain.

    Only use unique strong identifications; never guess using COM order.
    """
    ports = list(ports)
    scored = [(p, *usb_role_scores(p)) for p in ports]
    native = [p.device for p, data, diag in scored if data >= 80]
    bridges = [p.device for p, data, diag in scored if diag >= 90]
    data = native[0] if len(native) == 1 else ''
    diag = bridges[0] if len(bridges) == 1 else ''
    if not data and not diag:
        return '', '', 'Δεν αναγνωρίζονται οι συσκευές από USB VID/PID. Εκτελείται έλεγχος διαγνωστικών.'
    if data and diag and data != diag:
        return data, diag, f'Αυτόματα: DATA {data} (native USB) · CLOCK {diag} (USB-UART bridge)'
    # When there are exactly two USB serial interfaces, the other one may be
    # inferred. Mark it as inferred, not as independently verified.
    if len(ports) == 2:
        other = next((p for p in ports if p.device not in (data, diag)), None)
        if other is not None and (getattr(other, 'vid', None) is not None or
                                  'usb' in str(getattr(other, 'hwid', '')).lower()):
            if data:
                diag = other.device
                return data, diag, (f'Αυτόματα: DATA {data} · CLOCK {diag} (2η USB, εκτίμηση). '
                                    'Θα επαληθευτεί από AIRCAT_DIAG.')
            if diag:
                data = other.device
                return data, diag, (f'Αυτόματα: CLOCK {diag} · DATA {data} (2η USB, εκτίμηση). '
                                    'Θα επαληθευτεί από AIRCAT_DIAG.')
    if data:
        return data, '', f'DATA {data} αναγνωρίστηκε · CLOCK COM προαιρετική.'
    return '', diag, f'Βρέθηκε CLOCK {diag}, αλλά όχι βέβαιη DATA COM.'


def probe_diagnostic_port(port_name: str, seconds: float = 2.8) -> bool:
    """Check whether a COM port actually emits firmware AIRCAT_DIAG telemetry.

    Set DTR/RTS inactive before opening to reduce reset risk on UART bridges.
    This probe is used ONLY when USB descriptors cannot resolve the roles.
    """
    if serial is None:
        return False
    device = serial.Serial(port=None, baudrate=115200, timeout=0.2,
                           xonxoff=False, rtscts=False, dsrdtr=False)
    device.dtr = False
    device.rts = False
    device.port = port_name
    try:
        with device:
            limit = time.monotonic() + seconds
            while time.monotonic() < limit:
                line = device.readline(320).decode('ascii', errors='replace').strip()
                if parse_diagnostic_line(line):
                    return True
        return False
    finally:
        if device.is_open:
            device.close()


# CRC-16/KERMIT (reversed polynomial 0x8408, init=0, refin/refout=True,
# xorout=0, transmitted low byte first). Verified against 343 live BSC
# AIRCAT500 frames in the supplied November 2026 capture.
def _crc_table():
    values = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ (0x8408 if (c & 1) else 0)
        values.append(c)
    return tuple(values)


CRC_TABLE = _crc_table()


def crc16_kermit(data: bytes) -> int:
    value = 0
    for byte in data:
        value = (value >> 8) ^ CRC_TABLE[(value ^ byte) & 0xFF]
    return value


def decode_transparent_bsc(raw: bytes) -> tuple[bytes, bool]:
    """Undo transparent BSC DLE duplication, ignore any inserted DLE/SYN.

    Returns (decoded, is_well_formed). The trailing DLE ETX is NOT included
    in `raw`. Transparent content can otherwise contain any byte value.
    """
    out = bytearray()
    i = 0
    valid = True
    while i < len(raw):
        byte = raw[i]
        if byte != 0x10:
            out.append(byte)
            i += 1
            continue
        if i + 1 >= len(raw):
            valid = False
            out.append(byte)
            break
        nextbyte = raw[i + 1]
        if nextbyte == 0x10:
            out.append(0x10)
        elif nextbyte == 0x32:  # EBCDIC SYN inside a transparent block
            pass                # inserted DLE-SYN is excluded from CRC
        else:
            valid = False
            out.extend((0x10, nextbyte))
        i += 2
    return bytes(out), valid


class BSCObserver:
    """Streaming, CRC-validated AIRCAT500 BSC parser + revolution tracker.

    CRC scope observed in actual data:
      TYPE, ADDR, DLE, STX, transparently unstuffed payload, ETX
    Excluded:
      SYNC*3, SOH, final DLE preceding ETX, transmitted CRC bytes.

    Lost sectors are assessed only in complete, CRC-valid NORTH-to-NORTH
    intervals. Partial first and last revolutions are deliberately excluded.
    """

    TYPES = {
        0x19: 'NORTH', 0x0C: 'SECTOR', 0x0D: 'EXTENSION',
        0x1C: 'PROCESSOR', 0x2A: 'WEATHER', 0x0E: 'MONOPULSE',
    }
    PREAMBLE = b'\x32\x32\x32\x01'
    MAX_FRAME = 8192

    def __init__(self):
        self.total = 0
        self.sync = 0
        self.header_candidates = {name: 0 for name in self.TYPES.values()}
        self.framed = 0
        self.valid_frames = 0
        self.crc_errors = 0
        self.framing_errors = 0
        self.bad_sector_payloads = 0
        self.sectors = set()
        self.completed_rotations = 0
        self.complete_rotations = 0
        self.lost_sectors = 0
        self.uncertain_sectors = 0  # Absent sectors in rotations with CRC/framing errors.
        self.uncertain_rotations = 0
        self.duplicate_sectors = 0
        self.order_errors = 0
        self.invalid_rotations = 0
        self._rotation = None
        self.roll = deque(maxlen=8)
        self.state = 'SEARCH'
        self.current = bytearray()
        self.current_type = None
        self.frame_offset = 0
        self.after_dle = False
        # Diagnostic-only records: do NOT change frame acceptance/CRC logic.
        self.error_events = deque(maxlen=4096)

    def drain_error_events(self):
        events = list(self.error_events)
        self.error_events.clear()
        return events

    def counters(self) -> dict:
        total_checked = self.valid_frames + self.crc_errors
        return dict(
            total=self.total, sync=self.sync,
            headers=dict(self.header_candidates), framed=self.framed,
            valid_frames=self.valid_frames, crc_errors=self.crc_errors,
            framing_errors=self.framing_errors,
            crc_pct=(100 * self.valid_frames / total_checked) if total_checked else None,
            sector_unique=len(self.sectors),
            current_sector_unique=len(self._rotation['seen']) if self._rotation else None,
            completed_rotations=self.completed_rotations,
            perfect_rotations=self.complete_rotations,
            lost_sectors=self.lost_sectors,
            uncertain_sectors=self.uncertain_sectors,
            uncertain_rotations=self.uncertain_rotations,
            duplicate_sectors=self.duplicate_sectors,
            order_errors=self.order_errors,
            invalid_rotations=self.invalid_rotations,
            bad_sector_payloads=self.bad_sector_payloads,
        )

    def _reset_frame(self):
        self.state = 'SEARCH'
        self.current.clear()
        self.after_dle = False
        self.current_type = None

    def _new_frame(self, eight: bytes):
        if self.state != 'SEARCH':
            self.error_events.append(dict(kind='FRAMING_NEW_HEADER', offset=self.frame_offset,
                detected_at=self.total - 8, frame_length=len(self.current),
                sample_hex=bytes(self.current[-64:]).hex(' ').upper(), rx_crc='', calc_crc=''))
            self.framing_errors += 1
            # An abandoned frame makes the current revolution unreliable.
            if self._rotation is not None:
                self.invalid_rotations += 1
                self._rotation = None
        self.state = 'PAYLOAD'
        self.current = bytearray(eight)
        self.current_type = eight[4]
        self.frame_offset = self.total - len(eight)
        self.after_dle = False
        self.header_candidates[self.TYPES[eight[4]]] += 1

    def _valid_north(self, payload: bytes):
        # The observed, invariant NORTH payload for the 0x40 radar address.
        if payload != b'\xFD\x00\x00\x00':
            return
        if self._rotation is not None:
            seen = self._rotation['seen']
            self.completed_rotations += 1
            missing = 32 - len(seen)
            if self._rotation.get('integrity_errors', 0):
                # CRC/framing issues occurred within this NORTH-to-NORTH interval.
                # An absent sector here is unconfirmed, NOT a proven line dropout.
                self.uncertain_rotations += 1
                self.uncertain_sectors += missing
            else:
                self.lost_sectors += missing
                if missing == 0 and self._rotation['duplicates'] == 0 and self._rotation['order_errors'] == 0:
                    self.complete_rotations += 1
        self._rotation = dict(seen=set(), last=None, duplicates=0,
                              order_errors=0, integrity_errors=0)

    def _valid_sector(self, payload: bytes) -> str:
        if len(payload) < 2 or payload[0] != 0xFD or payload[1] > 0x1F:
            self.bad_sector_payloads += 1
            return ''
        sector = payload[1]
        self.sectors.add(sector)
        if self._rotation is not None:
            rot = self._rotation
            if sector in rot['seen']:
                self.duplicate_sectors += 1
                rot['duplicates'] += 1
            if rot['last'] is not None and sector != rot['last'] + 1:
                self.order_errors += 1
                rot['order_errors'] += 1
            rot['seen'].add(sector)
            rot['last'] = sector
        return f'{sector:02X}'

    def _finish_frame(self, events):
        frame = bytes(self.current)
        self.framed += 1
        # Prefix: 32 32 32 01 TYPE 40 10 02
        # Suffix: 10 03 CRClo CRChi
        raw_text = frame[8:-4]
        payload, transparent_ok = decode_transparent_bsc(raw_text)
        covered = frame[4:8] + payload + b'\x03'
        calculated_crc = crc16_kermit(covered)
        received_crc = int.from_bytes(frame[-2:], 'little')
        crc_ok = calculated_crc == received_crc
        name = self.TYPES.get(self.current_type, 'UNKNOWN')
        sector = ''
        result = 'CRC OK' if crc_ok and transparent_ok else ('CRC FAIL' if not crc_ok else 'FRAMING')
        if crc_ok and transparent_ok:
            self.valid_frames += 1
        elif not crc_ok:
            self.crc_errors += 1
        if not transparent_ok:
            self.framing_errors += 1
        if not crc_ok or not transparent_ok:
            self.error_events.append(dict(kind=('CRC_FAIL' if not crc_ok else 'FRAMING_TRANSPARENCY'),
                offset=self.frame_offset, detected_at=self.total,
                frame_length=len(frame), sample_hex=frame[-64:].hex(' ').upper(),
                rx_crc=f'{received_crc:04X}', calc_crc=f'{calculated_crc:04X}'))
        if (not crc_ok or not transparent_ok) and self._rotation is not None:
            self._rotation['integrity_errors'] += 1
        if crc_ok and transparent_ok:
            if name == 'NORTH':
                self._valid_north(payload)
            elif name == 'SECTOR':
                sector = self._valid_sector(payload)
        elif name == 'NORTH' and self._rotation is not None:
            # A CRC-failed NORTH can no longer delimit a reliable revolution.
            self._rotation = None
            self.invalid_rotations += 1
        if not sector and name == 'SECTOR' and len(payload) >= 2 and payload[0] == 0xFD and payload[1] <= 31:
            sector = f'{payload[1]:02X}'  # Show suspected sector even when CRC fails.

        events.append(dict(
            type=name, sector=sector, length=len(frame),
            head=frame[:80].hex(' ').upper(), result=result,
            rx_crc=f'{received_crc:04X}', calc_crc=f'{calculated_crc:04X}',
            offset=self.frame_offset,
            crc_fail_total=self.crc_errors,
            framing_error_total=self.framing_errors,
            payload=(bytes((self.current_type, frame[5])) + payload) if crc_ok and transparent_ok else b'', 
        ))
        self._reset_frame()

    def feed(self, data: bytes) -> list[dict]:
        events = []
        for byte in data:
            self.total += 1
            self.roll.append(byte)
            last = bytes(self.roll)
            if last.endswith(self.PREAMBLE):
                self.sync += 1
            # Require the complete, documented start-of-message sequence.
            if len(last) == 8 and last[:4] == self.PREAMBLE and \
                    last[4] in self.TYPES and last[5:] == b'\x40\x10\x02':
                self._new_frame(last)
                continue
            if self.state == 'SEARCH':
                continue
            self.current.append(byte)
            if len(self.current) > self.MAX_FRAME:
                self.error_events.append(dict(kind='FRAMING_MAX_LENGTH',
                    offset=self.frame_offset, detected_at=self.total,
                    frame_length=len(self.current), sample_hex=bytes(self.current[-64:]).hex(' ').upper(),
                    rx_crc='', calc_crc=''))
                self.framing_errors += 1
                if self._rotation is not None:
                    self.invalid_rotations += 1
                    self._rotation = None
                self._reset_frame()
                continue
            if self.state == 'CRC1':
                self.state = 'CRC2'
                continue
            if self.state == 'CRC2':
                self._finish_frame(events)
                continue
            if self.after_dle:
                self.after_dle = False
                if byte == 0x03:  # DLE ETX then two CRC bytes
                    self.state = 'CRC1'
            elif byte == 0x10:
                self.after_dle = True
        return events


def hex_lines(data: bytes, offset: int) -> str:
    lines = []
    for pos in range(0, len(data), 16):
        chunk = data[pos:pos+16]
        hx = ' '.join(f'{n:02X}' for n in chunk)
        asc = ''.join(chr(n) if 32 <= n < 127 else '.' for n in chunk)
        lines.append(f'{offset+pos:08X}  {hx:<47}  |{asc}|')
    return '\n'.join(lines) + ('\n' if lines else '')




def aircat30_default_folder():
    """Capture location: beside .exe if frozen, beside .py otherwise."""
    import sys
    return Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent


class Usb30Recording:
    """Lossless raw-byte recording, independent of GUI preview and serial read.

    Live counters are sampled at start and stop. The diagnostic sidecar is
    independent of the raw bytes. No telemetry ever enters the .bin file.
    """
    def __init__(self):
        self.lock = threading.RLock()
        self.fh = None
        self.diag_fh = None
        self.errors_fh = None
        self.errors_writer = None
        self.error_event_count = 0
        self.path = None
        self.metadata = {}
        self.bytes_written = 0
        self.started_monotonic = None
        self._last_flush = 0.0
        self._last_sidecar = 0.0
        self.firmware_version = 'unknown'

    def is_active(self):
        with self.lock:
            return self.fh is not None

    def start(self, path, counter_baseline, port, diag_port, firmware):
        with self.lock:
            if self.fh is not None:
                raise RuntimeError('Recording already active')
            path = Path(path).expanduser().resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            # GUI has already confirmed any overwrite.
            self.fh = path.open('wb', buffering=1024 * 1024)
            self.path = path
            self.bytes_written = 0
            self.error_event_count = 0
            self.started_monotonic = time.monotonic()
            self._last_flush = time.monotonic()
            self._last_sidecar = time.monotonic()
            self.firmware_version = str(firmware or 'unknown')
            try:
                self.diag_fh = Path(str(path) + '.diag.log').open('w', encoding='utf-8', buffering=1)
            except OSError:
                self.diag_fh = None
            try:
                self.errors_fh = Path(str(path) + '.errors.csv').open('w', encoding='utf-8', newline='', buffering=1)
                self.errors_writer = csv.writer(self.errors_fh)
                self.errors_writer.writerow(('observed_time', 'kind', 'raw_byte_offset', 'detected_byte_offset',
                                             'candidate_frame_length', 'rx_crc', 'calc_crc', 'hex_tail_64'))
            except OSError:
                self.errors_fh = None
                self.errors_writer = None
            self.metadata = {
                'format': 'AIRCAT500 SYNC2USB RAW BSC stream',
                'capture_device': 'SYNC2USB',
                'capture_connection': 'USB CDC',
                'analyzer_version': APP_VERSION,
                'firmware_version': self.firmware_version,
                'firmware_verification': 'Serial0 AIRCAT_DIAG' if self.firmware_version != 'unknown' else 'not_available',
                'firmware_expected_version': USB_FW_EXPECTED_VERSION,
                'capture_port': port,
                'clock_diagnostic_port': diag_port,
                'diag_log_file': self.diag_fh.name if self.diag_fh else None,
                'error_events_file': self.errors_fh.name if self.errors_fh else None,
                'start_time': datetime.now().astimezone().isoformat(timespec='milliseconds'),
                'counters_at_start': dict(counter_baseline),
                'status': 'recording',
                'bytes_recorded': 0,
                'notes': 'Unmodified raw bytes; no per-frame filtering; USB CRC is not exposed. All UART0 telemetry stored separately.',
            }
            save_capture_metadata(path, self.metadata)
            return path

    def write(self, data):
        with self.lock:
            if self.fh is None:
                return
            self.fh.write(data)
            self.bytes_written += len(data)
            now = time.monotonic()
            # Periodically flush the 1 MiB buffer for endurance testing.
            if now - self._last_flush > 5:
                self.fh.flush()
                self._last_flush = now
            if now - self._last_sidecar > 60:
                self.metadata['bytes_recorded'] = self.bytes_written
                self.metadata['last_checkpoint'] = datetime.now().astimezone().isoformat(timespec='seconds')
                save_capture_metadata(self.path, self.metadata)
                self._last_sidecar = now

    def diagnostic(self, line):
        with self.lock:
            if self.diag_fh is not None:
                self.diag_fh.write(datetime.now().astimezone().isoformat(timespec='milliseconds') + ' ' + line.rstrip('\r\n') + '\n')

    def error(self, event):
        with self.lock:
            if self.errors_writer is not None:
                self.errors_writer.writerow((datetime.now().astimezone().isoformat(timespec='milliseconds'),
                    event.get('kind', ''), event.get('offset', ''), event.get('detected_at', ''),
                    event.get('frame_length', ''), event.get('rx_crc', ''),
                    event.get('calc_crc', ''), event.get('sample_hex', '')))
                self.error_event_count += 1

    def update_firmware(self, firmware):
        if not firmware:
            return
        with self.lock:
            self.firmware_version = str(firmware)
            if self.fh is not None:
                self.metadata['firmware_version'] = str(firmware)
                self.metadata['firmware_verification'] = 'Serial0 AIRCAT_DIAG'

    def stop(self, counters, reason='user'):
        with self.lock:
            if self.fh is None:
                return None
            path = self.path
            try:
                self.fh.flush()
                os.fsync(self.fh.fileno())
            finally:
                self.fh.close()
                self.fh = None
            if self.diag_fh is not None:
                self.diag_fh.close()
                self.diag_fh = None
            if self.errors_fh is not None:
                self.errors_fh.close()
                self.errors_fh = None
                self.errors_writer = None
            self.metadata.update({
                'end_time': datetime.now().astimezone().isoformat(timespec='milliseconds'),
                'elapsed_seconds': round(time.monotonic() - self.started_monotonic, 3),
                'bytes_recorded': self.bytes_written,
                'error_event_rows': self.error_event_count,
                'firmware_version': self.firmware_version,
                'status': 'closed',
                'stop_reason': reason,
                'counters_at_end': dict(counters),
                'counters_during_recording': {k: counters[k] - self.metadata['counters_at_start'].get(k, 0)
                                              for k in ('sync','valid_frames','crc_errors','framing_errors',
                                                        'lost_sectors','uncertain_sectors','completed_rotations')
                                              if k in counters},
            })
            save_capture_metadata(path, self.metadata)
            self.path = None
            return path




class Sync2UsbMonitorWindow(tk.Toplevel):
    def __init__(self, parent, owner=None):
        super().__init__(parent)
        self._owner_app = owner
        self.title(f'AIRCAT500 Analyzer v{APP_VERSION} | USB Radar Serial Line Monitoring (CRC)')
        self.geometry('1220x980')
        self.minsize(990, 760)
        self.configure(bg='#ededed')
        self.com_var = tk.StringVar(value='')
        self.diag_port_var = tk.StringVar(value='(χωρίς διαγνωστικά)')
        self.autodetect_var = tk.StringVar(value='Αυτόματη ανίχνευση USB...')
        self._probe_thread = None
        self._probe_generation = 0
        self._known_ports = ()
        self._last_hotplug_scan = time.monotonic()
        self.diag_message_var = tk.StringVar(value='Επέλεξε τη δεύτερη COM (USB-UART) για μέτρηση GPIO17.')
        self.clock_status_var = tk.StringVar(value='ΑΝΑΜΟΝΗ ΔΙΑΓΝΩΣΤΙΚΩΝ')
        self.path_var = tk.StringVar(value=str(aircat30_default_folder() / ('AIRCAT500_SYNC2USB_v' + APP_VERSION.replace('.', '_') + '_' + datetime.now().strftime('%Y%m%d_%H%M%S') + '.bin')))
        self.save_var = tk.BooleanVar(value=False)
        self.recorder = Usb30Recording()
        self.firmware_version = 'unknown'
        # This is the device-reported firmware, not Analyzer APP_VERSION.
        self.firmware_status_var = tk.StringVar(
            value='Firmware ESP32-S3: UNKNOWN · αναμονή Service USB')
        self.record_started_mono = None
        self._diag_port_in_use = '' 
        self.status_var = tk.StringVar(value='Αποσυνδεδεμένο')
        self.info_var = tk.StringVar(value='CRC-16/KERMIT · LOST: καθαρές NORTH→NORTH περιστροφές. CRC-suspect gaps χωριστά. Δεν ταυτοποιείται η φυσική αιτία απώλειας.')
        self.counters = {k: tk.StringVar(value='0') for k in
                         ('bytes', 'rate', 'sync', 'north', 'sector', 'extension',
                          'frames', 'framing_errors', 'unique',
                          'clock_hz', 'clock_total', 'overflow',
                          'valid_frames', 'crc_errors', 'valid_pct',
                          'lost_sectors', 'uncertain_sectors', 'uncertain_rotations',
                          'rotations', 'perfect_rotations',
                          'duplicates', 'order_errors')}
        for k in ('clock_hz', 'clock_total', 'overflow', 'valid_pct', 'unique'):
            self.counters[k].set('—')
        self.events = queue.Queue(maxsize=128)
        self.stop_flag = threading.Event()
        self.worker = None
        self.diag_worker = None
        self.diag_enabled = False
        self.diag_last_report_time = None
        self.diag_last_counter = None
        self.diag_last_counter_time = None
        self.diag_last_hz = None
        # A single Serial0 reader/writer thread owns the Service USB port.
        self._wifi_control_commands = queue.Queue(maxsize=8)
        # ACK/telemetry must not be dropped by high-rate radar/UI data events.
        self._wifi_control_events = queue.SimpleQueue()
        self._wifi_confirmed_enabled = None
        self._wifi_command_pending = None
        self._wifi_command_started = None
        self._wifi_last_reply = None
        self.wifi_enabled_var = tk.BooleanVar(value=False)  # Unknown until actual firmware status arrives.
        self.wifi_status_var = tk.StringVar(value='Wi-Fi: default ON στο firmware · αναμονή επιβεβαίωσης Service USB')
        self.observer = BSCObserver()
        self.lock = threading.Lock()
        self.last_total = 0
        self.last_rate_time = time.monotonic()
        self.display_dropped = 0
        self._build()
        self.refresh_ports()
        self.protocol('WM_DELETE_WINDOW', self.on_close)
        self.after(200, self.poll)

    def _build(self):
        style = ttk.Style(self)
        # Do not switch the global ttk theme of the parent Analyzer.
        style.configure('SyncTitle.TLabel', background='#ededed', foreground='#151515', font=('Segoe UI', 19, 'bold'))
        style.configure('SyncStat.TLabel', background='#f8f8f8', foreground='#151515', font=('Segoe UI', 15, 'bold'))
        style.configure('SyncStatName.TLabel', background='#f8f8f8', foreground='#444444', font=('Segoe UI', 9))
        body = ttk.Frame(self, padding=15)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='AIRCAT500  /  SYNC2USB Live Monitor', style='SyncTitle.TLabel').pack(anchor='w')
        self.firmware_status_label = tk.Label(
            body, textvariable=self.firmware_status_var, bg='#ededed',
            fg='#8c6d29', font=('Segoe UI', 11, 'bold'), anchor='w')
        self.firmware_status_label.pack(anchor='w', pady=(5, 2))
        ttk.Label(body, text='DATA: Native USB CDC 19200 8N1 · CLOCK: USB-UART 115200 8N1 · CRC-16/KERMIT · NORTH→NORTH SECTORS').pack(anchor='w', pady=(2, 11))

        bar = ttk.Frame(body)
        bar.pack(fill='x', pady=(0, 7))
        ttk.Label(bar, text='DATA COM (native USB)').pack(side='left')
        self.com = ttk.Combobox(bar, width=17, textvariable=self.com_var, state='readonly')
        self.com.pack(side='left', padx=(8, 5))
        ttk.Button(bar, text='Ανανέωση', command=self.refresh_ports).pack(side='left', padx=(0, 5))
        ttk.Button(bar, text='Auto USB/COM', command=self.auto_select).pack(side='left', padx=(0, 9))
        ttk.Button(bar, text='Load BIN File', command=self.analyze_saved_bin).pack(side='left', padx=(0, 5))
        ttk.Button(bar, text='BIN Analysis / Replay', command=self.open_bin_in_main).pack(side='left', padx=(0, 5))
        self.connect_btn = ttk.Button(bar, text='Σύνδεση / START', command=self.connect)
        self.connect_btn.pack(side='left', padx=3)
        self.disconnect_btn = ttk.Button(bar, text='STOP', command=self.disconnect)
        self.disconnect_btn.pack(side='left', padx=3)
        ttk.Label(bar, textvariable=self.status_var).pack(side='right', padx=5)

        diagbar = ttk.Frame(body)
        diagbar.pack(fill='x', pady=(0, 9))
        ttk.Label(diagbar, text='SERVICE USB / CLOCK COM').pack(side='left')
        self.diag_com = ttk.Combobox(diagbar, width=22, textvariable=self.diag_port_var, state='readonly')
        self.diag_com.pack(side='left', padx=(8, 10))
        ttk.Label(diagbar, text='115200 8N1 · CLOCK και firmware diagnostics ανά 1 s').pack(side='left')
        self.clock_status_label = tk.Label(diagbar, textvariable=self.clock_status_var,
                                           font=('Segoe UI', 10, 'bold'), fg='#333333', bg='#ededed')
        self.clock_status_label.pack(side='right', padx=(8, 0))

        wifibar = ttk.Frame(body)
        wifibar.pack(fill='x', pady=(0, 8))
        self.wifi_check = ttk.Checkbutton(wifibar, text='Wi-Fi AP (SYNC) · ON στην εκκίνηση',
                                          variable=self.wifi_enabled_var,
                                          command=self._request_wifi_toggle)
        self.wifi_check.pack(side='left', padx=(0, 12))
        self.wifi_check.state(['disabled'])  # Wait for Service USB connection.
        ttk.Button(wifibar, text='Ανανέωση Wi-Fi', command=self._refresh_wifi_control).pack(side='left', padx=(0, 12))
        ttk.Label(wifibar, textvariable=self.wifi_status_var).pack(side='left')
        ttk.Label(body, textvariable=self.autodetect_var, foreground='#333333',
                  wraplength=1050).pack(anchor='w', pady=(0, 8))

        savebar = ttk.Frame(body)
        savebar.pack(fill='x', pady=(0, 10))
        self.record_button=tk.Button(savebar,text='Start Recording',
            command=self.start_recording,font=('Segoe UI',10,'bold'),
            fg='#171717',bg='#e0e0e0',activebackground='#cccccc',
            relief='raised',bd=1,padx=10,pady=5)
        self.record_button.pack(side='left')
        ttk.Label(savebar,text='Start Recording → RAW .bin + .meta.json + .errors.csv + .diag.log (αν υπάρχει διαγνωστική COM)').pack(side='left',padx=12)

        build_monitor_metric_sections(body,self.counters,is_wifi=False)

        framebox = ttk.LabelFrame(body, text='AIRCAT500 — επαλήθευση CRC ανά frame · DLE/STX ... DLE/ETX + CRC1/CRC2')
        framebox.pack(fill='both',expand=True,pady=(6,7))
        cols = ('time', 'type', 'sector', 'length', 'crc', 'rx_calc', 'bytes')
        self.tree = ttk.Treeview(framebox, columns=cols, show='headings', height=8)
        for key, name, w in zip(cols,
                                ('Ώρα', 'Τύπος', 'Sector', 'Bytes', 'CRC STATUS', 'RX / CALC', 'Πρώτα bytes (HEX)'),
                                (85, 105, 65, 65, 100, 115, 560)):
            self.tree.heading(key, text=name)
            self.tree.column(key, width=w, stretch=(key == 'bytes'))
        self.tree.tag_configure('crc_bad', foreground='#ad2424')
        self.tree.tag_configure('crc_ok', foreground='#145d3c')
        self.tree.tag_configure('framing_bad', foreground='#9b6b0b')
        self.tree.pack(side='left', fill='both', expand=True)
        ybar = ttk.Scrollbar(framebox, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=ybar.set)
        ybar.pack(side='right', fill='y')

        # The frame table occupies the entire lower area; no separate Live HEX.

        ttk.Label(body, textvariable=self.info_var, foreground='#393939', wraplength=1050).pack(anchor='w', pady=(8, 0))
        ttk.Label(body, textvariable=self.diag_message_var, foreground='#393939', wraplength=1050).pack(anchor='w')
        ttk.Label(body, text='* CRC OK = έγκυρο BSC CRC, όχι απόδειξη μηδενικών απωλειών. LOST: διαφορές από 32 μοναδικούς sectors μεταξύ δύο CRC-valid NORTH. Μερικές περιστροφές εξαιρούνται.',
                  foreground='#393939', wraplength=1050).pack(anchor='w')

    def refresh_ports(self):
        if list_ports is None:
            self.autodetect_var.set('Δεν υπάρχει pyserial — py -m pip install pyserial')
            return
        ports = sorted(list_ports.comports(), key=lambda p: p.device)
        names = [p.device for p in ports]
        self._known_ports = tuple(sorted(names))
        self.com['values'] = names
        diag_names = ['(χωρίς διαγνωστικά)'] + names
        self.diag_com['values'] = diag_names
        if self.worker is not None and self.worker.is_alive():
            # Never replace COM assignments while a capture is active.
            return
        data, diag, why = detect_usb_ports(ports)
        if data:
            self.com_var.set(data)
        elif self.com_var.get() not in names:
            self.com_var.set('')
        if diag and diag != self.com_var.get():
            self.diag_port_var.set(diag)
        elif self.diag_port_var.get() not in diag_names or (data and not diag):
            self.diag_port_var.set('(χωρίς διαγνωστικά)')
        self.autodetect_var.set(why)
        if not (data and diag) and len(ports) >= 2:
            self._start_diag_probe(ports, data)

    def auto_select(self):
        """User-requested rescan, without changing the firmware or COM numbers."""
        self.refresh_ports()

    def _start_diag_probe(self, ports, known_data: str):
        if serial is None or (self.worker is not None and self.worker.is_alive()):
            return
        if self._probe_thread is not None and self._probe_thread.is_alive():
            return
        self._probe_generation += 1
        generation = self._probe_generation
        # Probe likely external UART bridges first. Avoid native USB CDC when
        # identified — that port contains raw binary radar data, not telemetry.
        candidates = [p for p in ports if p.device != known_data and
                      usb_role_scores(p)[0] < 80 and
                      (getattr(p, 'vid', None) is not None or 'usb' in
                       str(getattr(p, 'hwid', '')).lower())]
        candidates.sort(key=lambda p: usb_role_scores(p)[1], reverse=True)
        if not candidates:
            return
        self.autodetect_var.set('Αυτόματη ανίχνευση: αναζήτηση AIRCAT_DIAG στα USB-UART...')

        def worker():
            for p in candidates:
                if self._probe_generation != generation:
                    return
                try:
                    if probe_diagnostic_port(p.device):
                        try:
                            self.events.put_nowait(('auto_found', generation, p.device))
                        except queue.Full:
                            pass
                        return
                except Exception:
                    continue  # Device may be in use by IDE or another monitor.
            try:
                self.events.put_nowait(('auto_missing', generation, None))
            except queue.Full:
                pass

        self._probe_thread = threading.Thread(target=worker, daemon=True)
        self._probe_thread.start()

    def _handle_auto_found(self, generation: int, diagnostic_port: str):
        if generation != self._probe_generation or (self.worker and self.worker.is_alive()):
            return
        ports = list(list_ports.comports()) if list_ports else []
        names = [p.device for p in ports]
        if diagnostic_port not in names:
            return
        data, _, _ = detect_usb_ports(ports)
        if not data and len(ports) == 2:
            data = next((p.device for p in ports if p.device != diagnostic_port), '')
        self.diag_port_var.set(diagnostic_port)
        if data and data != diagnostic_port:
            self.com_var.set(data)
            self.autodetect_var.set(f'ΕΠΑΛΗΘΕΥΤΗΚΕ: CLOCK {diagnostic_port} (AIRCAT_DIAG) · '
                                    f'DATA {data} (USB)')
        else:
            self.autodetect_var.set(f'ΕΠΑΛΗΘΕΥΤΗΚΕ: CLOCK {diagnostic_port} (AIRCAT_DIAG). '
                                    'Επέλεξε DATA COM χειροκίνητα.')

    @staticmethod
    def _snapshot_counts(counters):
        return {k: int(counters.get(k, 0)) for k in
                ('sync', 'valid_frames', 'crc_errors', 'framing_errors',
                 'lost_sectors', 'uncertain_sectors', 'completed_rotations')}

    def _reset_wifi_control(self):
        """Invalidate the GUI session, not the physical Wi-Fi state."""
        self._wifi_confirmed_enabled = None
        self._wifi_command_pending = None
        self._wifi_command_started = None
        self._wifi_last_reply = None
        self.wifi_enabled_var.set(False)
        self.wifi_check.state(['disabled'])
        self.wifi_status_var.set('Wi-Fi: default ON στο firmware · αναμονή επιβεβαίωσης Service USB')
        for control_queue in (self._wifi_control_commands, self._wifi_control_events):
            while True:
                try:
                    control_queue.get_nowait()
                except queue.Empty:
                    break

    def _send_wifi_command(self, command):
        """Nonblocking Tk call; the single UART0 owner does the actual write."""
        if (self.stop_flag.is_set() or self.diag_worker is None or
                not self.diag_worker.is_alive()):
            self.wifi_status_var.set('Wi-Fi: Service USB δεν είναι συνδεδεμένη')
            return False
        try:
            self._wifi_control_commands.put_nowait(command)
            return True
        except queue.Full:
            self.wifi_status_var.set('Wi-Fi: ουρά Service USB γεμάτη — δοκίμασε Ανανέωση')
            return False

    def _refresh_wifi_control(self):
        """Manual resynchronization remains available after a lost ACK."""
        if self._send_wifi_command('GET'):
            self.wifi_status_var.set('Wi-Fi: ζητήθηκε η πραγματική κατάσταση από Service USB...')

    def _request_wifi_toggle(self):
        """Never assume a click means the radio has actually changed state."""
        desired = bool(self.wifi_enabled_var.get())
        current = self._wifi_confirmed_enabled
        # Restore the last displayed state until firmware confirms the request.
        self.wifi_enabled_var.set(bool(current) if current is not None else not desired)
        if self._wifi_command_pending is not None:
            self.wifi_status_var.set('Wi-Fi: προηγούμενη εντολή σε εξέλιξη — Ανανέωση για έλεγχο')
            return
        if not self._send_wifi_command('ON' if desired else 'OFF'):
            return
        self._wifi_command_pending = desired
        self._wifi_command_started = time.monotonic()
        # Keep checkbox operational. A timeout must NEVER gray it permanently.
        self.wifi_check.state(['!disabled'])
        self.wifi_status_var.set('Wi-Fi: ' + ('ON' if desired else 'OFF') +
                                 ' ζητήθηκε · αναμονή firmware')

    def _handle_wifi_control(self, fields: dict[str, str]):
        if self.stop_flag.is_set():
            return
        enabled = fields['enabled'] == '1'
        ap_ready = fields['ap'] == '1'
        result = fields.get('result', 'TELEMETRY')
        self._wifi_last_reply = time.monotonic()
        pending = self._wifi_command_pending
        if pending is not None:
            # STATUS/TELEMETRY can confirm an operation even when the direct
            # ON/OFF ACK was lost. Do not accept stale "old state" telemetry.
            if enabled == pending and ap_ready == pending and result != 'OFF_START':
                self._wifi_command_pending = None
                self._wifi_command_started = None
            elif result in ('ERROR', 'INVALID'):
                self._wifi_command_pending = None
                self._wifi_command_started = None
            else:
                self.wifi_status_var.set('Wi-Fi: ' +
                    ('απενεργοποίηση σε εξέλιξη...' if result == 'OFF_START' else
                     'αναμονή επιβεβαίωσης · Ανανέωση διαθέσιμη'))
                return
        self._wifi_confirmed_enabled = enabled
        self.wifi_enabled_var.set(enabled)
        self.wifi_check.state(['!disabled'])
        if result in ('ERROR', 'INVALID'):
            self.wifi_status_var.set('Wi-Fi: σφάλμα firmware (' + result + ') · ' +
                                     ('ON' if enabled else 'OFF'))
        else:
            self.wifi_status_var.set('Wi-Fi: ' + ('ON' if enabled else 'OFF') +
                                     ' · AP ' + ('READY' if ap_ready else 'OFF') +
                                     ' · αναφορά ESP32')

    def _poll_wifi_control(self, now):
        """Recover UI from lost ACK, interrupted UART, or stale status."""
        if (self._wifi_command_pending is not None and
                self._wifi_command_started is not None and
                now - self._wifi_command_started > 8.0):
            self._wifi_command_pending = None
            self._wifi_command_started = None
            self._wifi_confirmed_enabled = None
            # Do not assert an unconfirmed OFF/ON. Allow user to retry.
            self.wifi_check.state(['!disabled'])
            self.wifi_status_var.set('Wi-Fi: δεν ήρθε επιβεβαίωση · Ανανέωση ή ξαναδοκίμασε')
            self._send_wifi_command('GET')
        elif (self._wifi_command_pending is None and
              self._wifi_last_reply is not None and
              now - self._wifi_last_reply > 7.0 and
              self._wifi_confirmed_enabled is not None):
            self._wifi_confirmed_enabled = None
            self.wifi_check.state(['!disabled'])
            self.wifi_status_var.set('Wi-Fi: παλιά τηλεμετρία · Ανανέωση για επαλήθευση')
            self._send_wifi_command('GET')

    def _start_diag_if_possible(self):
        """Start diag sidecar without interfering with DATA; never guess arbitrary COM."""
        if self.diag_worker is not None and self.diag_worker.is_alive():
            return
        port = self.diag_port_var.get().strip()
        if port == '(χωρίς διαγνωστικά)':
            port = ''
        if not port and list_ports is not None:
            try:
                data, detected, _ = detect_usb_ports(list_ports.comports())
                if detected and detected.upper() != self.com_var.get().strip().upper():
                    port = detected
                    self.diag_port_var.set(port)
            except Exception:
                pass
        if not port or port.upper() == self.com_var.get().strip().upper():
            self.diag_message_var.set('RAW BIN ενεργό · Χωρίς διαγνωστική COM. Επίλεξε CLOCK COM για .diag.log.')
            return
        self._reset_wifi_control()
        self.diag_enabled = True
        self._diag_port_in_use = port
        if self.recorder.is_active():
            self.recorder.metadata['clock_diagnostic_port'] = port
        self.diag_worker = threading.Thread(target=self._read_diagnostics, args=(port,), daemon=True)
        self.diag_worker.start()

    def start_recording(self):
        if self.recorder.is_active():
            self.stop_recording()
            return
        if not (self.worker and self.worker.is_alive() and not self.stop_flag.is_set()):
            messagebox.showinfo('Start Recording', 'Συνδέσου πρώτα στη USB DATA COM.', parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self, title='Start Recording — SYNC2USB v6.0 LAB',
            defaultextension='.bin', initialdir=str(aircat30_default_folder()),
            initialfile='AIRCAT500_SYNC2USB_v'+APP_VERSION.replace('.', '_')+'_'+datetime.now().strftime('%Y%m%d_%H%M%S')+'.bin',
            filetypes=[('RAW AIRCAT capture', '*.bin'), ('All files', '*.*')])
        if not path:
            return
        with self.lock:
            baseline=self._snapshot_counts(self.observer.counters())
        diag=self.diag_port_var.get().strip()
        if diag == '(χωρίς διαγνωστικά)':
            diag = ''
        try:
            self.recorder.start(path, baseline, self.com_var.get(), diag, self.firmware_version)
            self.record_started_mono = time.monotonic()
            self._start_diag_if_possible()
            self.status_var.set('Recording: '+str(path))
            self._update_record_button()
        except Exception as exc:
            messagebox.showerror('Start Recording', f'Αδυναμία έναρξης RAW BIN:\n{exc}', parent=self)

    def _update_record_button(self):
        start = self.recorder.started_monotonic if self.recorder.is_active() else None
        if start is None:
            self.record_button.configure(text='Start Recording',fg='#171717',bg='#e0e0e0',
                activeforeground='#171717',activebackground='#cccccc')
        else:
            elapsed=int(max(0,time.monotonic()-start))
            hrs,remain=divmod(elapsed,3600)
            mins,secs=divmod(remain,60)
            self.record_button.configure(text=f'Recording {hrs:02}:{mins:02}:{secs:02}',
                fg='#cc1515',bg='#ffe4e4',activeforeground='#b00000',activebackground='#ffd5d5')

    def stop_recording(self):
        if not self.recorder.is_active():
            return
        # Snapshot and prevent any worker write during finalization.
        with self.lock:
            totals=self._snapshot_counts(self.observer.counters())
        try:
            saved=self.recorder.stop(totals)
            if saved is not None:
                self.status_var.set(f'RAW BIN αποθηκεύτηκε: {saved.name} ({saved.stat().st_size:,} bytes)')
        except Exception as exc:
            self.status_var.set(f'Αποτυχία κλεισίματος BIN: {exc}')
        finally:
            self.record_started_mono=None
            self._update_record_button()

    def choose_file(self):
        filename = filedialog.asksaveasfilename(defaultextension='.bin',
                                                filetypes=[('RAW Binary', '*.bin'), ('All files', '*.*')],
                                                initialfile=Path(self.path_var.get()).name)
        if filename:
            self.path_var.set(filename)

    def open_bin_in_main(self):
        """Open a RAW BIN in the main AIRCAT Analyzer for time-window Replay."""
        if self._owner_app is None:
            return
        filename = filedialog.askopenfilename(parent=self, title='RAW BIN — Analysis / Replay',
                filetypes=[('RAW BSC BIN', '*.bin'), ('All files', '*.*')])
        if filename:
            self._owner_app.open_raw_bin_browser(filename)

    def analyze_saved_bin(self):
        """Analyze a previously saved capture without opening either COM port."""
        if self.worker and self.worker.is_alive():
            messagebox.showinfo('Ενεργή καταγραφή', 'Πάτησε STOP πριν ανοίξεις αρχείο BIN.')
            return
        filename = filedialog.askopenfilename(
            title='Load BIN File — SYNC2USB',
            filetypes=[('Binary capture', '*.bin'), ('All files', '*.*')])
        if not filename:
            return
        self._probe_generation += 1
        self.stop_flag.clear()
        self.diag_enabled = False
        self.observer = BSCObserver()
        self.last_total = 0
        self.last_rate_time = time.monotonic()
        self.display_dropped = 0
        self.diag_last_hz = None
        self.diag_last_report_time = None
        for k in ('clock_hz', 'clock_total', 'overflow'):
            self.counters[k].set('—')
        self.diag_message_var.set('OFFLINE BIN: η μέτρηση CLOCK απαιτεί ζωντανή σύνδεση GPIO17 / USB-UART.')
        self.tree.delete(*self.tree.get_children())
        metadata_file = Path(str(filename) + '.meta.json')
        source_display = ''
        if metadata_file.exists():
            try:
                source_info = json.loads(metadata_file.read_text(encoding='utf-8'))
                source_display = str(source_info.get('capture_device', '') or '')
            except (OSError, ValueError, TypeError):
                pass
        self.status_var.set('Ανάλυση BIN: ' + Path(filename).name +
                            (f' | Πηγή: {source_display}' if source_display else ''))
        self.worker = threading.Thread(target=self._read_saved_bin,
                                       args=(Path(filename),), daemon=True)
        self.worker.start()

    def _read_saved_bin(self, filename: Path):
        try:
            with filename.open('rb') as fp:
                while not self.stop_flag.is_set():
                    chunk = fp.read(8192)
                    if not chunk:
                        break
                    with self.lock:
                        initial = self.observer.total
                        records = self.observer.feed(chunk)
                    try:
                        self.events.put_nowait(('data', initial, chunk[:160], records))
                    except queue.Full:
                        self.display_dropped += 1
            self.events.put(('status', f'Ολοκληρώθηκε η ανάλυση: {filename.name}'))
        except Exception as exc:
            self.events.put(('status', f'Σφάλμα BIN: {exc}'))
        finally:
            self.events.put(('ended', None))

    def connect(self):
        if self.worker is not None and self.worker.is_alive():
            return
        if serial is None:
            messagebox.showerror('pyserial', 'Εγκατάσταση: py -m pip install pyserial')
            return
        port = self.com_var.get().strip()
        if not port:
            messagebox.showwarning('Θύρα COM', 'Επίλεξε τη θύρα COM του SYNC2USB.')
            return
        diag_port = self.diag_port_var.get().strip()
        if diag_port == '(χωρίς διαγνωστικά)':
            diag_port = ''
        if diag_port and port.upper() == diag_port.upper():
            messagebox.showerror('Θύρες', 'DATA COM και CLOCK COM πρέπει να είναι διαφορετικές!')
            return
        output = None  # Recording starts ONLY by pressing Start Recording.
        self._probe_generation += 1  # Invalidate any pending auto-probe result.
        self.stop_flag.clear()
        self.diag_enabled = bool(diag_port)
        self.diag_last_report_time = None
        self.diag_last_counter = None
        self.diag_last_counter_time = None
        self.diag_last_hz = None
        self.diag_error = False
        self.firmware_version = 'unknown'  # New session must re-verify device.
        self._reset_wifi_control()
        self.counters['clock_hz'].set('—')
        self.counters['clock_total'].set('—')
        self.counters['overflow'].set('—')
        self.diag_message_var.set('Αναμονή τηλεμετρίας...' if diag_port else
                                  'Για έλεγχο GPIO17: επίλεξε CLOCK COM, τη δεύτερη USB-UART θύρα.')
        if not diag_port:
            self.wifi_status_var.set('Wi-Fi: απαιτείται Service USB / CLOCK COM στα 115200')
        self.observer = BSCObserver()
        self.last_total = 0
        self.last_rate_time = time.monotonic()
        self.display_dropped = 0
        self.tree.delete(*self.tree.get_children())
        self.status_var.set('Σύνδεση...')
        self.worker = threading.Thread(target=self._capture, args=(port, output, diag_port), daemon=True)
        self.worker.start()
        if diag_port:
            self.diag_worker = threading.Thread(target=self._read_diagnostics,
                                                args=(diag_port,), daemon=True)
            self.diag_worker.start()
        else:
            self.diag_worker = None

    def _read_diagnostics(self, port: str):
        try:
            # UART bridge RTS/DTR can toggle board auto-program/reset circuitry.
            # Configure them inactive BEFORE opening the diagnostic port.
            com = serial.Serial(port=None, baudrate=115200, timeout=0.25, write_timeout=0.5,
                                xonxoff=False, rtscts=False, dsrdtr=False)
            com.dtr = False
            com.rts = False
            com.port = port
            with com:
                if not com.is_open:
                    com.open()
                self.events.put(('diag_status', f'CLOCK COM {port} συνδεδεμένη στα 115200'))
                # Read the real firmware state at USB connection: boot default
                # is ON but never pre-check the box without Service USB proof.
                # No automatic ON command and no USB DATA-channel control bytes.
                com.write(b'AIRCAT_WIFI GET\n')
                last_get = time.monotonic()
                while not self.stop_flag.is_set():
                    try:
                        command = self._wifi_control_commands.get_nowait()
                    except queue.Empty:
                        command = None
                    now = time.monotonic()
                    if command is not None:
                        com.write(('AIRCAT_WIFI ' + command + '\n').encode('ascii'))
                        if command == 'GET':
                            last_get = now
                    elif now - last_get >= 2.5:
                        # Heartbeat query handles dropped ACKs and stalled UI.
                        com.write(b'AIRCAT_WIFI GET\n')
                        last_get = now
                    line = com.readline(384).decode('ascii', errors='replace').strip()
                    if not line:
                        continue
                    self.recorder.diagnostic(line)
                    wifi_report = parse_wifi_control_line(line)
                    if wifi_report:
                        self._wifi_control_events.put(('wifi_control', wifi_report))
                        continue
                    report = parse_diagnostic_line(line)
                    if report:
                        self.recorder.update_firmware(report.get('version'))
                        try:
                            self.events.put_nowait(('diag', time.monotonic(), report))
                        except queue.Full:
                            pass
        except Exception as exc:
            self._wifi_control_events.put(('diag_error', f'Σφάλμα CLOCK COM {port}: {exc}'))

    def _update_firmware_banner(self, diag_recent: bool):
        """Show verified device identity only with fresh Service USB telemetry."""
        fw = str(self.firmware_version or '').strip()
        if not diag_recent or not fw or fw == 'unknown':
            label = 'Firmware ESP32-S3: UNKNOWN · χωρίς πρόσφατη επιβεβαίωση Service USB'
            color = '#8c6d29'
        elif fw != USB_FW_EXPECTED_VERSION:
            label = (f'Firmware ESP32-S3: v{fw} · ΔΙΑΦΟΡΕΤΙΚΗ ΕΚΔΟΣΗ '
                     f'(USB expected v{USB_FW_EXPECTED_VERSION})')
            color = '#b26b13'
        else:
            label = f'Firmware ESP32-S3: v{fw} · επιβεβαιωμένο από Service USB'
            color = '#157f53'
        if self.firmware_status_var.get() != label:
            self.firmware_status_var.set(label)
            self.firmware_status_label.configure(fg=color)

    def _handle_diag(self, report_time: float, fields: dict[str, str]):
        fw = fields.get('version', '')
        if fw:
            self.firmware_version = fw
            self.recorder.update_firmware(fw)
        self.diag_last_report_time = report_time
        self.diag_error = False
        try:
            total = int(fields['clock'])
        except (ValueError, KeyError):
            return
        hz = None
        if 'clock_hz' in fields:
            try:
                hz = float(fields['clock_hz'])
            except ValueError:
                pass
        if hz is None and self.diag_last_counter is not None and self.diag_last_counter_time is not None:
            seconds = report_time - self.diag_last_counter_time
            if seconds > 0:
                hz = ((total - self.diag_last_counter) & 0xFFFFFFFF) / seconds
        self.diag_last_counter = total
        self.diag_last_counter_time = report_time
        if hz is not None:
            self.diag_last_hz = hz
            self.counters['clock_hz'].set(f'{hz:,.0f}')
        self.counters['clock_total'].set(f'{total:,}')
        if 'overflow' in fields:
            try:
                self.counters['overflow'].set(f'{int(fields["overflow"]):,}')
            except ValueError:
                pass
        self.diag_message_var.set('FW '+self.firmware_version + ' · GPIO17: ' +
                                  f'CLOCK={total:,} | SYNC={fields.get("syncs", "—")} | '
                                  f'LOCKS={fields.get("locks", "—")} | '
                                  f'OVERFLOW={fields.get("overflow", "—")} | ' +
                                  f'REALIGNS={fields.get("realigns", "—")} | ' +
                                  f'SHORT_WRITES={fields.get("short_writes", "—")} | ' +
                                  f'BIT SAMPLE OVERRUN={fields.get("bit_sample_overruns", "—")} | '
                                  f'USB PENDING={fields.get("pending", "—")} | '
                                  f'DTR GLITCHES={fields.get("dtr_glitches", "—")} | '
                                  f'DTR MAX={fields.get("dtr_max_glitch_ms", "—")}ms | '
                                  f'USB DISCONNECTS={fields.get("usb_disconnects", "—")} | '
                                  f'DISCONNECT DROPPED={fields.get("disconnect_dropped_bytes", "—")} | '
                                  f'HOST={fields.get("host", "—")} / RAW={fields.get("host_raw", "—")}')

    def _capture(self, port: str, output: Path | None = None, diag_port: str = ''):
        try:
            with serial.Serial(port=port, baudrate=19200, bytesize=serial.EIGHTBITS,
                               parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
                               xonxoff=False, rtscts=False, dsrdtr=False, timeout=0.12) as com:
                self.events.put(('status', f'SYNC2USB · Συνδεδεμένο: {port} — 19200 8N1'))
                while not self.stop_flag.is_set():
                    chunk=com.read(min(4096,max(1,com.in_waiting)))
                    if not chunk:continue
                    # The recording write precedes ALL decoding and UI updates.
                    # The lock synchronizes Start/Stop Recording with this thread.
                    self.recorder.write(chunk)
                    with self.lock:
                        initial=self.observer.total
                        records=self.observer.feed(chunk)
                        problems=self.observer.drain_error_events()
                    for problem in problems:
                        self.recorder.error(problem)
                    try:
                        self.events.put_nowait(('data',initial,b'',records))
                    except queue.Full:
                        self.display_dropped+=1
        except Exception as exc:
            try:self.events.put_nowait(('status',f'Σφάλμα COM: {exc}'))
            except queue.Full:pass
        finally:
            # Closing/metadata handled by poll (Tk thread).
            try:self.events.put_nowait(('ended',None))
            except queue.Full:pass

    def disconnect(self):
        self.stop_flag.set()
        self.firmware_version = 'unknown'
        self.diag_last_report_time = None
        self._reset_wifi_control()
        if self.worker and self.worker.is_alive():
            self.status_var.set('Διακοπή...')

    def poll(self):
        try:
            # Process control telemetry before bulk radar data. These events
            # use a dedicated queue so UI overload cannot discard OFF/ON ACKs.
            for _ in range(32):
                try:
                    control = self._wifi_control_events.get_nowait()
                except queue.Empty:
                    break
                if control[0] == 'wifi_control':
                    self._handle_wifi_control(control[1])
                elif control[0] == 'diag_error':
                    self.diag_message_var.set(control[1])
                    self.diag_last_report_time = None
                    self.diag_error = True
                    self._reset_wifi_control()
                    self.wifi_status_var.set('Wi-Fi: Service USB αποσυνδέθηκε / σφάλμα')
            for _ in range(40):
                try:
                    message = self.events.get_nowait()
                except queue.Empty:
                    break
                if message[0] == 'auto_found':
                    self._handle_auto_found(message[1], message[2])
                elif message[0] == 'auto_missing':
                    if message[1] == self._probe_generation and not (self.worker and self.worker.is_alive()):
                        self.autodetect_var.set('Δεν βρέθηκε AIRCAT_DIAG αυτόματα. '
                                                'Έλεγξε firmware v0.5 και τις COM, ή επίλεξέ τες χειροκίνητα.')
                elif message[0] == 'diag':
                    self._handle_diag(message[1], message[2])
                elif message[0] == 'wifi_control':
                    self._handle_wifi_control(message[1])
                elif message[0] == 'diag_status':
                    self.diag_message_var.set(message[1])
                elif message[0] == 'diag_error':
                    self.diag_message_var.set(message[1])
                    self.diag_last_report_time = None
                    self.diag_error = True
                    self._reset_wifi_control()
                    self.wifi_status_var.set('Wi-Fi: Service USB αποσυνδέθηκε / σφάλμα')
                elif message[0] == 'status':
                    self.status_var.set(message[1])
                elif message[0] == 'ended':
                    self.stop_recording()
                    if self.stop_flag.is_set():
                        self.status_var.set('Αποσυνδεδεμένο')
                elif message[0] == 'data':
                    _, initial, sample, records = message
                    # The table below displays complete parsed AIRCAT frames.
                    for record in records:
                        clock = datetime.now().strftime('%H:%M:%S')
                        tag = ('crc_ok' if record['result'] == 'CRC OK' else
                               'crc_bad' if record['result'] == 'CRC FAIL' else 'framing_bad')
                        self.tree.insert('', 'end', values=(
                            clock, record['type'], record['sector'], record['length'],
                            record['result'], f"{record['rx_crc']}/{record['calc_crc']}",
                            record['head']), tags=(tag,))
                    # Prune the table once per received batch, not once per
                    # frame. This reduces Tk CPU load when both monitors run.
                    children = self.tree.get_children()
                    if len(children) > 400:
                        self.tree.delete(*children[:len(children)-300])
                    if records:
                        self.tree.yview_moveto(1.0)
        finally:
            scan_time = time.monotonic()
            if list_ports is not None and scan_time - self._last_hotplug_scan >= 2.0:
                self._last_hotplug_scan = scan_time
                try:
                    present = tuple(sorted(p.device for p in list_ports.comports()))
                    if present != self._known_ports:
                        self.refresh_ports()  # Auto-select on USB plug/unplug too.
                except Exception:
                    pass
            with self.lock:
                data = self.observer.counters()
            now = time.monotonic()
            duration = now - self.last_rate_time
            if duration >= 0.5:
                self.counters['rate'].set(f'{(data["total"] - self.last_total)/duration:,.0f}')
                self.last_total = data['total']
                self.last_rate_time = now
            self.counters['bytes'].set(f'{data["total"]:,}')
            self.counters['sync'].set(f'{data["sync"]:,}')
            self.counters['north'].set(f'{data["headers"]["NORTH"]:,}')
            self.counters['sector'].set(f'{data["headers"]["SECTOR"]:,}')
            self.counters['extension'].set(f'{data["headers"]["EXTENSION"]:,}')
            self.counters['frames'].set(f'{data["framed"]:,}')
            self.counters['framing_errors'].set(f'{data["framing_errors"]:,}')
            self.counters['unique'].set((f'{data["current_sector_unique"]} / 32')
                                        if data['current_sector_unique'] is not None else '—')
            self.counters['valid_frames'].set(f'{data["valid_frames"]:,}')
            self.counters['crc_errors'].set(f'{data["crc_errors"]:,}')
            self.counters['valid_pct'].set((f'{data["crc_pct"]:.1f}%')
                                          if data['crc_pct'] is not None else '—')
            self.counters['lost_sectors'].set(f'{data["lost_sectors"]:,}')
            self.counters['uncertain_sectors'].set(f'{data["uncertain_sectors"]:,}')
            self.counters['uncertain_rotations'].set(f'{data["uncertain_rotations"]:,}')
            self.counters['rotations'].set(f'{data["completed_rotations"]:,}')
            self.counters['perfect_rotations'].set(f'{data["perfect_rotations"]:,}')
            self.counters['duplicates'].set(f'{data["duplicate_sectors"]:,}')
            self.counters['order_errors'].set(f'{data["order_errors"]:,}')
            # Legacy v0.4 firmware reports every 5s; v0.5 every 1s.
            # Stale detection allows both but still marks a stopped feed as stale.
            diag_recent = (self.diag_last_report_time is not None and
                           now - self.diag_last_report_time < 7.5 and
                           not self.stop_flag.is_set() and not self.diag_error)
            self._update_firmware_banner(diag_recent)
            clock_label, clock_color = clock_classification(
                self.diag_last_hz, diag_recent, self.diag_enabled)
            self.clock_status_var.set(clock_label)
            self.clock_status_label.configure(fg=clock_color)
            if self.display_dropped:
                self.info_var.set(f'Περιορισμός προβολής: {self.display_dropped} ενημερώσεις δεν εμφανίστηκαν. Η αποθηκευμένη RAW .bin παραμένει πλήρης κατά τη ζωντανή καταγραφή.')
            else:
                self.info_var.set(f'CRC: {data["valid_frames"]} OK / {data["crc_errors"]} FAIL · ' +
                                  f'Πλήρεις NORTH→NORTH: {data["completed_rotations"]} · ' +
                                  f'Ακυρωμένες περιστροφές: {data["invalid_rotations"]} · ' +
                                  f'Άκυρα sector payloads: {data["bad_sector_payloads"]} · '
                                  f'Uncertain gaps: {data["uncertain_sectors"]}.')
            self._poll_wifi_control(now)
            self._update_record_button()
            try:
                self.after(200, self.poll)
            except tk.TclError:
                pass

    def on_close(self):
        if self._owner_app is not None:
            self._owner_app.sync_monitor_window = None
        self._probe_generation += 1
        self.stop_flag.set()
        self._reset_wifi_control()
        if self.worker is not None and self.worker.is_alive():
            self.worker.join(timeout=1.3)  # Permit COM close / RAW file flush.
        if self.diag_worker is not None and self.diag_worker.is_alive():
            self.diag_worker.join(timeout=0.6)
        self.stop_recording()
        self.destroy()






# ===== v30.3 RAW BSC BIN browser: full-file integrity scan, windowed AIRCAT Replay =====
# Raw BSC BIN contains bytes ONLY. It does not encode reliable per-frame wall-clock
# timestamps. Playback time is ESTIMATED from NORTH count and capture sidecar.
class RawBscBinBrowser(tk.Toplevel):
    """Memory-bounded large-BIN scanner and selected-window AIRCAT analysis/replay.

    The original BSCObserver is reused without modifying CRC or framing rules.
    Only sparse NORTH offsets are stored; no millions of frame dictionaries in RAM.
    """
    INDEX_STEP = 64
    MINUTE_OPTIONS = ('5', '10', '20', '30', '60', '90')

    def __init__(self, owner, path):
        super().__init__(owner.root)
        self.owner = owner
        self.path = Path(path)
        self.stop_event = threading.Event()
        self.events = queue.Queue()
        self.ready = False
        self.index = []  # (north_number, BSC preamble file_offset, crc_valid_frame_number)
        self.summary = None
        self.metadata = {}
        self.north_count = 0
        self.duration_sec = None
        self.start_epoch = None
        self.rotation_sec = None
        self.replay_requested = False
        self.loading_window = False
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.title('AIRCAT500 v6.0 LAB — RAW BIN Analysis / Replay')
        self.geometry('890x580')
        self.minsize(740, 470)
        frame = ttk.Frame(self, padding=15)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='RAW BSC BIN — πλήρης έλεγχος και Replay κατά τμήματα',
                  font=('Segoe UI', 14, 'bold')).pack(anchor='w')
        ttk.Label(frame, text=self.path.name, wraplength=830).pack(anchor='w', pady=(3, 7))
        self.status_var = tk.StringVar(value='Ξεκινά η πλήρης σάρωση του RAW BIN...')
        ttk.Label(frame, textvariable=self.status_var, wraplength=800).pack(anchor='w', pady=(0, 6))
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progressbar = ttk.Progressbar(frame, variable=self.progress_var, maximum=100)
        self.progressbar.pack(fill='x', pady=(0, 12))
        body = ttk.LabelFrame(frame, text='Επιλογή διαστήματος για πλήρη AIRCAT Analysis / Replay')
        body.pack(fill='x', pady=(0, 9))
        controls = ttk.Frame(body, padding=9)
        controls.pack(fill='x')
        ttk.Label(controls, text='Έναρξη (ώρες από την αρχή):').pack(side='left', padx=(0, 5))
        self.hours_var = tk.StringVar(value='0')
        ttk.Entry(controls, width=10, textvariable=self.hours_var).pack(side='left', padx=(0, 12))
        ttk.Label(controls, text='Διάρκεια (λεπτά):').pack(side='left', padx=(0, 5))
        self.minutes_var = tk.StringVar(value='20')
        ttk.Combobox(controls, textvariable=self.minutes_var, values=self.MINUTE_OPTIONS,
                     state='readonly', width=7).pack(side='left', padx=(0, 12))
        self.analysis_button = ttk.Button(controls, text='Analysis διαστήματος',
                                          command=lambda: self.load_window(False), state='disabled')
        self.analysis_button.pack(side='left', padx=4)
        self.replay_button = ttk.Button(controls, text='Replay διαστήματος',
                                        command=lambda: self.load_window(True), state='disabled')
        self.replay_button.pack(side='left', padx=4)
        ttk.Label(body, text='Η πλήρης σάρωση CRC καλύπτει ΟΛΟ το BIN. Η αναλυτική αποκωδικοποίηση '
                  'στόχων και το Replay φορτώνουν μόνο το επιλεγμένο διάστημα, για να μη γεμίζει η μνήμη.',
                  wraplength=820).pack(anchor='w', padx=10, pady=(0, 10))
        summary_frame = ttk.LabelFrame(frame, text='Πλήρης αναφορά ακεραιότητας (όλο το RAW BIN)')
        summary_frame.pack(fill='both', expand=True)
        self.out = scrolledtext.ScrolledText(summary_frame, wrap='word', font=('Consolas', 10), height=12)
        self.out.pack(fill='both', expand=True, padx=7, pady=7)
        self.out.insert('end', 'Γίνεται επαλήθευση BSC και CRC σε όλα τα bytes, με συνεχή ένδειξη προόδου.\n')
        self.out.configure(state='disabled')
        self.after(150, self.poll)
        self.worker = threading.Thread(target=self._scan, daemon=True)
        self.worker.start()

    def _set_output(self, message):
        self.out.configure(state='normal')
        self.out.delete('1.0', 'end')
        self.out.insert('1.0', message)
        self.out.configure(state='disabled')

    def close(self):
        self.stop_event.set()
        self.replay_requested = False
        try:
            if getattr(self.owner, '_raw_bin_browser', None) is self:
                self.owner._raw_bin_browser = None
        except Exception:
            pass
        try:
            self.destroy()
        except tk.TclError:
            pass

    def _get_metadata(self):
        sidecar = Path(str(self.path) + '.meta.json')
        if not sidecar.is_file():
            return {}
        try:
            obj = json.loads(sidecar.read_text(encoding='utf-8-sig'))
            return obj if isinstance(obj, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    def _cache_path(self):
        # Sidecar index is optional. No modification of the original .bin.
        return Path(str(self.path) + '.bscindex.json')

    def _load_cached_index(self, size, mtime_ns):
        try:
            obj = json.loads(self._cache_path().read_text(encoding='utf-8'))
            if (obj.get('index_schema') != 1 or obj.get('size') != size
                    or obj.get('mtime_ns') != mtime_ns):
                return None
            marks = obj.get('marks')
            if not isinstance(marks, list) or not all(len(m) == 3 for m in marks):
                return None
            return obj
        except (OSError, ValueError, TypeError):
            return None

    def _scan(self):
        try:
            st = self.path.stat()
            size = st.st_size
            meta = self._get_metadata()
            cached = self._load_cached_index(size, st.st_mtime_ns)
            if cached is not None:
                self.events.put(('complete', cached['counters'], cached['marks'],
                                 cached['north_count'], meta, size, True))
                return
            obs = BSCObserver()
            marks = []
            north = 0
            frame_number = 0
            last_pct = -1
            with self.path.open('rb') as fp:
                while not self.stop_event.is_set():
                    chunk = fp.read(262144)
                    if not chunk:
                        break
                    frames = obs.feed(chunk)
                    for ev in frames:
                        if ev.get('result') != 'CRC OK':
                            continue
                        frame_number += 1
                        if ev.get('type') == 'NORTH':
                            north += 1
                            if north == 1 or (north - 1) % self.INDEX_STEP == 0:
                                marks.append([north, int(ev['offset']), frame_number])
                    pct = int(100 * obs.total / size) if size else 100
                    if pct != last_pct:
                        self.events.put(('progress', pct, f'RAW BIN: {obs.total:,} / {size:,} bytes · '
                                f'{obs.valid_frames:,} CRC OK · {obs.crc_errors} CRC FAIL · '
                                f'{obs.framing_errors} FRAMING'))
                        last_pct = pct
            if self.stop_event.is_set():
                return
            counters = obs.counters()
            cache_obj = dict(index_schema=1, size=size, mtime_ns=st.st_mtime_ns,
                             north_count=north, marks=marks, counters=counters)
            try:
                self._cache_path().write_text(json.dumps(cache_obj, ensure_ascii=False), encoding='utf-8')
            except OSError:
                pass
            self.events.put(('complete', counters, marks, north, meta, size, False))
        except Exception as exc:
            self.events.put(('error', f'Σφάλμα ανάγνωσης BIN: {exc}'))

    def full_report(self):
        c = self.summary or {}
        d = self.duration_sec
        meta = self.metadata
        parts = [
            'AIRCAT500 v6.0 LAB | RAW BIN — ΟΛΟ ΤΟ ΑΡΧΕΙΟ',
            '=' * 65,
            'BIN: ' + self.path.name,
            'Bytes: {:,}'.format(self.path.stat().st_size),
            'Firmware (metadata): {}'.format(meta.get('firmware_version', 'unknown')),
            'Duration (metadata): ' + (f'{d / 3600:.3f} ώρες' if d is not None else 'άγνωστη'),
            'BSC CRC OK: {:,}'.format(c.get('valid_frames', 0)),
            'BSC CRC FAIL: {:,}'.format(c.get('crc_errors', 0)),
            'BSC framing errors: {:,}'.format(c.get('framing_errors', 0)),
            'NORTH frames: {:,}'.format(self.north_count),
            'Completed NORTH cycles: {:,}'.format(c.get('completed_rotations', 0)),
            'Perfect 32/32 rotations: {:,}'.format(c.get('perfect_rotations', 0)),
            'Missing sectors (clean cycles): {:,}'.format(c.get('lost_sectors', 0)),
            'CRC-suspect sector gaps: {:,}'.format(c.get('uncertain_sectors', 0)),
            'Duplicated sectors: {:,}'.format(c.get('duplicate_sectors', 0)),
            'Out-of-order sectors: {:,}'.format(c.get('order_errors', 0)),
            '',
            'ΣΗΜΑΝΤΙΚΟ:',
            'Ο παραπάνω έλεγχος αφορά όλο το BIN και δεν βασίζεται στους μετρητές του metadata.',
            'Για πλήρη αποκωδικοποίηση στόχων, αναφορές και Replay επέλεξε χρονικό διάστημα.',
            'Οι χρόνοι Replay από BIN είναι ΕΚΤΙΜΗΣΕΙΣ από το NORTH και το .meta.json,',
            'επειδή το RAW BIN δεν περιέχει timestamps ανά frame.',
            'Τα άκρα ενός επιλεγμένου διαστήματος μπορεί να είναι μερικές περιστροφές.',
        ]
        if d is None:
            parts.extend(['', 'Χωρίς metadata διάρκειας το Replay χρησιμοποιεί ενδεικτικό',
                          'χρονισμό ~3,956 s/NORTH. Οι ώρες είναι κατά προσέγγιση.'])
        return '\n'.join(parts) + '\n'

    def _set_complete(self, counters, marks, north_count, metadata, size, cached):
        self.summary = counters
        self.index = [tuple(map(int, m)) for m in marks]
        self.north_count = int(north_count)
        self.metadata = metadata
        try:
            duration = float(metadata.get('elapsed_seconds', 0))
            self.duration_sec = duration if duration > 0 else None
        except (ValueError, TypeError):
            self.duration_sec = None
        try:
            self.start_epoch = datetime.fromisoformat(metadata['start_time']).timestamp()
        except (KeyError, TypeError, ValueError):
            self.start_epoch = None
        self.rotation_sec = (self.duration_sec / (self.north_count - 1)
                             if self.duration_sec and self.north_count > 1 else 3.956)
        self.ready = bool(self.index)
        self.progress_var.set(100.0)
        self.status_var.set(('Έτοιμο από αποθηκευμένο index.' if cached else 'Ολοκληρώθηκε πλήρης σάρωση.')
                            + ' NORTH: {:,}, CRC OK: {:,}, CRC FAIL: {}, FRAMING: {}'.format(
                                self.north_count, counters.get('valid_frames', 0),
                                counters.get('crc_errors', 0), counters.get('framing_errors', 0)))
        self.analysis_button.configure(state='normal' if self.ready else 'disabled')
        self.replay_button.configure(state='normal' if self.ready else 'disabled')
        self._set_output(self.full_report())
        self.owner.report_text = self.full_report()
        self.owner.text.delete('1.0', 'end')
        self.owner.text.insert('1.0', self.owner.report_text)
        self.owner.status_label.config(text='RAW BIN: ολοκληρώθηκε πλήρης σάρωση· επέλεξε Analysis / Replay διαστήματος.')
        self.owner.progress_var.set(100)

    def poll(self):
        if not self.winfo_exists():
            return
        try:
            for _ in range(60):
                try:
                    item = self.events.get_nowait()
                except queue.Empty:
                    break
                tag = item[0]
                if tag == 'progress':
                    self.progress_var.set(item[1])
                    self.status_var.set(item[2])
                elif tag == 'complete':
                    self._set_complete(*item[1:])
                elif tag == 'error':
                    self.status_var.set(item[1])
                    self._set_output(item[1])
        finally:
            try:
                self.after(150, self.poll)
            except tk.TclError:
                pass

    def load_window(self, replay=False):
        if not self.ready or self.loading_window:
            messagebox.showinfo('RAW BIN', 'Η σάρωση BIN δεν έχει ολοκληρωθεί ή υπάρχει ενεργή φόρτωση.', parent=self)
            return
        if getattr(self.owner, 'file_analysis_running', False):
            messagebox.showinfo('RAW BIN', 'Ήδη εκτελείται ανάλυση.', parent=self)
            return
        try:
            start_h = float(self.hours_var.get().strip().replace(',', '.'))
            minutes = int(self.minutes_var.get())
            if not 0 <= start_h or minutes not in (5, 10, 20, 30, 60, 90):
                raise ValueError()
            max_h = self.duration_sec / 3600 if self.duration_sec else self.north_count * self.rotation_sec / 3600
            if start_h >= max_h:
                raise ValueError()
        except (TypeError, ValueError):
            messagebox.showwarning('RAW BIN', 'Δώσε έγκυρη ώρα έναρξης (π.χ. 12.5) και διάρκεια.', parent=self)
            return
        self.loading_window = True
        self.replay_requested = bool(replay)
        self.analysis_button.configure(state='disabled')
        self.replay_button.configure(state='disabled')
        self.status_var.set('Φόρτωση και πλήρης ανάλυση επιλεγμένου τμήματος...')
        self.owner.file_analysis_running = True
        self.owner.file_analysis_queue = queue.Queue()
        self.owner.file_analysis_thread = threading.Thread(
            target=self._window_worker, args=(start_h * 3600, minutes * 60), daemon=True)
        self.owner.file_analysis_thread.start()
        try:
            if self.owner.file_analysis_after_id is not None:
                self.owner.root.after_cancel(self.owner.file_analysis_after_id)
        except (tk.TclError, AttributeError):
            pass
        self.owner.file_analysis_after_id = self.owner.root.after(50, self.owner._poll_file_analysis_queue)
        self._watch_window()

    def _watch_window(self):
        if not self.winfo_exists():
            return
        if self.owner.file_analysis_running:
            self.after(300, self._watch_window)
        else:
            self.loading_window = False
            self.analysis_button.configure(state='normal' if self.ready else 'disabled')
            self.replay_button.configure(state='normal' if self.ready else 'disabled')
            if self.owner.current_records:
                self.status_var.set('Έτοιμο διάστημα: {:,} frames για AIRCAT Analysis / Replay.'.format(
                    len(self.owner.current_records)))
            else:
                self.replay_requested = False

    def _window_worker(self, start_seconds, duration_seconds):
        try:
            total_norths = self.north_count
            period = self.rotation_sec
            start_north = min(total_norths, max(1, int(start_seconds / period) + 1))
            end_north = min(total_norths + 1, start_north + max(1, round(duration_seconds / period)))
            # Read from the nearest earlier complete NORTH preamble; no speculative seeking mid-frame.
            mark = max((m for m in self.index if m[0] <= start_north), key=lambda m: m[0])
            global_north, byte_offset, global_frame = mark
            global_north -= 1
            global_frame -= 1
            obs = BSCObserver()
            records = []
            last_sector = 0
            completed = False
            with self.path.open('rb') as fp:
                fp.seek(byte_offset)
                while not completed and not self.stop_event.is_set():
                    data = fp.read(131072)
                    if not data:
                        break
                    for ev in obs.feed(data):
                        if ev.get('result') != 'CRC OK':
                            continue
                        global_frame += 1
                        if ev['type'] == 'NORTH':
                            global_north += 1
                            last_sector = 0
                        elif ev['type'] == 'SECTOR' and ev.get('sector'):
                            try:
                                last_sector = int(ev['sector'], 16)
                            except ValueError:
                                pass
                        if global_north >= end_north:
                            completed = True
                            break
                        if global_north < start_north or not ev.get('payload'):
                            continue
                        fractional = (last_sector + 1) / 32 if ev['type'] != 'NORTH' else 0.0
                        est_seconds = max(0.0, (global_north - 1 + fractional) * period)
                        timestamp = (self.start_epoch + est_seconds) if self.start_epoch is not None else est_seconds
                        records.append({
                            'source': 'usb_raw_bin', 'timestamp': timestamp,
                            'payload': ev['payload'], 'frame_no': global_frame,
                            'capture_device': 'SYNC2USB', 'capture_connection': 'USB CDC',
                            'capture_port': str(self.metadata.get('capture_port', '')),
                            'raw_bin_offset': byte_offset + ev.get('offset', 0),
                        })
                    # reader progression outside Tk; report every ~16 MiB to avoid queue flooding
                    if len(records) % 1000 < 100:
                        self.owner.file_analysis_queue.put(('progress', 50.0,
                            'BIN window... {:,} frames (μέχρι ~{:,.1f} ώρες)'.format(
                            len(records), global_north * period / 3600)))
                    if len(records) > 55000:
                        raise ValueError('Το τμήμα ξεπερνά 55.000 frames. Επίλεξε μικρότερη διάρκεια.')
            if not records:
                raise ValueError('Δεν βρέθηκαν έγκυρα AIRCAT frames στο επιλεγμένο διάστημα.')
            self.owner.file_analysis_queue.put(('progress', 60.0, 'Ανάλυση AIRCAT του επιλεγμένου διαστήματος...'))
            stats = analyze_records(records)
            stats['filter_mode'] = 'RAW BIN CRC-valid only'
            stats['raw_bin_full_counters'] = self.summary
            stats['raw_bin_metadata'] = self.metadata
            header = (self.full_report() + '\n' + '=' * 65 + '\n'
                      + 'DETAILED AIRCAT ANALYSIS — SELECTED REPLAY WINDOW\n'
                      + f'Start: {start_seconds / 3600:.3f} h · Length: {duration_seconds / 60:.0f} min\n'
                      + f'CRC-valid frames in window: {len(records):,}\n'
                      + 'Replay time is ESTIMATED (no per-frame timestamps in RAW BIN).\n\n')
            report = header + build_report(stats, self.path.name)
            self.owner.file_analysis_queue.put(('done', str(self.path), records, stats, report))
        except Exception as exc:
            self.replay_requested = False
            self.owner.file_analysis_queue.put(('error', 'BIN Analysis / Replay: ' + str(exc)))


# Independent observer used ONLY by the synthetic TCP LAB path.
class LabBSCObserver(BSCObserver):
    def lab_gap(self):
        self._reset_frame()
        self.roll.clear()
        if self._rotation is not None:
            self.invalid_rotations += 1
        self._rotation = None

    def _valid_sector(self, payload):
        if self._rotation is not None and len(payload)>=2:
            previous=self._rotation.get('last')
            if previous is not None and payload[1]<=previous:
                self.invalid_rotations += 1
                self._rotation = None
                self._lab_ambiguous=True
        return super()._valid_sector(payload)

    def lab_feed(self, data):
        # The laboratory generator sends only the small synthetic NORTH/sector
        # messages. Reject non-fixture records instead of using this path as
        # an operational acquisition interface.
        self._lab_ambiguous=False
        if len(data) not in (14,15,16) or data[:4]!=b'\x32\x32\x32\x01' or data[5:8]!=b'\x40\x10\x02' or data[-4:-2]!=b'\x10\x03':
            self.lab_gap()
            return [],False
        body,ok=decode_transparent_bsc(data[8:-4])
        synthetic=(data[4]==0x19 and body==b'\xfd\x00\x00\x00') or (data[4]==0x0c and len(body)==2 and body[0]==0xfd and body[1]<32)
        if not ok or not synthetic:
            self.lab_gap()
            return [],False
        events=self.feed(data)
        valid=len(events)==1 and events[0].get('result')=='CRC OK' and not self._lab_ambiguous
        if not valid:self.lab_gap()
        return events,valid


class AircatStatsApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_TITLE} v{APP_VERSION}")
        self.root.geometry(APP_SIZE)
        self.root.minsize(1240, 660)
        self.report_text = ""
        self.current_file = None
        self.current_records = None
        self.last_stats = None
        self.filter_mode = tk.StringVar(value="UDP packets only")
        self.report_font_family = "Consolas"
        self.report_font_size = 10

        # File loading/analysis now runs in a background worker thread.
        # Tk widgets are updated only from the main thread through this queue,
        # so the progress bar keeps moving and the window does not appear frozen
        # during long analyses or report generation.
        self.file_analysis_running = False
        self.file_analysis_thread = None
        self.file_analysis_queue = queue.Queue()
        self.file_analysis_after_id = None

        self.liveplay_button = None
        self.liveplay_button_default_bg = None
        self.liveplay_button_default_fg = None
        self.live_capture_source = None  # 'ethernet', 'usb', 'wifi'
        self.live_usb_stop_flag = threading.Event()
        self.live_usb_data_com = ''
        self.live_usb_observer = None
        self.live_usb_observer_lock = threading.Lock()
        self.live_usb_frame_count = 0
        self.live_usb_session_id = 0
        self.sync_monitor_window = None
        self.wifi_monitor_window = None
        self.wifi_receiver = None
        self.wifi_pin = '1234'
        self.live_wifi_packets_lost = 0
        self.live_wifi_invalid = 0
        self.live_wifi_overflow = 0
        self.live_wifi_clock_hz = 0
        self.live_capture_running = False
        self.live_capture_proc = None
        self.live_capture_thread = None
        self.live_capture_queue = queue.Queue()
        self.live_capture_after_id = None
        self.live_render_after_id = None
        self.live_display_dirty = False
        self.live_last_render_time = 0.0
        self.live_monitor_after_id = None
        self.live_non_aircat_lock = threading.Lock()
        self.live_non_aircat_ignored_total = 0
        self.live_non_aircat_ignored_rate = 0.0
        self.live_non_aircat_ignored_window_count = 0
        self.live_non_aircat_ignored_window_start = time.perf_counter()
        self.live_alert_after_id = None
        self.live_capture_window = None
        self.live_canvas = None
        self.live_status_var = None
        self.live_state = None
        self.live_interface_label = ""
        self.live_record_button = None
        self.live_record_button_default_bg = None
        self.live_record_button_default_fg = None
        self.live_udp_recording = False
        self.live_udp_record_start_time = None
        self.live_udp_recorded_packets = []  # Legacy in-memory list is kept empty; safe recording writes live to disk.
        self.live_udp_recorded_packet_count = 0
        self.live_udp_record_path = None
        self.live_udp_record_file = None
        self.live_udp_record_writer = None
        self.live_udp_record_metadata = {}
        self.live_usb_record_start_counts = {}
        self.live_usb_record_start_uncertain = 0
        self.live_udp_record_queue = None
        self.live_udp_record_writer_thread = None
        self.live_udp_record_lock = threading.Lock()
        self.live_udp_record_last_error = None
        self.live_record_timer_after_id = None
        self.live_udp_record_filter_lock = threading.Lock()
        self.live_udp_record_filter_settings = {
            'aircat_like_only': True,
            'radar_sector': True,
            'north_signal': True,
            'radar_extension': True,
            'processor_state': True,
            'weather': True,
            'other_aircat': True,
            'non_aircat_udp': False,
        }
        self.live_record_filter_aircat_like_only_var = tk.BooleanVar(value=True)
        self.live_record_filter_radar_sector_var = tk.BooleanVar(value=True)
        self.live_record_filter_north_signal_var = tk.BooleanVar(value=True)
        self.live_record_filter_radar_extension_var = tk.BooleanVar(value=True)
        self.live_record_filter_processor_state_var = tk.BooleanVar(value=True)
        self.live_record_filter_weather_var = tk.BooleanVar(value=True)
        self.live_record_filter_other_aircat_var = tk.BooleanVar(value=True)
        self.live_record_filter_non_aircat_udp_var = tk.BooleanVar(value=False)
        self.live_show_psr_var = tk.BooleanVar(value=True)
        self.live_show_weather_var = tk.BooleanVar(value=True)
        self.live_show_mode_a_var = tk.BooleanVar(value=True)
        self.live_show_mode_c_var = tk.BooleanVar(value=True)
        self.live_track_cancellation_enable_var = tk.BooleanVar(value=False)
        self.live_show_velocity_vector_var = tk.BooleanVar(value=False)
        self.live_show_velocity_dxdy_var = tk.BooleanVar(value=False)
        self.live_show_range_var = tk.BooleanVar(value=False)
        self.live_coordinate_scale_var = tk.StringVar(value=DEFAULT_COORDINATE_SCALE)
        self.live_show_speed_var = tk.BooleanVar(value=False)
        self.live_show_low_quality_tracks_var = tk.BooleanVar(value=True)
        self.live_show_high_quality_tracks_var = tk.BooleanVar(value=True)
        self.live_show_quality_q_var = tk.BooleanVar(value=False)
        self.live_show_detection_misses_var = tk.BooleanVar(value=False)
        self.live_show_track_number_var = tk.BooleanVar(value=False)
        self.live_show_tpr_var = tk.BooleanVar(value=False)
        self.live_show_log_sigma_var = tk.BooleanVar(value=False)
        self.live_show_time_since_north_var = tk.BooleanVar(value=False)
        self.live_show_tracking_window_var = tk.BooleanVar(value=False)
        self.live_show_smoothing_k_var = tk.BooleanVar(value=False)
        self.live_show_psr_airport_var = tk.BooleanVar(value=False)
        self.live_show_psr_test_beacon_var = tk.BooleanVar(value=False)

        self.build_ui()
        self._trial_locked = False
        self.root.after(0, self._expiry_tick)

    def _expiry_tick(self):
        if self._trial_locked:
            return
        if self._is_license_expired():
            self._lock_after_expiry()
            return
        self.root.after(30000, self._expiry_tick)

    def _lock_after_expiry(self):
        if self._trial_locked:
            return
        self._trial_locked = True
        # Stop active recording before discarding the operational GUI.
        if self.sync_monitor_window is not None:
            try:
                self.sync_monitor_window.on_close()
            except Exception:
                pass
        try:
            self.stop_live_capture()
        except Exception:
            pass
        try:
            for child in list(self.root.winfo_children()):
                if isinstance(child, tk.Toplevel):
                    child.destroy()
        except Exception:
            pass
        for child in list(self.root.winfo_children()):
            try:
                child.destroy()
            except tk.TclError:
                pass
        # Drop the original application menu: after expiry only About / Exit.
        try:
            self.root.configure(menu='')
        except tk.TclError:
            pass
        self.root.unbind_all('<Control-o>')
        self.root.unbind_all('<Control-O>')
        self.root.unbind_all('<Control-s>')
        self.root.unbind_all('<Control-S>')
        self.root.title(f'{APP_TITLE} v{APP_VERSION} — Ολοκλήρωση δοκιμαστικής λειτουργίας')
        holder = ttk.Frame(self.root, padding=40)
        holder.pack(expand=True)
        ttk.Label(holder, text='Ολοκλήρωση δοκιμαστικής λειτουργίας',
                  font=('Segoe UI', 19, 'bold')).pack(pady=(0, 20))
        ttk.Label(holder, text=f'Η δοκιμαστική περίοδος ολοκληρώθηκε στις {LICENSE_EXPIRY_DATE:%d/%m/%Y}.').pack(pady=(0, 20))
        ttk.Button(holder, text='About', command=self.show_about).pack(side='left', padx=15)
        ttk.Button(holder, text='Exit / Κλείσιμο', command=self.root.destroy).pack(side='left', padx=15)
        self.root.protocol('WM_DELETE_WINDOW', self.root.destroy)

    def center_window(self, width=1180, height=620):
        self.root.update_idletasks()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        x = max((screen_w - width) // 2, 0)
        y = max((screen_h - height) // 2, 0)
        self.root.geometry(f"{width}x{height}+{x}+{y}")


    def center_toplevel_near_screen(self, win, min_width=760, min_height=620,
                                    margin_x=120, margin_y=120,
                                    width_ratio=0.68, height_ratio=0.84,
                                    max_width_cap=None, max_height_cap=None,
                                    grow_y_up_ratio=0.0):
        """Open a Toplevel safely centered and compact inside the visible screen.

        Replay / LivePlay should feel like focused working windows, not almost
        maximized windows. The size is therefore based on compact screen ratios
        plus hard caps, and it is clamped so it always stays fully visible.
        grow_y_up_ratio increases the height upward, keeping the bottom edge
        practically stable when there is available screen space.
        """
        try:
            win.update_idletasks()
            screen_w = max(1, int(win.winfo_screenwidth()))
            screen_h = max(1, int(win.winfo_screenheight()))

            safe_margin_x = max(40, int(margin_x))
            safe_margin_y = max(40, int(margin_y))
            usable_w = max(640, screen_w - (2 * safe_margin_x))
            usable_h = max(480, screen_h - (2 * safe_margin_y))

            width = max(int(min_width), int(screen_w * float(width_ratio)))
            height = max(int(min_height), int(screen_h * float(height_ratio)))

            if max_width_cap is not None:
                width = min(width, int(max_width_cap))
            if max_height_cap is not None:
                height = min(height, int(max_height_cap))

            width = min(width, usable_w, max(640, screen_w - 60))
            height = min(height, usable_h, max(480, screen_h - 100))

            width = max(640, width)
            height = max(480, height)

            x = max((screen_w - width) // 2, 0)
            y = max((screen_h - height) // 2, 0)

            if grow_y_up_ratio and grow_y_up_ratio > 0:
                base_height = height
                base_y = y
                bottom_edge = min(screen_h, base_y + base_height)
                target_height = int(round(base_height * (1.0 + float(grow_y_up_ratio))))
                # Grow upward as much as possible without moving the bottom edge
                # downward and without leaving the visible screen.
                height = min(target_height, bottom_edge, max(480, screen_h - 60))
                height = max(base_height, height)
                y = max(0, bottom_edge - height)

            try:
                win.maxsize(max(640, screen_w - 40), max(480, screen_h - 80))
            except Exception:
                pass

            geom = f"{width}x{height}+{x}+{y}"
            win.geometry(geom)
            win.update_idletasks()
            # Re-apply after Tk computes the child widgets.
            win.geometry(geom)
            return width, height
        except Exception:
            try:
                win.geometry(f"{min_width}x{min_height}")
            except Exception:
                pass
            return min_width, min_height

    def _nested_count_total(self, stats_key):
        """Return the total count inside a nested {source: {bucket: count}} stats entry."""
        try:
            root = (self.last_stats or {}).get(stats_key, {}) or {}
            total = 0
            for src_counts in root.values():
                if isinstance(src_counts, dict):
                    total += sum(int(v or 0) for v in src_counts.values())
                else:
                    total += int(src_counts or 0)
            return total
        except Exception:
            return 0

    def optional_field_available(self, field_name):
        """Return True only when analysis found the optional AIRCAT field in the capture."""
        field_name = str(field_name or '').lower()
        if field_name in ('tracking_window', 'time_since_north', 'timing'):
            return self._nested_count_total('tracking_window_counts_by_source') > 0
        if field_name in ('smoothing_k', 'k'):
            return self._nested_count_total('smoothing_k_counts_by_source') > 0
        if field_name in ('log_sigma', 'logsigma'):
            return self._nested_count_total('log_sigma_counts_by_source') > 0
        if field_name in ('tpr', 'tpr_number', 'tpr_source'):
            return self._nested_count_total('tpr_counts_by_source') > 0
        if field_name in ('psr_airport', 'airport', 'fast_slow_airport'):
            root = (self.last_stats or {}).get('psr_service_counts_by_source', {}) or {}
            psr = root.get('PSR', {}) or {}
            return int(psr.get('Slow airport track', 0) or 0) + int(psr.get('Fast airport/outside track', 0) or 0) > 0
        if field_name in ('psr_test', 'test_beacon', 'psr_test_beacon'):
            root = (self.last_stats or {}).get('psr_service_counts_by_source', {}) or {}
            psr = root.get('PSR', {}) or {}
            return int(psr.get('BT test beacon', 0) or 0) + int(psr.get('TVD900 test plot', 0) or 0) > 0
        return False


    def build_ui(self):
        # v10.0: crisp neutral-gray controls, high contrast, LivePlay first.
        self.palette = {
            'bg': '#efefef', 'bar': '#dddddd', 'button': '#f7f7f7',
            'navy': '#101010', 'border': '#b5b5b5', 'accent': '#e0e0e0',
            'hover': '#dedede', 'live': '#bcbcbc', 'status': '#efefef',
        }
        p = self.palette
        self.root.configure(bg=p['bg'])
        top = tk.Frame(self.root, bg=p['bar'], highlightbackground=p['border'],
                       highlightthickness=1, bd=0)
        top.pack(fill='x', padx=7, pady=(7, 5))

        def action(label, command, prominent=False):
            button = tk.Button(
                top, text=label, command=command, font=('Segoe UI', 10, 'normal'),
                bg=p['accent'] if prominent else p['button'],
                fg=p['navy'],
                activebackground=p['live'] if prominent else p['hover'],
                activeforeground=p['navy'],
                relief='raised', bd=1, padx=7, pady=8,
                highlightthickness=0, cursor='hand2',
            )
            button.pack(side='left', padx=(2, 2), pady=4)
            if not prominent:
                button.bind('<Enter>', lambda ev, b=button: b.configure(bg=p['hover']))
                button.bind('<Leave>', lambda ev, b=button: b.configure(bg=p['button']))
            return button

        # Navigation order: monitoring comes before offline files.
        self.liveplay_button = action('LivePlay / Monitor', self.show_liveplay_monitor_menu, prominent=True)
        self.liveplay_button_default_bg = self.liveplay_button.cget('bg')
        self.liveplay_button_default_fg = self.liveplay_button.cget('fg')
        action('Άνοιγμα αρχείου', self.open_file)
        action('Αποθήκευση report', self.save_report)
        action('Φίλτρα', self.show_filters)
        action('Πίνακες σφαλμάτων', self.show_tables)
        action('Alerts', self.show_alerts)
        action('Ραβδόγραμμα', self.show_bar_chart)
        action('Replay', self.show_replay)
        action('About', self.show_about)
        action('Help', self.show_help)

        self._top_toolbar = top
        self._toolbar_buttons = [w for w in top.winfo_children() if isinstance(w, tk.Button)]
        self._toolbar_compact = False
        # Display scaling varies across Windows PCs; keep all buttons on one row.
        self.root.bind('<Configure>', self._fit_main_toolbar, add='+')
        self.root.after_idle(self._fit_main_toolbar)

        prog_frame = tk.Frame(self.root, bg=p['bg'])
        prog_frame.pack(fill='x', padx=10, pady=(0, 7))
        self.progress_var = tk.DoubleVar(value=0.0)
        pstyle = ttk.Style(self.root)
        pstyle.configure('Aviation.Horizontal.TProgressbar', troughcolor='#c9c9c9',
                         background='#737373', thickness=15, bordercolor='#a5a5a5')
        self.progress = ttk.Progressbar(
            prog_frame, orient='horizontal', mode='determinate',
            variable=self.progress_var, maximum=100.0, style='Aviation.Horizontal.TProgressbar')
        self.progress.pack(fill='x', side='top')
        self.status_label = tk.Label(prog_frame, text='Έτοιμο.', anchor='w',
                                     bg=p['bg'], fg=p['navy'], font=('Segoe UI', 9))
        self.status_label.pack(fill='x', side='top', pady=(4, 0))

        self.text = scrolledtext.ScrolledText(
            self.root,
            wrap='word',
            font=(self.report_font_family, self.report_font_size),
            exportselection=False,
            bg='#fafafa', fg='#151515', insertbackground='#151515',
            selectbackground='#c9c9c9', relief='solid', bd=1,
        )
        self.text.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        self.text.insert("end", "Πάτησε «Άνοιγμα αρχείου» και διάλεξε BIN/PCAPNG/PCAP/CSV.\n")
        self.text.bind("<Control-a>", self.select_all_text)
        self.text.bind("<Control-A>", self.select_all_text)
        self.text.bind("<Control-Key-a>", self.select_all_text)
        self.text.bind("<Control-Key-A>", self.select_all_text)
        self.text.bind("<Control-c>", self.copy_selected_text)
        self.text.bind("<Control-C>", self.copy_selected_text)
        self.text.bind("<Control-Key-c>", self.copy_selected_text)
        self.text.bind("<Control-Key-C>", self.copy_selected_text)
        self.text.bind("<<Copy>>", self.copy_selected_text)
        self.root.bind_all("<KeyPress>", self.handle_global_copy_keys, add="+")
        self.text.bind("<Control-plus>", self.increase_report_font)
        self.text.bind("<Control-KP_Add>", self.increase_report_font)
        self.text.bind("<Control-equal>", self.increase_report_font)
        self.text.bind("<Control-minus>", self.decrease_report_font)
        self.text.bind("<Control-KP_Subtract>", self.decrease_report_font)
        self.text.bind("<Control-underscore>", self.decrease_report_font)
        self.text.bind("<Button-3>", self.show_text_context_menu)
        self.center_window(1240, 660)

    def _fit_main_toolbar(self, event=None):
        """Use regular readable text when it fits; compact only on narrow displays."""
        try:
            if event is not None and event.widget is not self.root:
                return
            buttons = self._toolbar_buttons
            if not buttons:
                return
            available = max(300, int(self.root.winfo_width()) - 22)
            # Text widths are computed in physical pixels after DPI initialization.
            import tkinter.font as tkfont_local
            regular = tkfont_local.Font(root=self.root, family='Segoe UI', size=10)
            compact = tkfont_local.Font(root=self.root, family='Segoe UI', size=9)
            label_total = sum(regular.measure(button.cget('text')) + 34 for button in buttons)
            cramped = label_total > available
            if cramped != self._toolbar_compact:
                self._toolbar_compact = cramped
                for button in buttons:
                    button.configure(font=('Segoe UI', 9 if cramped else 10, 'normal'),
                                     padx=3 if cramped else 7,
                                     pady=6 if cramped else 8)
        except (tk.TclError, ValueError):
            pass

    def _apply_report_font_size(self):
        self.report_font_size = max(7, min(28, int(self.report_font_size)))
        self.text.configure(font=(self.report_font_family, self.report_font_size))
        try:
            self.status_label.config(text=f"Report font size: {self.report_font_size}")
        except Exception:
            pass

    def increase_report_font(self, event=None):
        self.report_font_size += 1
        self._apply_report_font_size()
        return "break"

    def decrease_report_font(self, event=None):
        self.report_font_size -= 1
        self._apply_report_font_size()
        return "break"

    def set_progress(self, percent, message):
        self.progress_var.set(percent)
        self.status_label.config(text=f"{percent:.1f}% - {message}")
        self.root.update_idletasks()

    def _queue_file_analysis_progress(self, percent, message):
        """Thread-safe progress callback used by the file analysis worker."""
        try:
            self.file_analysis_queue.put(("progress", float(percent), str(message)))
        except Exception:
            pass

    def _start_file_analysis_worker(self, path, selected_mode):
        """Start load/analyze/report in a worker thread so Tk never freezes."""
        if getattr(self, 'file_analysis_running', False):
            return

        self.file_analysis_running = True
        self.file_analysis_queue = queue.Queue()
        self.file_analysis_thread = threading.Thread(
            target=self._file_analysis_worker,
            args=(path, selected_mode),
            daemon=True
        )
        self.file_analysis_thread.start()

        try:
            if self.file_analysis_after_id is not None:
                self.root.after_cancel(self.file_analysis_after_id)
        except Exception:
            pass
        self.file_analysis_after_id = self.root.after(50, self._poll_file_analysis_queue)

    def _file_analysis_worker(self, path, selected_mode):
        """Worker thread: no direct Tk calls here."""
        try:
            self._queue_file_analysis_progress(0.0, "Έναρξη...")

            udp_only_loader = selected_mode != "All packets"
            ext = os.path.splitext(path)[1].lower()

            if ext == ".pcapng":
                records = load_from_pcapng(path, self._queue_file_analysis_progress, udp_only=udp_only_loader)
            elif ext == ".pcap":
                records = load_from_pcap(path, self._queue_file_analysis_progress, udp_only=udp_only_loader)
            elif ext == ".csv":
                with open(path,encoding='utf-8-sig',newline='') as f:
                    header=next(csv.reader(f),[])
                if 'capture_event' in header:
                    result=analyze_lab_file(path)
                    report='TCP LAB — Offline continuity audit\n\n'+json.dumps(result,ensure_ascii=False,indent=2)
                    self.file_analysis_queue.put(("lab_done",path,report))
                    return
                records = load_from_csv(path, self._queue_file_analysis_progress)
            else:
                raise ValueError("Για RAW .bin χρησιμοποίησε το κεντρικό Open File. Υποστηρίζονται επίσης .pcapng, .pcap και .csv")

            if selected_mode == "AIRCAT-like only":
                self._queue_file_analysis_progress(0.0, "Φιλτράρισμα AIRCAT-like packets...")
                records = [r for r in records if is_aircat_like_payload(r.get('payload', b''))]
            elif selected_mode == "Known AIRCAT only":
                self._queue_file_analysis_progress(0.0, "Φιλτράρισμα known AIRCAT packets...")
                records = [r for r in records if is_known_aircat_payload(r.get('payload', b''))]

            if not records:
                raise ValueError("Δεν βρέθηκαν χρήσιμα payloads μέσα στο αρχείο με το επιλεγμένο φίλτρο.")

            self._queue_file_analysis_progress(0.0, "Έναρξη ανάλυσης...")
            stats = analyze_records(records, self._queue_file_analysis_progress)
            stats['filter_mode'] = selected_mode
            if ext == '.csv':
                sidecar = Path(str(path) + '.meta.json')
                if sidecar.is_file():
                    try:
                        info = json.loads(sidecar.read_text(encoding='utf-8'))
                        if (info.get('format') ==
                                'AIRCAT500 LivePlay CRC-valid payload CSV + USB diagnostics'):
                            stats['usb_record_sidecar'] = info
                    except (ValueError, OSError, TypeError, AttributeError):
                        pass

            # Report creation can also take noticeable time on large files.
            # Keep it in the worker and park the progress at 99% until it is ready.
            self._queue_file_analysis_progress(99.0, "Δημιουργία report...")
            report = build_report(stats, os.path.basename(path))

            self.file_analysis_queue.put(("done", path, records, stats, report))
        except Exception as exc:
            self.file_analysis_queue.put(("error", str(exc)))

    def _poll_file_analysis_queue(self):
        """Apply worker updates on the Tk main thread."""
        try:
            processed = 0
            while processed < 200:
                try:
                    item = self.file_analysis_queue.get_nowait()
                except queue.Empty:
                    break

                processed += 1
                kind = item[0]

                if kind == "progress":
                    _, percent, message = item
                    self.set_progress(percent, message)

                elif kind == "lab_done":
                    _, path, report = item
                    browser=getattr(self,'_raw_bin_browser',None)
                    if browser is not None:
                        try:browser.close()
                        except Exception:pass
                    self._raw_bin_browser=None
                    self.last_stats=None
                    self.current_records=None
                    self.current_file=path
                    self.report_text=report
                    self.text.delete("1.0","end")
                    self.text.insert("end",report)
                    self.set_progress(100.0,"LAB audit complete; legacy replay/charts unavailable for this format.")
                    self.file_analysis_running=False

                elif kind == "done":
                    _, path, records, stats, report = item
                    self.last_stats = stats
                    self.report_text = report
                    self.current_file = path
                    self.current_records = records

                    self.text.delete("1.0", "end")
                    self.text.insert("end", report)
                    self.set_progress(100.0, "Έτοιμο.")
                    self.file_analysis_running = False
                    browser = getattr(self, '_raw_bin_browser', None)
                    if browser is not None and getattr(browser, 'replay_requested', False):
                        browser.replay_requested = False
                        self.root.after(100, self.show_replay)

                elif kind == "error":
                    _, message = item
                    self.set_progress(0.0, "Σφάλμα.")
                    self.file_analysis_running = False
                    messagebox.showerror("Σφάλμα", message)

        finally:
            if getattr(self, 'file_analysis_running', False):
                self.file_analysis_after_id = self.root.after(50, self._poll_file_analysis_queue)
            else:
                self.file_analysis_after_id = None


    def _is_control_pressed(self, event):
        return bool(getattr(event, "state", 0) & 0x0004)

    def _show_track_raw_payload_window(self, track, title_prefix="Target raw payload"):
        """Show a small read-only text window with the raw AIRCAT target payload."""
        try:
            raw_txt = _track_raw_payload_text(track)
            if not raw_txt:
                raw_txt = "Raw payload not available for this target."

            track_no = track.get('track_no') if isinstance(track, dict) else None
            type_i = int(track.get('type', 0) or 0) if isinstance(track, dict) else 0
            src = "MSSR/SSR" if type_i == 0xFF else ("PSR" if type_i == 0xFE else f"0x{type_i:02X}")
            frame_no = track.get('source_frame_no') if isinstance(track, dict) else None
            ts = track.get('source_time') if isinstance(track, dict) else None

            lines = [
                f"{src} Track #{track_no if track_no is not None else 'n/a'}",
            ]
            if frame_no is not None:
                lines.append(f"Wireshark Frame #{frame_no}")
            if ts is not None:
                try:
                    lines.append(f"Time: {format_capture_time(ts)}")
                except Exception:
                    lines.append(f"Time: {ts}")
            lines.extend([
                "",
                f"Raw target payload ({track.get('raw_track_payload_len', 'n/a') if isinstance(track, dict) else 'n/a'} bytes):",
                raw_txt,
            ])
            body = "\n".join(lines)

            win = tk.Toplevel(self.root)
            win.title(title_prefix)
            win.resizable(True, True)
            try:
                win.transient(self.root)
            except Exception:
                pass

            frame = ttk.Frame(win, padding=8)
            frame.pack(fill="both", expand=True)

            txt = scrolledtext.ScrolledText(frame, wrap="word", width=78, height=14)
            txt.pack(fill="both", expand=True)
            txt.insert("1.0", body)
            txt.configure(state="disabled")

            buttons = ttk.Frame(frame)
            buttons.pack(fill="x", pady=(8, 0))

            def copy_raw():
                try:
                    self.root.clipboard_clear()
                    self.root.clipboard_append(raw_txt)
                except Exception:
                    pass

            ttk.Button(buttons, text="Copy raw", command=copy_raw).pack(side="left")
            ttk.Button(buttons, text="Close", command=win.destroy).pack(side="right")

            self.center_toplevel_near_screen(
                win, min_width=720, min_height=340,
                margin_x=180, margin_y=160,
                width_ratio=0.46, height_ratio=0.34,
                max_width_cap=900, max_height_cap=520
            )
            try:
                txt.focus_set()
            except Exception:
                pass
        except Exception as exc:
            try:
                messagebox.showerror("Raw payload", str(exc))
            except Exception:
                pass
        return "break"

    def _show_current_scan_raw_window(self, scan_items, selected_track=None, title_prefix="Current scan raw data"):
        """Show raw data from the current North up to the selected target payload."""
        try:
            items = list(scan_items or [])
            rows = []
            selected_found = False

            for item in items:
                if not isinstance(item, dict):
                    continue
                payload = item.get('payload')
                rec = item.get('rec') if isinstance(item.get('rec'), dict) else None
                if payload is None and rec is not None:
                    payload = rec.get('payload')
                if payload is None:
                    payload = item.get('_payload', b'')
                payload = payload or b''

                frame_no = item.get('frame_no')
                if frame_no is None and rec is not None:
                    frame_no = rec.get('frame_no')
                ts = item.get('time')
                if ts is None and rec is not None:
                    ts = rec.get('timestamp')
                kind = item.get('kind') or 'other'
                sector = item.get('sector')
                meta = _scan_window_meta_text(frame_no, ts)
                info = classify_aircat_payload(payload) if payload else None

                if kind == 'north' or (info and info.get('is_north')):
                    rows.append((f"{meta} | North Signal | {_raw_bytes_to_spaced_hex(payload)}", 'north'))
                    continue

                if kind == 'sector' or (info and info.get('is_sector')):
                    if sector is None and info:
                        sector = info.get('sector')
                    sector_txt = f"Sector {int(sector):02X}" if sector is not None else "Sector"
                    rows.append((f"{meta} | {sector_txt}", None))
                    entries, found = _aircat_payload_scan_entries(payload, selected_track, stop_at_selected=True)
                    if entries:
                        for entry in entries:
                            rows.append((entry.get('text', ''), entry.get('tag')))
                    else:
                        rows.append((f"  Raw payload: {_raw_bytes_to_spaced_hex(payload)}", None))
                    if found:
                        selected_found = True
                        break
                    continue

                label = item.get('label')
                if not label:
                    if info and info.get('type') == 0x2A:
                        label = 'Weather'
                    elif info and info.get('type_name'):
                        label = info.get('type_name')
                    else:
                        label = 'Other UDP payload'
                rows.append((f"{meta} | {label} | {_raw_bytes_to_spaced_hex(payload)}", None))

            if selected_track is not None and not selected_found:
                raw_txt = _track_raw_payload_text(selected_track)
                if raw_txt:
                    rows.append(("Selected target payload:", None))
                    rows.append((raw_txt, 'target_selected'))

            body_lines = [txt for txt, _tag in rows] or ["No current scan raw data available."]

            win = tk.Toplevel(self.root)
            win.title(title_prefix)
            win.resizable(True, True)
            try:
                win.transient(self.root)
            except Exception:
                pass

            frame = ttk.Frame(win, padding=8)
            frame.pack(fill="both", expand=True)

            txt = scrolledtext.ScrolledText(frame, wrap="none", width=118, height=28)
            txt.pack(fill="both", expand=True)
            try:
                txt.tag_configure('north', foreground='red')
                txt.tag_configure('target', foreground='blue')
                txt.tag_configure('target_selected', foreground='blue', font=(self.report_font_family, max(9, self.report_font_size), 'bold'))
            except Exception:
                pass

            if rows:
                for line, tag in rows:
                    try:
                        if tag:
                            txt.insert('end', line + "\n", tag)
                        else:
                            txt.insert('end', line + "\n")
                    except Exception:
                        txt.insert('end', str(line) + "\n")
            else:
                txt.insert('end', "No current scan raw data available.\n")
            txt.configure(state="disabled")

            buttons = ttk.Frame(frame)
            buttons.pack(fill="x", pady=(8, 0))

            def copy_all():
                try:
                    self.root.clipboard_clear()
                    self.root.clipboard_append("\n".join(body_lines))
                except Exception:
                    pass

            ttk.Button(buttons, text="Copy all", command=copy_all).pack(side="left")
            ttk.Button(buttons, text="Close", command=win.destroy).pack(side="right")

            self.center_toplevel_near_screen(
                win, min_width=980, min_height=520,
                margin_x=80, margin_y=80,
                width_ratio=0.74, height_ratio=0.66,
                max_width_cap=1450, max_height_cap=860
            )
            try:
                txt.focus_set()
            except Exception:
                pass
        except Exception as exc:
            try:
                messagebox.showerror("Current scan raw data", str(exc))
            except Exception:
                pass
        return "break"

    def _live_append_current_scan_record(self, rec, info=None, kind=None, sector=None):
        """Store raw packets in the current LivePlay scan for Ctrl+drag inspection."""
        if self.live_state is None:
            return None
        if kind is None:
            if info and info.get('is_north'):
                kind = 'north'
            elif info and info.get('is_sector'):
                kind = 'sector'
            elif info and info.get('type') == 0x2A:
                kind = 'weather'
            else:
                kind = 'other'
        if sector is None and info:
            sector = info.get('sector')
        records = self.live_state.setdefault('current_scan_records', [])
        records.append({
            'kind': kind,
            'rec': rec,
            'payload': rec.get('payload', b'') if isinstance(rec, dict) else b'',
            'frame_no': rec.get('frame_no') if isinstance(rec, dict) else None,
            'time': rec.get('timestamp') if isinstance(rec, dict) else None,
            'sector': sector,
            'label': (info or {}).get('type_name') if isinstance(info, dict) else None,
        })
        return len(records) - 1

    def _show_live_current_scan_raw_for_track(self, track):
        records = []
        try:
            records = list((self.live_state or {}).get('current_scan_records', []) or [])
            idx = track.get('source_live_scan_index') if isinstance(track, dict) else None
            if idx is not None and records:
                idx = max(0, min(int(idx), len(records) - 1))
                records = records[:idx + 1]
        except Exception:
            pass
        return self._show_current_scan_raw_window(records, track, "LivePlay current scan raw data")

    def _copy_treeview_selection(self, tree):
        selected = list(tree.selection())
        if not selected:
            focus_item = tree.focus()
            selected = [focus_item] if focus_item else []
        if not selected:
            return False

        copied_lines = []
        for item_id in selected:
            values = tree.item(item_id, "values")
            copied_lines.append("\t".join(str(v) for v in values))

        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(copied_lines))
        return True

    def _copy_text_selection(self, widget):
        try:
            selected = widget.get("sel.first", "sel.last")
        except Exception:
            return False
        if not selected:
            return False
        self.root.clipboard_clear()
        self.root.clipboard_append(selected)
        return True

    def copy_active_selection(self, event=None):
        widget = None
        try:
            widget = self.root.focus_get()
        except Exception:
            widget = None

        if isinstance(widget, tk.Text):
            if self._copy_text_selection(widget):
                return "break"

        try:
            if widget is not None and widget.winfo_class() == "Treeview":
                if self._copy_treeview_selection(widget):
                    return "break"
        except Exception:
            pass

        if self._copy_text_selection(self.text):
            return "break"

        return None

    def select_all_active(self, event=None):
        widget = None
        try:
            widget = self.root.focus_get()
        except Exception:
            widget = None

        if isinstance(widget, tk.Text):
            widget.tag_add("sel", "1.0", "end-1c")
            widget.mark_set("insert", "1.0")
            widget.see("insert")
            return "break"

        try:
            if widget is not None and widget.winfo_class() == "Treeview":
                widget.selection_set(widget.get_children(""))
                return "break"
        except Exception:
            pass

        self.text.tag_add("sel", "1.0", "end-1c")
        self.text.mark_set("insert", "1.0")
        self.text.see("insert")
        return "break"

    def handle_global_copy_keys(self, event):
        # Robust handling for different keyboard layouts. Ctrl+C often arrives as char \x03,
        # and Ctrl+A as char \x01 even when the active layout is not English.
        if not self._is_control_pressed(event):
            return None

        ch = getattr(event, "char", "")
        keysym = str(getattr(event, "keysym", "")).lower()

        if ch == "\x03" or keysym in ("c", "insert"):
            return self.copy_active_selection(event)

        if ch == "\x01" or keysym == "a":
            return self.select_all_active(event)

        return None

    def select_all_text(self, event=None):
        return self.select_all_active(event)

    def copy_selected_text(self, event=None):
        return self.copy_active_selection(event)

    def show_text_context_menu(self, event):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Copy", command=lambda: self.copy_selected_text())
        menu.add_command(label="Select All", command=lambda: self.select_all_text())
        menu.tk_popup(event.x_root, event.y_root)

    def _set_liveplay_button_state(self, active: bool):
        if not self.liveplay_button:
            return
        try:
            if active:
                self.liveplay_button.config(
                    bg="#bababa", fg="#111111",
                    activebackground="#acacac", activeforeground="#111111",
                    relief="sunken"
                )
            else:
                self.liveplay_button.config(
                    bg=self.liveplay_button_default_bg,
                    fg=self.liveplay_button_default_fg,
                    activebackground=self.liveplay_button_default_bg,
                    activeforeground=self.liveplay_button_default_fg,
                    relief="raised"
                )
        except Exception:
            pass

    def _find_tshark_path(self):
        candidates = [
            shutil.which("tshark"),
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        return None

    def _find_dumpcap_path(self):
        candidates = [
            shutil.which("dumpcap"),
            r"C:\Program Files\Wireshark\dumpcap.exe",
            r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        return None

    def _pick_ethernet_interface(self, tshark_path):
        def run_interface_list(cmd_path, label):
            if not cmd_path:
                return [], "", f"{label}: not found"
            try:
                kwargs = {}
                if hasattr(subprocess, "CREATE_NO_WINDOW"):
                    kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
                res = subprocess.run(
                    [cmd_path, "-D"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    encoding="utf-8",
                    errors="ignore",
                    **kwargs
                )
                combined = ((res.stdout or "") + "\n" + (res.stderr or "")).strip()
                return combined.splitlines(), combined, f"{label}: rc={res.returncode}"
            except Exception as e:
                return [], "", f"{label}: {e}"

        def score_interface(desc):
            dl = str(desc).lower()
            score = 0

            # Interfaces that are usually not useful for AIRCAT live UDP capture.
            if any(x in dl for x in [
                "loopback", "npcap loopback", "adapter for loopback",
                "bluetooth", "vpn", "virtualbox", "vmware", "hyper-v",
                "pseudo", "tunnel", "teredo", "isatap"
            ]):
                score -= 100

            # Wi-Fi is possible, but not preferred for radar Ethernet streams.
            if any(x in dl for x in ["wi-fi", "wifi", "wireless", "wlan", "802.11"]):
                score -= 10

            # Real Ethernet adapters. Includes Realtek PCIe GbE Family Controller.
            if any(x in dl for x in [
                "ethernet", "realtek", "pci", "pcie", "gbe", "gigabit",
                "intel", "i219", "i210", "i225", "i226",
                "eth", "enp", "eno", "ens"
            ]):
                score += 80

            # NPF device with adapter description in parentheses.
            if "npf_" in dl or "\\device\\npf" in dl:
                score += 5

            return score

        dumpcap_path = self._find_dumpcap_path()

        raw_lines = []
        diagnostics = []

        for cmd_path, label in ((tshark_path, "tshark"), (dumpcap_path, "dumpcap")):
            lines, raw, diag = run_interface_list(cmd_path, label)
            diagnostics.append(diag)
            raw_lines.extend(lines)

        seen = set()
        options = []
        debug_lines = []

        for raw in raw_lines:
            line = raw.strip()
            if not line:
                continue
            debug_lines.append(line)

            # Typical forms:
            #   1. \\Device\\NPF_{GUID} (Realtek PCIe GbE Family Controller)
            #   2. eth0
            #   3. 1. enp3s0
            m = re.match(r"^\s*(\d+)\.\s+(.+?)\s*$", line)
            if not m:
                continue

            idx, desc = m.group(1), m.group(2).strip()
            key = (idx, desc)
            if key in seen:
                continue
            seen.add(key)

            score = score_interface(desc)
            options.append((score, idx, desc))

        # Do not reject non-positive options. On some Windows/Npcap installations
        # tshark -D only shows NPF GUIDs without "Ethernet" / "Realtek" text.
        # In that case we still show the list and let the user choose manually.
        if not options:
            msg = (
                "Δεν βρέθηκε διαθέσιμη διεπαφή capture από tshark/dumpcap.\n\n"
                "Έλεγξε ότι:\n"
                "1) είναι εγκατεστημένο το Wireshark μαζί με Npcap,\n"
                "2) το Npcap έχει εγκατασταθεί με υποστήριξη capture για όλους τους χρήστες,\n"
                "3) το Wireshark/tshark μπορεί να κάνει capture από τη Realtek κάρτα,\n"
                "4) δοκίμασε να τρέξεις το πρόγραμμα ως Administrator.\n\n"
                "Diagnostics:\n"
                + "\n".join(diagnostics)
            )
            if debug_lines:
                msg += "\n\nRaw interface output:\n" + "\n".join(debug_lines[:30])
            messagebox.showerror("LivePlay interfaces", msg)
            return None, None

        # Show all physical-looking and unknown NPF interfaces, but sort best first.
        options.sort(key=lambda x: (-x[0], str(x[1])))

        default_idx = 0

        win = tk.Toplevel(self.root)
        win.title("Επιλογή Ethernet θύρας")
        win.resizable(True, True)
        try:
            win.transient(self.root)
            win.grab_set()
        except Exception:
            pass

        selected = {'value': None}

        frame = ttk.Frame(win, padding=12)
        frame.pack(fill="both", expand=True)

        ttk.Label(
            frame,
            text="Διάλεξε διεπαφή για LivePlay. Αν βλέπεις Realtek PCIe GbE Family Controller, επίλεξέ την:"
        ).pack(anchor="w", pady=(0, 8))

        listbox = tk.Listbox(frame, height=min(14, max(5, len(options))), exportselection=False)
        listbox.pack(fill="both", expand=True)

        for score, idx, desc in options:
            tag = "Ethernet candidate" if score > 0 else "manual choice"
            listbox.insert("end", f"{idx}. {desc}    [{tag}]")

        listbox.selection_set(default_idx)
        listbox.activate(default_idx)
        listbox.see(default_idx)

        info_var = tk.StringVar(value="Tip: Για Realtek επίλεξε τη γραμμή που γράφει Realtek / PCIe / GbE ή το αντίστοιχο NPF device.")
        ttk.Label(frame, textvariable=info_var, anchor="w").pack(fill="x", pady=(8, 0))

        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(10, 0))

        def choose_current(_event=None):
            sel = listbox.curselection()
            if not sel:
                return
            chosen = options[sel[0]]
            selected['value'] = (chosen[1], chosen[2])
            win.destroy()

        def cancel_choice():
            selected['value'] = None
            win.destroy()

        ttk.Button(btns, text="OK", command=choose_current).pack(side="right")
        ttk.Button(btns, text="Cancel", command=cancel_choice).pack(side="right", padx=(0, 8))

        listbox.bind("<Double-Button-1>", choose_current)
        listbox.bind("<Return>", choose_current)
        win.protocol("WM_DELETE_WINDOW", cancel_choice)

        win.update_idletasks()
        ww = max(860, min(1250, win.winfo_reqwidth() + 60))
        wh = max(340, min(620, win.winfo_reqheight() + 30))
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = max((sw - ww) // 2, 0)
        y = max((sh - wh) // 2, 0)
        win.geometry(f"{ww}x{wh}+{x}+{y}")
        listbox.focus_set()

        self.root.wait_window(win)

        if selected['value'] is None:
            return None, None
        return selected['value']

    def _new_live_state(self):
        return {
            'angle_deg': -90.0,
            'sector_memory': {},
            'sector_history': {},
            'history_depth': 0,
            'zoom_factor': 1.0,
            'view_center_x': 0.0,
            'view_center_y': 0.0,
            'pan_start': None,
            'label_offsets': {},
            'label_drag': None,
            'label_track_map': {},
            'label_font_level': 1,
            'max_track_range': 1.0,
            'last_time': None,
            'last_frame_no': None,
            'last_label': '',
            'last_sector': None,
            'current_cycle_active': False,
            'current_cycle_north_time': None,
            'current_cycle_north_frame_no': None,
            'current_cycle_sectors': [],
            'current_scan_records': [],
            'valid_north_times': [],
            'north_intervals_sec': [],
            'sector_alert_curr': 0,
            'sector_alert_total': 0,
            'sector_sequence_total': 0,
            'north_boundary_uncertain_total': 0,
            'usb_sector_uncertain_total': 0,
            'usb_cycle_crc_start': 0,
            'usb_cycle_framing_start': 0,
            # LivePlay system counters kept intentionally simple:
            # sector missing, scan missed, north jitter.
            'scan_missed_total': 0,
            'north_jitter_total': 0,
            'last_sector_time': None,
            'sector_intervals_sec': [],
            'alert_message': '',
            'alert_active': False,
            'track_cancellations': 0,
            'scan_count': 0,
            'non_aircat_ignored_total': 0,
            'non_aircat_ignored_rate': 0.0,
        }

    def _live_cancel_alert_timer(self):
        if self.live_alert_after_id is not None:
            try:
                self.root.after_cancel(self.live_alert_after_id)
            except Exception:
                pass
            self.live_alert_after_id = None

    def _live_clear_alert(self):
        self.live_alert_after_id = None
        if self.live_state is not None:
            self.live_state['alert_message'] = ''
            self.live_state['alert_active'] = False
            label = getattr(self,'live_alert_label',None)
            if label is not None:
                try:label.configure(text='',bg='#ededed')
                except tk.TclError:pass
            self._request_liveplay_render(immediate=True)

    def _live_alert_duration_ms(self):
        # Flash only for about one sector pass. When timing is not known yet,
        # use a short fallback so LivePlay stays responsive.
        if self.live_state is None:
            return 125

        sector_intervals = list(self.live_state.get('sector_intervals_sec', []) or [])
        sector_interval = safe_median(sector_intervals) if sector_intervals else None

        if not sector_interval:
            north_intervals = list(self.live_state.get('north_intervals_sec', []) or [])
            north_interval = safe_median(north_intervals) if north_intervals else None
            if north_interval and north_interval > 0:
                sector_interval = north_interval / 32.0

        if sector_interval and sector_interval > 0:
            return int(max(60, min(600, sector_interval * 1000.0)))
        return 125

    def _live_set_alert(self, message):
        if self.live_state is None:
            return
        self.live_state['alert_message'] = message
        self.live_state['alert_active'] = True
        label=getattr(self,'live_alert_label',None)
        if label is not None:
            try:label.configure(text='⚠ '+str(message),bg='#ffe2e2')
            except tk.TclError:pass
        self._live_cancel_alert_timer()
        try:
            self.live_alert_after_id = self.root.after(2500, self._live_clear_alert)
        except Exception:
            self.live_alert_after_id = None

    def _live_check_cycle_protocol(self, sector_list):
        sectors = [int(s) for s in sector_list if s is not None and 0 <= int(s) < 32]
        seen = set(sectors)
        missing_sectors = [s for s in range(32) if s not in seen]

        if len(sectors) != 32:
            return False, missing_sectors

        for expected_sector, actual_sector in enumerate(sectors):
            if actual_sector != expected_sector:
                return False, missing_sectors

        return True, missing_sectors

    def _live_add_sector_missing_alert(self, missing_sectors, usb_uncertain=False):
        """Only absent sector numbers count as missing: order/duplicates are separate."""
        if self.live_state is None:
            return
        absent = sorted(set(int(x) for x in (missing_sectors or []) if 0 <= int(x) < 32))
        if not absent:
            return
        count = len(absent)
        if usb_uncertain:
            self.live_state['usb_sector_uncertain_total'] += count
            self._live_set_alert(f"USB sector gaps ({count}) with CRC/framing errors — cause uncertain")
        else:
            self.live_state['sector_alert_total'] += count
            self.live_state['sector_alert_curr'] = self.live_state['sector_alert_total']
            if count == 1:
                self._live_set_alert(f"sector {absent[0]:02X} missing (cause not determined)")
            else:
                self._live_set_alert(f"{count} sector IDs absent (cause not determined)")

    def _live_add_sector_sequence_alert(self):
        if self.live_state is None:
            return
        self.live_state['sector_sequence_total'] += 1
        self._live_set_alert('sector order/duplicate anomaly — NO sector ID missing')

    def _live_usb_cycle_has_errors(self, closing_rec=None):
        """Compare integrity counters attached to consecutive NORTH events."""
        if self.live_capture_source != 'usb' or closing_rec is None:
            return False
        return (closing_rec.get('_usb_crc_fail_total', 0) >
                self.live_state.get('usb_cycle_crc_start', 0) or
                closing_rec.get('_usb_framing_total', 0) >
                self.live_state.get('usb_cycle_framing_start', 0))

    def _live_snapshot_usb_cycle_integrity(self, rec):
        if self.live_capture_source != 'usb':
            return
        self.live_state['usb_cycle_crc_start'] = rec.get('_usb_crc_fail_total', 0)
        self.live_state['usb_cycle_framing_start'] = rec.get('_usb_framing_total', 0)

    def _live_add_scan_missed_alert(self, ratio=None):
        if self.live_state is None:
            return
        self.live_state['scan_missed_total'] = int(self.live_state.get('scan_missed_total', 0) or 0) + 1
        if ratio is not None:
            self._live_set_alert(f"scan missed ratio {float(ratio):.2f}")
        else:
            self._live_set_alert("scan missed")

    def _live_add_north_jitter_alert(self, ratio=None):
        if self.live_state is None:
            return
        self.live_state['north_jitter_total'] = int(self.live_state.get('north_jitter_total', 0) or 0) + 1
        if ratio is not None:
            try:
                variation = abs(float(ratio) - 1.0) * 100.0
                self._live_set_alert(f"north jitter {variation:.1f}%")
            except Exception:
                self._live_set_alert("north jitter")
        else:
            self._live_set_alert("north jitter")

    def _live_register_valid_north_time(self, north_time):
        if self.live_state is None or north_time is None:
            return

        valid_times = self.live_state.setdefault('valid_north_times', [])
        intervals = self.live_state.setdefault('north_intervals_sec', [])

        if valid_times:
            delta = north_time - valid_times[-1]
            if delta > 0:
                # Keep LivePlay closer to the offline algorithm:
                # offline calculates the expected North interval from the full
                # North interval population. Online cannot know the future, so
                # we use the median of all intervals seen so far, after adding
                # the current interval, and we wait for a small warm-up window.
                intervals.append(delta)
                self.live_state['north_intervals_sec'] = intervals
                expected_interval = safe_median(intervals) if len(intervals) >= 10 else None

                if expected_interval and expected_interval > 0:
                    ratio = delta / expected_interval
                    variation_pct = abs(ratio - 1.0) * 100.0

                    # Keep LivePlay aligned with the offline report:
                    #   - Scan missed: real missing scan, ratio > 1.9
                    #   - North jitter: displayed variation >5%, but not a missed scan
                    #   - Do NOT count jitter as "north missing".
                    if ratio > 1.9:
                        self._live_add_scan_missed_alert(ratio)
                    elif round(variation_pct, 1) > 5.0:
                        self._live_add_north_jitter_alert(ratio)

        valid_times.append(north_time)
        self.live_state['valid_north_times'] = valid_times

    def _live_append_north_reference_time(self, north_time):
        if self.live_state is None or north_time is None:
            return

        valid_times = self.live_state.setdefault('valid_north_times', [])
        intervals = self.live_state.setdefault('north_intervals_sec', [])

        if valid_times:
            delta = north_time - valid_times[-1]
            if delta > 0:
                intervals.append(delta)
                self.live_state['north_intervals_sec'] = intervals

        valid_times.append(north_time)
        self.live_state['valid_north_times'] = valid_times

    def _live_register_sector_time(self, sector_time):
        if self.live_state is None or sector_time is None:
            return

        last_sector_time = self.live_state.get('last_sector_time')
        if last_sector_time is not None:
            delta = sector_time - last_sector_time
            if 0 < delta <= 2.0:
                intervals = self.live_state.setdefault('sector_intervals_sec', [])
                intervals.append(delta)
                self.live_state['sector_intervals_sec'] = intervals[-40:]

        self.live_state['last_sector_time'] = sector_time

    def _live_record_sector_for_cycle(self, sector, rec):
        if self.live_state is None or sector is None:
            return
        if not self.live_state.get('current_cycle_active'):
            return

        sectors = self.live_state.setdefault('current_cycle_sectors', [])
        sector_i = int(sector)

        if sectors:
            previous_sector = int(sectors[-1])
            if previous_sector == 31 and sector_i == 0:
                # The boundary NORTH frame was not observed. Do not assert a
                # confirmed sector loss or infer a valid NORTH timestamp.
                self.live_state['north_boundary_uncertain_total'] += 1
                self._live_set_alert('NORTH boundary not received — scan uncertain')
                self.live_state['current_cycle_active'] = False
                self.live_state['current_cycle_north_time'] = None
                self.live_state['current_cycle_north_frame_no'] = None
                self.live_state['current_cycle_sectors'] = []
                return

        sectors.append(sector_i)

    def _live_finalize_current_cycle(self, closing_rec=None):
        if self.live_state is None or not self.live_state.get('current_cycle_active'):
            return
        sectors = list(self.live_state.get('current_cycle_sectors', []) or [])
        is_valid, missing = self._live_check_cycle_protocol(sectors)
        if is_valid:
            self._live_register_valid_north_time(self.live_state.get('current_cycle_north_time'))
        else:
            if missing:
                self._live_add_sector_missing_alert(missing, usb_uncertain=self._live_usb_cycle_has_errors(closing_rec))
            else:
                self._live_add_sector_sequence_alert()
            # Invalid cycle is NOT a lost North or a doubled North interval.
            self._live_append_north_reference_time(self.live_state.get('current_cycle_north_time'))

    def _reset_liveplay_view(self, event=None):
        self._live_cancel_alert_timer()
        self.live_state = self._new_live_state()
        if self.live_status_var is not None:
            if self.live_capture_running:
                self.live_status_var.set(f"LIVE {self.live_interface_label} | reset view | αναμονή valid UDP packets...")
            else:
                self.live_status_var.set("Live capture: stopped")
        self._draw_liveplay_radar()
        return "break"

    def _live_radar_screen_scale(self):
        try:
            geom = self._liveplay_calc_geom()
            if not geom or self.live_state is None:
                return None
            zoom = max(1.0, float(self.live_state.get('zoom_factor', 1.0)))
            visible_range = max(1.0, _display_range_raw_units(self.live_coordinate_scale_var.get()) / zoom)
            return float(geom.get('radius', 1.0)) / visible_range
        except Exception:
            return None

    def _live_reset_pan_center(self, event=None):
        """Reset radar pan center and all manual label offsets; keep LivePlay state."""
        if self.live_state is not None:
            self.live_state['view_center_x'] = 0.0
            self.live_state['view_center_y'] = 0.0
            self.live_state['pan_start'] = None
            self.live_state['label_drag'] = None
            self.live_state['label_offsets'] = {}
            self._draw_liveplay_radar()
        try:
            if self.live_canvas is not None:
                self.live_canvas.focus_set()
        except Exception:
            pass
        return "break"

    def _live_pan_start(self, event=None):
        if self.live_state is None or event is None:
            return "break"
        try:
            label_key = _find_track_label_key_from_canvas_event(self.live_canvas, event)
            if label_key:
                # LivePlay: dragging a target label is allowed, but Ctrl+drag
                # current-scan raw inspection is intentionally disabled here
                # so it cannot interfere with live recording/capture.
                offsets = self.live_state.setdefault('label_offsets', {})
                ox, oy = offsets.get(label_key, (0.0, 0.0))
                self.live_state['label_drag'] = {
                    'key': label_key,
                    'screen_x': float(event.x),
                    'screen_y': float(event.y),
                    'offset_x': float(ox),
                    'offset_y': float(oy),
                }
                self.live_state['pan_start'] = None
            else:
                # LivePlay center pan is disabled. The user may still zoom,
                # but the radar center remains fixed at the default origin.
                self.live_state['pan_start'] = None
                self.live_state['label_drag'] = None
            if self.live_canvas is not None:
                self.live_canvas.focus_set()
        except Exception:
            self.live_state['pan_start'] = None
            self.live_state['label_drag'] = None
        return "break"

    def _live_pan_motion(self, event=None):
        if self.live_state is None or event is None:
            return "break"

        label_drag = self.live_state.get('label_drag')
        if label_drag:
            try:
                key = label_drag.get('key')
                dx_pixels = float(event.x) - float(label_drag.get('screen_x', event.x))
                dy_pixels = float(event.y) - float(label_drag.get('screen_y', event.y))
                offsets = self.live_state.setdefault('label_offsets', {})
                offsets[key] = (
                    float(label_drag.get('offset_x', 0.0)) + dx_pixels,
                    float(label_drag.get('offset_y', 0.0)) + dy_pixels,
                )
                self._draw_liveplay_radar()
            except Exception:
                pass
            return "break"

        pan = self.live_state.get('pan_start')
        if not pan:
            return "break"
        scale = self._live_radar_screen_scale()
        if not scale or scale <= 0:
            return "break"
        try:
            dx_pixels = float(event.x) - float(pan.get('screen_x', event.x))
            dy_pixels = float(event.y) - float(pan.get('screen_y', event.y))
            # Drag behaves like grabbing the radar view: symbols follow the mouse.
            self.live_state['view_center_x'] = float(pan.get('center_x', 0.0)) - (dx_pixels / scale)
            self.live_state['view_center_y'] = float(pan.get('center_y', 0.0)) + (dy_pixels / scale)
            self._draw_liveplay_radar()
        except Exception:
            pass
        return "break"

    def _live_pan_end(self, event=None):
        if self.live_state is not None:
            self.live_state['pan_start'] = None
            self.live_state['label_drag'] = None
        return "break"

    def _live_zoom_in(self, event=None):
        if self.live_state is not None:
            self.live_state['zoom_factor'] = min(50.0, self.live_state.get('zoom_factor', 1.0) * 1.25)
            self._draw_liveplay_radar()
        return "break"

    def _live_zoom_out(self, event=None):
        if self.live_state is not None:
            self.live_state['zoom_factor'] = max(1.0, self.live_state.get('zoom_factor', 1.0) / 1.25)
            self._draw_liveplay_radar()
        return "break"

    def _live_increase_label_font(self, event=None):
        if self.live_state is not None:
            self.live_state['label_font_level'] = min(4, int(self.live_state.get('label_font_level', 1)) + 1)
            self._draw_liveplay_radar()
        return "break"

    def _live_decrease_label_font(self, event=None):
        if self.live_state is not None:
            self.live_state['label_font_level'] = max(1, int(self.live_state.get('label_font_level', 1)) - 1)
            self._draw_liveplay_radar()
        return "break"

    def _live_set_history_depth(self, depth):
        if self.live_state is not None:
            self.live_state['history_depth'] = max(0, min(20, int(depth)))
            self.live_state['sector_history'] = {k: v[:20] for k, v in self.live_state.get('sector_history', {}).items()}
            if self.live_status_var is not None:
                self.live_status_var.set(self._format_live_status_text())
            self._draw_liveplay_radar()
        return "break"

    def _live_increase_history_depth(self, event=None):
        depth = 0 if self.live_state is None else int(self.live_state.get('history_depth', 0))
        return self._live_set_history_depth(depth + 1)

    def _live_decrease_history_depth(self, event=None):
        depth = 0 if self.live_state is None else int(self.live_state.get('history_depth', 0))
        return self._live_set_history_depth(depth - 1)

    def _format_live_udp_record_duration(self):
        start_time = self.live_udp_record_start_time
        if start_time is None:
            return "00:00:00"
        try:
            elapsed = int(max(0, (datetime.now() - start_time).total_seconds()))
        except Exception:
            elapsed = 0
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def _cancel_live_udp_record_timer(self):
        if self.live_record_timer_after_id is not None:
            try:
                self.root.after_cancel(self.live_record_timer_after_id)
            except Exception:
                pass
            self.live_record_timer_after_id = None

    def _live_udp_record_timer_tick(self):
        self.live_record_timer_after_id = None
        if not self.live_udp_recording:
            return
        try:
            # Keep the red REC overlay on the white radar area updated without
            # redrawing the whole LivePlay radar and without duplicating REC info
            # in the black/grey status line.
            self._update_live_rec_overlay()
        finally:
            if self.live_udp_recording:
                self.live_record_timer_after_id = self.root.after(500, self._live_udp_record_timer_tick)

    def _start_live_udp_record_timer(self):
        self._cancel_live_udp_record_timer()
        if self.live_udp_recording:
            self.live_record_timer_after_id = self.root.after(500, self._live_udp_record_timer_tick)

    def _set_live_udp_record_button_state(self, active: bool):
        if not self.live_record_button:
            return
        try:
            if active:
                self.live_record_button.config(
                    bg="red", fg="white",
                    activebackground="red", activeforeground="white",
                    relief="sunken",
                    text="Recording"
                )
            else:
                self.live_record_button.config(
                    bg=self.live_record_button_default_bg,
                    fg=self.live_record_button_default_fg,
                    activebackground=self.live_record_button_default_bg,
                    activeforeground=self.live_record_button_default_fg,
                    relief="raised",
                    text="Record"
                )
        except Exception:
            pass

    def _sync_live_udp_record_filter_settings(self):
        """Copy LivePlay Record filter checkboxes into a thread-safe snapshot."""
        try:
            settings = {
                'aircat_like_only': bool(self.live_record_filter_aircat_like_only_var.get()),
                'radar_sector': bool(self.live_record_filter_radar_sector_var.get()),
                'north_signal': bool(self.live_record_filter_north_signal_var.get()),
                'radar_extension': bool(self.live_record_filter_radar_extension_var.get()),
                'processor_state': bool(self.live_record_filter_processor_state_var.get()),
                'weather': bool(self.live_record_filter_weather_var.get()),
                'other_aircat': bool(self.live_record_filter_other_aircat_var.get()),
                'non_aircat_udp': bool(self.live_record_filter_non_aircat_udp_var.get()),
            }
            with self.live_udp_record_filter_lock:
                self.live_udp_record_filter_settings = dict(settings)
        except Exception:
            pass

    def _get_live_udp_record_filter_settings_from_capture_thread(self):
        """Return a safe copy of the LivePlay recording filter settings."""
        try:
            with self.live_udp_record_filter_lock:
                return dict(self.live_udp_record_filter_settings or {})
        except Exception:
            return {
                'aircat_like_only': True,
                'radar_sector': True,
                'north_signal': True,
                'radar_extension': True,
                'processor_state': True,
                'weather': True,
                'other_aircat': True,
                'non_aircat_udp': False,
            }

    def _live_udp_record_filter_allows(self, payload, info=None):
        """Return True when the current Record filters allow this UDP packet.

        This function is intentionally safe for the capture reader thread: it
        reads only a plain dict snapshot, not Tkinter BooleanVars.
        """
        if not payload:
            return False
        try:
            settings = self._get_live_udp_record_filter_settings_from_capture_thread()
            if info is None:
                info = classify_aircat_payload(payload)
            is_aircat_like = bool(info and info.get('is_aircat_like'))

            if settings.get('aircat_like_only', True) and not is_aircat_like:
                return False

            if not is_aircat_like:
                return bool(settings.get('non_aircat_udp', False))

            msg_type = int(info.get('type', -1))
            if msg_type == 0x0C:
                return bool(settings.get('radar_sector', True))
            if msg_type == 0x19:
                return bool(settings.get('north_signal', True))
            if msg_type == 0x0D:
                return bool(settings.get('radar_extension', True))
            if msg_type == 0x1C:
                return bool(settings.get('processor_state', True))
            if msg_type == 0x2A:
                return bool(settings.get('weather', True))
            return bool(settings.get('other_aircat', True))
        except Exception:
            # Fail safe for recording: if filtering itself breaks, record the
            # packet rather than silently losing a potentially important one.
            return True

    def _open_live_udp_record_filter_window(self):
        """Open LivePlay recording filters.

        Default policy is AIRCAT-like only, so unrelated UDP traffic is still
        rejected from the saved recording unless the user explicitly enables it.
        """
        try:
            win = tk.Toplevel(self.live_capture_window or self.root)
            win.title("LivePlay Record Filters")
            win.resizable(False, False)
            outer = ttk.Frame(win, padding=12)
            outer.pack(fill="both", expand=True)

            ttk.Label(
                outer,
                text="LivePlay Record Filters",
                font=("Arial", 11, "bold")
            ).pack(anchor="w", pady=(0, 8))

            ttk.Checkbutton(
                outer,
                text="AIRCAT-like only (default)",
                variable=self.live_record_filter_aircat_like_only_var,
                command=self._sync_live_udp_record_filter_settings
            ).pack(anchor="w", pady=2)

            ttk.Separator(outer, orient="horizontal").pack(fill="x", pady=(8, 8))
            ttk.Label(
                outer,
                text="AIRCAT packets to save:",
                font=("Arial", 10, "bold")
            ).pack(anchor="w", pady=(0, 4))

            rows = [
                ("Radar Sector 0x0C", self.live_record_filter_radar_sector_var),
                ("North Signal 0x19", self.live_record_filter_north_signal_var),
                ("Radar Extension 0x0D", self.live_record_filter_radar_extension_var),
                ("Processor State 0x1C", self.live_record_filter_processor_state_var),
                ("Weather 0x2A", self.live_record_filter_weather_var),
                ("Other AIRCAT-like / unknown AIRCAT", self.live_record_filter_other_aircat_var),
            ]
            for label, var in rows:
                ttk.Checkbutton(
                    outer,
                    text=label,
                    variable=var,
                    command=self._sync_live_udp_record_filter_settings
                ).pack(anchor="w", pady=1)

            ttk.Separator(outer, orient="horizontal").pack(fill="x", pady=(8, 8))
            ttk.Checkbutton(
                outer,
                text="non-AIRCAT UDP packets (only if AIRCAT-like only is OFF)",
                variable=self.live_record_filter_non_aircat_udp_var,
                command=self._sync_live_udp_record_filter_settings
            ).pack(anchor="w", pady=2)

            ttk.Label(
                outer,
                text="Τα φίλτρα επηρεάζουν μόνο το αρχείο Record. Το LivePlay drawing κρατάει μόνο AIRCAT data.",
                foreground="#555555",
                wraplength=420,
                justify="left"
            ).pack(anchor="w", pady=(10, 8))

            ttk.Button(outer, text="Close", command=win.destroy).pack(anchor="e")
            self._sync_live_udp_record_filter_settings()

            try:
                win.transient(self.live_capture_window or self.root)
                win.grab_set()
            except Exception:
                pass
            try:
                self.center_toplevel_near_screen(win, min_width=420, min_height=360, margin_x=220, margin_y=160, width_ratio=0.32, height_ratio=0.40, max_width_cap=520, max_height_cap=520)
            except Exception:
                pass
        except Exception as exc:
            try:
                messagebox.showerror("LivePlay Record Filters", f"Αποτυχία ανοίγματος φίλτρων:\n{exc}")
            except Exception:
                pass

    def _get_live_capture_device_metadata(self):
        """Name the selected interface, not an unverified device serial number."""
        if self.live_capture_source == 'wifi':
            return {'capture_device': 'SYNC2WIFI-LAB',
                    'capture_connection': 'LAB TCP v5',
                    'capture_port': 'SYNC-LAB (synthetic)'}
        if self.live_capture_source == 'usb':
            return {
                'capture_device': 'SYNC2USB',
                'capture_connection': 'RS232 SYNC → USB CDC',
                'capture_port': self.live_usb_data_com or '',
            }
        if self.live_capture_source == 'ethernet':
            return {
                'capture_device': 'RICI5000',
                'capture_connection': 'RS232 SYNC → LAN / UDP',
                'capture_port': (self.live_interface_label or '').strip('[]'),
            }
        return {'capture_device': 'UNKNOWN', 'capture_connection': '', 'capture_port': ''}

    def _live_udp_record_row(self, rec):
        """Build one durable CSV row with capture equipment metadata."""
        payload = rec.get('payload', b'') or b''
        ts = rec.get('timestamp')
        info = classify_aircat_payload(payload)
        row = [
            rec.get('frame_no') if rec.get('frame_no') is not None else '',
            f"{ts:.6f}" if ts is not None else '',
            format_capture_time(ts) if ts is not None else '',
            payload.hex().upper(),
            len(payload),
            f"0x{info['type']:02X}" if info else '',
            info.get('type_name', '') if info else '',
            f"0x{info['addr']:02X}" if info else '',
            f"0x{int(info['sector']):02X}" if info and info.get('sector') is not None else '',
            '1' if info and info.get('is_north') else '0',
            '1' if info and info.get('is_sector') else '0',
            self.live_udp_record_metadata.get('capture_device', ''),
            self.live_udp_record_metadata.get('capture_connection', ''),
            self.live_udp_record_metadata.get('capture_port', ''),
            rec.get('_usb_crc_fail_total', '') if self.live_capture_source in ('usb','wifi') else '',
            rec.get('_usb_framing_total', '') if self.live_capture_source in ('usb','wifi') else '',
        ]
        if self.live_capture_source == 'wifi':
            row += ['GAP' if rec.get('_lab_gap') else 'FRAME',rec.get('_lab_segment',''),
                    rec.get('_lab_source_us',''),rec.get('_lab_gap',''),rec.get('_lab_index','')]
        return row

    def _live_udp_record_writer_loop(self):
        """Write recorded UDP packets to disk independently from the GUI.

        Each row is flushed and fsync'ed so a sudden power loss should not
        corrupt the rows that were already written successfully.
        """
        try:
            while True:
                item = self.live_udp_record_queue.get()
                if item is None:
                    break
                if self.live_capture_source == 'wifi':
                    item['_lab_index']=self.live_udp_recorded_packet_count+1
                self.live_udp_record_writer.writerow(self._live_udp_record_row(item))
                self.live_udp_recorded_packet_count += 1
                try:
                    self.live_udp_record_file.flush()
                    os.fsync(self.live_udp_record_file.fileno())
                except Exception:
                    # The write itself already succeeded; continue if only fsync fails.
                    pass
        except Exception as exc:
            self.live_udp_record_last_error = str(exc)
            try:
                self.live_capture_queue.put({'_live_error': f"LivePlay Record write error: {exc}"})
            except Exception:
                pass
        finally:
            try:
                if self.live_udp_record_file is not None:
                    self.live_udp_record_file.flush()
                    os.fsync(self.live_udp_record_file.fileno())
            except Exception:
                pass

    def _enqueue_live_udp_record_packet_from_capture_thread(self, rec, info=None):
        payload=rec.get('payload',b'') or b''
        lab=self.live_capture_source=='wifi'
        gap=rec.get('_lab_gap') if lab else None
        if not payload and not gap:return
        try:
            if not gap and not self._live_udp_record_filter_allows(payload,info):
                if not lab:return
                gap='Record filter excluded a frame';payload=b''
            rec_copy={'timestamp':rec.get('timestamp'),'frame_no':rec.get('frame_no'),
                      'payload':bytes(payload),'_usb_crc_fail_total':rec.get('_usb_crc_fail_total',''),
                      '_usb_framing_total':rec.get('_usb_framing_total','')}
            if lab:
                rec_copy.update(_lab_gap=gap,_lab_segment=rec.get('_lab_segment',''),
                                _lab_source_us=rec.get('_lab_source_us',''))
            with self.live_udp_record_lock:
                q=self.live_udp_record_queue
                if not self.live_udp_recording or q is None:return
                q.put(rec_copy)
        except Exception as exc:
            if lab:self.live_capture_queue.put({'_live_error':'LAB recording failed: '+str(exc)})

    def _append_live_udp_record_packet(self, rec):
        """Legacy GUI-side hook.

        Recording is now done directly from the capture reader thread through
        _enqueue_live_udp_record_packet_from_capture_thread(), so GUI drawing
        cannot delay or lose recorded packets.
        """
        return
    def _default_live_udp_record_filename(self):
        # Include the hardware in the filename; preserve full metadata in each CSV row.
        device = ('SYNC2WIFI' if self.live_capture_source == 'wifi' else 'SYNC2USB_USB' if self.live_capture_source == 'usb' else 'RICI5000_LAN')
        return datetime.now().strftime(f"AIRCAT500_{device}_Record_%Y%m%d_%H%M%S.csv")

    def _save_live_udp_recording(self):
        packet_count = len(self.live_udp_recorded_packets)
        path = filedialog.asksaveasfilename(
            title="Αποθήκευση καταγραφής UDP",
            defaultextension=".csv",
            initialfile=self._default_live_udp_record_filename(),
            filetypes=[
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ]
        )
        if not path:
            if self.live_status_var is not None:
                self.live_status_var.set(f"Η καταγραφή UDP σταμάτησε χωρίς αποθήκευση ({packet_count} packets).")
            return False

        try:
            with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(LIVE_RECORD_CSV_FIELDS + (list(CSV_EXTRA) if self.live_capture_source == 'wifi' else []))
                self.live_udp_record_metadata = self._get_live_capture_device_metadata()
                for rec in self.live_udp_recorded_packets:
                    payload = rec.get('payload', b'') or b''
                    ts = rec.get('timestamp')
                    info = classify_aircat_payload(payload)
                    writer.writerow(self._live_udp_record_row(rec))
        except Exception as e:
            messagebox.showerror("LivePlay Record", f"Αποτυχία αποθήκευσης καταγραφής UDP:\n{e}")
            return False

        msg = f"Αποθηκεύτηκαν {packet_count} UDP packets στο αρχείο:\n{path}"
        if self.live_status_var is not None:
            self.live_status_var.set(msg)
        messagebox.showinfo("LivePlay Record", msg)
        return True

    def _start_live_udp_recording(self):
        if self.live_udp_recording:
            return

        path = filedialog.asksaveasfilename(
            title="Αποθήκευση LivePlay recording (RICI5000 / SYNC2USB)",
            defaultextension=".csv",
            initialfile=self._default_live_udp_record_filename(),
            filetypes=[
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ]
        )
        if not path:
            if self.live_status_var is not None:
                self.live_status_var.set("REC UDP: ακυρώθηκε η επιλογή αρχείου.")
            try:
                self._bring_liveplay_to_front()
            except Exception:
                pass
            return

        try:
            self._bring_liveplay_to_front()
        except Exception:
            pass

        try:
            f = open(path, 'w', encoding='utf-8-sig', newline='', buffering=1)
            writer = csv.writer(f)
            writer.writerow(LIVE_RECORD_CSV_FIELDS + (list(CSV_EXTRA) if self.live_capture_source == 'wifi' else []))
            f.flush()
            os.fsync(f.fileno())
        except Exception as exc:
            try:
                messagebox.showerror("LivePlay Record", f"Αποτυχία έναρξης καταγραφής UDP:\n{exc}")
            except Exception:
                pass
            return

        self._sync_live_udp_record_filter_settings()

        self.live_udp_recorded_packets = []
        self.live_udp_recorded_packet_count = 0
        self.live_udp_record_metadata = self._get_live_capture_device_metadata()
        self.live_usb_record_start_counts = {}
        self.live_usb_record_start_uncertain = 0
        if self.live_capture_source in ('usb','wifi') and self.live_usb_observer is not None:
            with self.live_usb_observer_lock:
                self.live_usb_record_start_counts = self.live_usb_observer.counters()
            self.live_usb_record_start_uncertain = int(
                (self.live_state or {}).get('usb_sector_uncertain_total', 0) or 0)
        self.live_udp_record_path = path
        self.live_udp_record_file = f
        self.live_udp_record_writer = writer
        self.live_udp_record_queue = queue.Queue()
        self.live_udp_record_last_error = None
        self.live_udp_record_start_time = datetime.now()

        with self.live_udp_record_lock:
            self.live_udp_recording = True

        self.live_udp_record_writer_thread = threading.Thread(
            target=self._live_udp_record_writer_loop,
            name="AIRCAT500 LivePlay UDP writer",
            daemon=True
        )
        self.live_udp_record_writer_thread.start()

        self._set_live_udp_record_button_state(True)
        self._start_live_udp_record_timer()
        if self.live_status_var is not None:
            self.live_status_var.set(self._format_live_status_text())
        self._update_live_rec_overlay()
        try:
            self._bring_liveplay_to_front()
        except Exception:
            pass
        # No full radar redraw is needed to start recording.

    def _stop_live_udp_recording(self, prompt_save=True):
        if not self.live_udp_recording and self.live_udp_record_queue is None:
            self._set_live_udp_record_button_state(False)
            return

        self._cancel_live_udp_record_timer()
        self._set_live_udp_record_button_state(False)

        q = None
        with self.live_udp_record_lock:
            self.live_udp_recording = False
            q = self.live_udp_record_queue

        if q is not None:
            try:
                q.put(None)
            except Exception:
                pass

        writer_thread = self.live_udp_record_writer_thread
        if writer_thread is not None:
            try:
                # Wait until all queued packets have been flushed to disk.
                # This is intentional: Stop may take a little longer, but it
                # avoids closing the file while the writer is still saving data.
                writer_thread.join()
            except Exception:
                pass

        try:
            if self.live_udp_record_file is not None:
                self.live_udp_record_file.flush()
                os.fsync(self.live_udp_record_file.fileno())
                self.live_udp_record_file.close()
        except Exception:
            pass

        packet_count = int(self.live_udp_recorded_packet_count or 0)
        path = self.live_udp_record_path
        err = self.live_udp_record_last_error

        # The CSV intentionally contains only BSC CRC-valid frames. Save the
        # full recording-window integrity counts separately, including errors
        # after the last good frame that cannot appear in per-row snapshots.
        if (path and self.live_capture_source in ('usb','wifi') and
                self.live_usb_observer is not None):
            try:
                with self.live_usb_observer_lock:
                    final_counts = self.live_usb_observer.counters()
                begin = self.live_usb_record_start_counts or {}
                def difference(key):
                    return max(0, int(final_counts.get(key, 0) or 0) -
                               int(begin.get(key, 0) or 0))
                gap_delta = max(0, int((self.live_state or {}).get(
                    'usb_sector_uncertain_total', 0) or 0) -
                    int(self.live_usb_record_start_uncertain or 0))
                network = self.wifi_receiver if self.live_capture_source == 'wifi' else None
                save_capture_metadata(path, dict(
                    format='AIRCAT500 LivePlay CRC-valid payload CSV + USB diagnostics',
                    **self.live_udp_record_metadata,
                    captured_packets=packet_count,
                    crc_errors_during_recording=difference('crc_errors'),
                    framing_errors_during_recording=difference('framing_errors'),
                    crc_associated_sector_gaps_during_recording=gap_delta,
                    wifi_udp_packets_received=(network.udp_received if network else None),
                    wifi_udp_packets_lost=(network.udp_lost if network else None),
                    wifi_udp_invalid=(network.udp_invalid if network else None),
                    wifi_udp_crc32_bad=(network.udp_bad_crc32 if network else None),
                    wifi_udp_duplicates=(network.udp_duplicates if network else None),
                    wifi_firmware_overflow=(network.firmware_overflow if network else None),
                    wifi_firmware_overflow_since_connect=(network.firmware_overflow_since_connect if network else None),
                    notes=('CRC-failed BSC frames are excluded from CSV payload rows. '
                           'CRC-associated sector gaps are absent IDs in rotations '
                           'with integrity errors; they are NOT additional sector faults '
                           'and do NOT establish the physical source of data loss.'),
                ))
            except Exception as sidecar_exc:
                err = (str(err) + '; ' if err else '') + f'USB metadata: {sidecar_exc}'

        self.live_udp_record_start_time = None
        self.live_udp_record_file = None
        self.live_udp_record_writer = None
        self.live_udp_record_queue = None
        self.live_udp_record_writer_thread = None

        self._update_live_rec_overlay()
        if self.live_status_var is not None:
            if err:
                self.live_status_var.set(f"REC UDP: σταμάτησε με σφάλμα ({packet_count} packets) -> {path}")
            else:
                self.live_status_var.set(f"REC UDP: αποθηκεύτηκαν {packet_count} packets -> {path}")

        if prompt_save:
            origin = self.live_udp_record_metadata.get('capture_device', 'unknown')
            if err:
                messagebox.showerror("LivePlay Record", f"Πηγή: {origin}\nΗ καταγραφή σταμάτησε με σφάλμα:\n{err}\n\nΑρχείο:\n{path}")
            else:
                messagebox.showinfo("LivePlay Record", f"Πηγή: {origin}\nΑποθηκεύτηκαν {packet_count} packets στο αρχείο:\n{path}")

    def toggle_live_udp_recording(self):
        if self.live_udp_recording:
            self._stop_live_udp_recording(prompt_save=True)
        else:
            self._start_live_udp_recording()

    def _reset_live_non_aircat_counters(self):
        """Reset fast-discard counters for non-AIRCAT UDP packets."""
        try:
            with self.live_non_aircat_lock:
                self.live_non_aircat_ignored_total = 0
                self.live_non_aircat_ignored_rate = 0.0
                self.live_non_aircat_ignored_window_count = 0
                self.live_non_aircat_ignored_window_start = time.perf_counter()
        except Exception:
            pass
        if self.live_state is not None:
            self.live_state['non_aircat_ignored_total'] = 0
            self.live_state['non_aircat_ignored_rate'] = 0.0

    def _register_live_non_aircat_udp_ignored_from_capture_thread(self):
        """Count a non-AIRCAT UDP packet and keep it out of the GUI queue.

        This is intentionally very lightweight and runs in the capture reader
        thread.  Non-AIRCAT traffic is still recorded by the writer thread when
        Record is active, but it is not sent to the Tk GUI queue, so unrelated
        UDP bursts cannot freeze the radar drawing path.
        """
        try:
            now = time.perf_counter()
            with self.live_non_aircat_lock:
                self.live_non_aircat_ignored_total += 1
                self.live_non_aircat_ignored_window_count += 1
                elapsed = now - float(self.live_non_aircat_ignored_window_start or now)
                if elapsed >= 1.0:
                    self.live_non_aircat_ignored_rate = self.live_non_aircat_ignored_window_count / elapsed
                    self.live_non_aircat_ignored_window_count = 0
                    self.live_non_aircat_ignored_window_start = now
        except Exception:
            pass

    def _get_live_non_aircat_ignored_stats(self):
        """Return (total, rate/sec) for non-AIRCAT UDP packets discarded from GUI."""
        try:
            now = time.perf_counter()
            with self.live_non_aircat_lock:
                total = int(self.live_non_aircat_ignored_total or 0)
                rate = float(self.live_non_aircat_ignored_rate or 0.0)
                elapsed = now - float(self.live_non_aircat_ignored_window_start or now)
                window_count = int(self.live_non_aircat_ignored_window_count or 0)
                if elapsed >= 0.25 and window_count > 0:
                    rate = window_count / elapsed
            if self.live_state is not None:
                self.live_state['non_aircat_ignored_total'] = total
                self.live_state['non_aircat_ignored_rate'] = rate
            return total, rate
        except Exception:
            return 0, 0.0

    def _cancel_live_monitor_timer(self):
        if self.live_monitor_after_id is not None:
            try:
                self.root.after_cancel(self.live_monitor_after_id)
            except Exception:
                pass
            self.live_monitor_after_id = None

    def _live_monitor_timer_tick(self):
        """Light status/overlay refresh that does not redraw the radar."""
        self.live_monitor_after_id = None
        if not self.live_capture_running:
            return
        try:
            if self.live_status_var is not None:
                self.live_status_var.set(self._format_live_status_text())
            self._update_live_ignored_udp_overlay()
            if self.live_udp_recording:
                self._update_live_rec_overlay()
        except Exception:
            pass
        finally:
            if self.live_capture_running:
                try:
                    self.live_monitor_after_id = self.root.after(500, self._live_monitor_timer_tick)
                except Exception:
                    self.live_monitor_after_id = None

    def _start_live_monitor_timer(self):
        self._cancel_live_monitor_timer()
        if self.live_capture_running:
            try:
                self.live_monitor_after_id = self.root.after(500, self._live_monitor_timer_tick)
            except Exception:
                self.live_monitor_after_id = None

    def _format_live_status_text(self):
        if self.live_state is None:
            return "Live capture: stopped"
        hist_txt = f"history {self.live_state.get('history_depth', 0)}"
        track_count = sum(len(v) for v in self.live_state.get('sector_memory', {}).values())
        state_txt = "LIVE" if self.live_capture_running else "Live capture: stopped"
        return (
            f"{state_txt} {self.live_interface_label} | "
            f"{self.live_state.get('last_label', '')} | "
            f"packet #{self.live_state.get('last_frame_no', '')} | "
            f"tracks {track_count} | {hist_txt}"
        ).strip()

    def _show_live_usb_status(self):
        """Read-only USB reception details; never mixes diagnostics into radar data."""
        if self.live_capture_source != 'usb':
            return
        if self.live_usb_observer is None:
            messagebox.showinfo('USB Status', 'Δεν υπάρχουν ακόμη μετρήσεις USB.',
                                parent=self.live_capture_window or self.root)
            return
        with self.live_usb_observer_lock:
            counts = dict(self.live_usb_observer.counters())
        def number(key):
            return int(counts.get(key, 0) or 0)
        details = (
            f"DATA COM: {self.live_usb_data_com or '—'}\n"
            f"SYNC: {number('sync')}\n"
            f"VALID FRAMES (CRC OK): {number('valid_frames')}\n"
            f"CRC ERRORS: {number('crc_errors')}\n"
            f"BSC FRAMING ERRORS: {number('framing_errors')}\n"
            f"LOST SECTORS (clean rotations): {number('lost_sectors')}\n"
            f"SECTOR GAPS (CRC suspect): {number('uncertain_sectors')}\n"
            f"Duplicate sectors: {number('duplicate_sectors')}\n"
            f"Out-of-order sectors: {number('order_errors')}\n\n"
            "Οι CRC-suspect gaps δεν μετρώνται ως επιπλέον χαμένοι sectors.\n"
            "Οι μετρήσεις CLOCK είναι διαθέσιμες στο Radar Serial Line Monitoring."
        )
        messagebox.showinfo('USB Status', details,
                            parent=self.live_capture_window or self.root)

    def _update_live_ignored_udp_overlay(self):
        """Remove the old top-right non-AIRCAT meter.

        The non-AIRCAT counters are now shown together with the red recording
        overlay at the upper-left area above the radar picture.
        """
        canvas = getattr(self, 'live_canvas', None)
        if canvas is None:
            return
        try:
            canvas.delete('live_ignored_udp_overlay')
        except Exception:
            pass

    def _update_live_rec_overlay(self):
        """Update only the red LivePlay recording counters on the radar.

        The grey status line must not duplicate these values.  The red overlay
        shows recording time first, then the saved packet count and the fast
        non-AIRCAT reject counters.
        """
        canvas = getattr(self, 'live_canvas', None)
        if canvas is None:
            return
        try:
            canvas.delete('live_rec_overlay')
        except Exception:
            return
        if not self.live_udp_recording:
            return
        try:
            ignored_total, ignored_rate = self._get_live_non_aircat_ignored_stats()
            label_width = len("non-AIRCAT pkts ignored/sec")
            text = "\n".join((
                f"{'Capture device':<{label_width}}: {self.live_udp_record_metadata.get('capture_device', 'UNKNOWN')}",
                f"{'Recording time':<{label_width}}: {self._format_live_udp_record_duration()}",
                f"{'Recorded packets':<{label_width}}: {int(self.live_udp_recorded_packet_count or 0)}",
                f"{'non-AIRCAT UDP packets':<{label_width}}: {int(ignored_total or 0)}",
                f"{'non-AIRCAT pkts ignored/sec':<{label_width}}: {float(ignored_rate or 0.0):.0f}",
            ))
            # Keep the recording counters in the upper-left of the LivePlay
            # radar area, where they remain visible and do not duplicate the
            # grey status line.
            canvas.create_text(
                10, 10,
                text=text,
                anchor="nw",
                justify="left",
                fill="red",
                font=("Consolas", 10, "bold"),
                tags=("live_rec_overlay",)
            )
        except Exception:
            pass

    def _bring_liveplay_to_front(self):
        """Bring the LivePlay window to the foreground when opened/selected.

        Some Windows/Tk combinations create the Toplevel behind the main
        application. Temporarily toggling topmost and repeating lift/focus
        after Tk has mapped the window makes the LivePlay window reliably
        visible without leaving it permanently above all other windows.
        """
        win = self.live_capture_window
        if win is None:
            return
        try:
            if not win.winfo_exists():
                return
        except Exception:
            return

        def _raise_once():
            try:
                if not win.winfo_exists():
                    return
                win.deiconify()
                win.update_idletasks()
                win.lift()
                win.attributes("-topmost", True)
                win.lift()
                win.focus_force()
                if self.live_canvas is not None:
                    self.live_canvas.focus_set()
            except Exception:
                try:
                    win.lift()
                except Exception:
                    pass

        def _release_topmost():
            try:
                if win.winfo_exists():
                    win.attributes("-topmost", False)
                    win.lift()
                    win.focus_force()
                    if self.live_canvas is not None:
                        self.live_canvas.focus_set()
            except Exception:
                pass

        try:
            _raise_once()
            # Repeat after mapping/focus settles, because a freshly opened
            # Toplevel can otherwise remain behind the main window.
            win.after(80, _raise_once)
            win.after(250, _raise_once)
            win.after(700, _release_topmost)
        except Exception:
            try:
                win.lift()
            except Exception:
                pass

    def _ensure_liveplay_window(self):
        if self.live_capture_window is not None:
            try:
                if self.live_capture_window.winfo_exists():
                    self._bring_liveplay_to_front()
                    return
            except Exception:
                pass

        win = tk.Toplevel(self.root)
        win.title('Live Radar Display — '+ ('SYNC2WIFI' if self.live_capture_source == 'wifi' else 'USB/SYNC2USB' if self.live_capture_source == 'usb' else 'Ethernet/RICI5000'))
        win.minsize(900, 560)
        win.resizable(True, True)
        self.center_toplevel_near_screen(win, min_width=960, min_height=620, margin_x=120, margin_y=90, width_ratio=0.66, height_ratio=0.84, max_width_cap=1180, max_height_cap=920, grow_y_up_ratio=0.20)

        outer = ttk.Frame(win, padding=8)
        outer.pack(fill="both", expand=True)

        control_row = ttk.Frame(outer)
        control_row.pack(fill="x", pady=(0, 8))
        self.live_record_button = tk.Button(control_row, text="Record", width=10, command=self.toggle_live_udp_recording)
        self.live_record_button.pack(side="left")
        neutral_control = dict(bg='#dfdfdf', fg='#151515', activebackground='#cecece',
                               activeforeground='#151515', relief='raised', bd=1,
                               font=('Segoe UI', 9))
        tk.Button(control_row, text='Record Filters',
                  command=self._open_live_udp_record_filter_window,
                  **neutral_control).pack(side='left', padx=(8, 0))
        tk.Button(control_row, text='Stop', command=self.stop_live_capture,
                  **neutral_control).pack(side='left', padx=(8, 0))
        if self.live_capture_source in ('usb', 'wifi'):
            tk.Button(control_row, text=('USB Status' if self.live_capture_source == 'usb' else 'Wi-Fi Status'),
                      command=(self._show_live_usb_status if self.live_capture_source == 'usb' else self._show_live_wifi_status),
                      **neutral_control).pack(side='left', padx=(8, 0))
        self.live_record_button_default_bg = self.live_record_button.cget("bg")
        self.live_record_button_default_fg = self.live_record_button.cget("fg")
        self._set_live_udp_record_button_state(False)

        self.live_status_var = tk.StringVar(value="Live capture: stopped")
        ttk.Label(outer, textvariable=self.live_status_var, anchor="w").pack(fill="x", pady=(0, 4))

        live_radar_area = ttk.Frame(outer)
        live_radar_area.pack(fill="both", expand=True)

        ppi_holder = ttk.Frame(live_radar_area)
        ppi_holder.pack(side='left', fill='both', expand=True)
        self.live_canvas = tk.Canvas(ppi_holder, bg="white", highlightthickness=1, highlightbackground="#B0B0B0")
        self.live_canvas.pack(side='top', fill='both', expand=True)
        self.live_alert_label = tk.Label(ppi_holder, text='', bg='#ededed', fg='#bb2222',
                                         font=('Segoe UI', 11, 'bold'), anchor='w', height=2)
        self.live_alert_label.pack(side='bottom', fill='x')

        live_settings_frame = ttk.LabelFrame(live_radar_area, text="Label Filters", padding=(8, 6))
        live_settings_frame.pack(side="right", fill="y", padx=(8, 0))

        def add_live_setting(label, variable, command=None):
            ttk.Checkbutton(
                live_settings_frame,
                text=label,
                variable=variable,
                command=command or self._draw_liveplay_radar
            ).pack(anchor="w", pady=1)

        add_live_setting("PSR", self.live_show_psr_var)
        add_live_setting("Weather", self.live_show_weather_var)
        add_live_setting("Mode A", self.live_show_mode_a_var)
        add_live_setting("Mode C", self.live_show_mode_c_var)
        ttk.Separator(live_settings_frame, orient="horizontal").pack(fill="x", pady=(6, 6))
        add_live_setting("Track cancellation", self.live_track_cancellation_enable_var)
        add_live_setting("Velocity Vector", self.live_show_velocity_vector_var)
        add_live_setting("Range", self.live_show_range_var)
        add_live_setting("Speed", self.live_show_speed_var)
        add_live_setting("Low quality tracks", self.live_show_low_quality_tracks_var)
        add_live_setting("High quality tracks", self.live_show_high_quality_tracks_var)
        add_live_setting("Quality Q", self.live_show_quality_q_var)
        add_live_setting("Detection misses", self.live_show_detection_misses_var)
        add_live_setting("Track number", self.live_show_track_number_var)
        add_live_setting("TPR #", self.live_show_tpr_var)
        if self.optional_field_available('psr_airport'):
            add_live_setting("Fast/Slow airport", self.live_show_psr_airport_var)
        if self.optional_field_available('psr_test_beacon'):
            add_live_setting("Test beacon", self.live_show_psr_test_beacon_var)
        if self.optional_field_available('log_sigma'):
            add_live_setting("LogSigma (SSR)", self.live_show_log_sigma_var)
        if self.optional_field_available('tracking_window'):
            add_live_setting("Time Since North", self.live_show_time_since_north_var)
            add_live_setting("Tracking Window", self.live_show_tracking_window_var)
        if self.optional_field_available('smoothing_k'):
            add_live_setting("Smoothing K", self.live_show_smoothing_k_var)

        self.live_capture_window = win
        self.live_state = self._new_live_state()

        self.live_canvas.bind("<Configure>", lambda _e=None: self._draw_liveplay_radar())
        self.live_canvas.bind("<ButtonPress-1>", self._live_pan_start, add="+")
        self.live_canvas.bind("<B1-Motion>", self._live_pan_motion, add="+")
        self.live_canvas.bind("<ButtonRelease-1>", self._live_pan_end, add="+")
        self.live_canvas.bind("<Escape>", self._live_reset_pan_center)
        self.live_canvas.bind("<Key-plus>", self._live_zoom_in)
        self.live_canvas.bind("<Key-KP_Add>", self._live_zoom_in)
        self.live_canvas.bind("<Key-minus>", self._live_zoom_out)
        self.live_canvas.bind("<Key-KP_Subtract>", self._live_zoom_out)
        self.live_canvas.bind("<Key-equal>", self._live_zoom_in)
        self.live_canvas.bind("<Shift-Key-plus>", self._live_increase_label_font)
        self.live_canvas.bind("<Shift-Key-KP_Add>", self._live_increase_label_font)
        self.live_canvas.bind("<Shift-Key-minus>", self._live_decrease_label_font)
        self.live_canvas.bind("<Shift-Key-KP_Subtract>", self._live_decrease_label_font)
        self.live_canvas.bind("<Shift-Key-underscore>", self._live_decrease_label_font)
        self.live_canvas.bind("<Control-Key-plus>", self._live_increase_history_depth)
        self.live_canvas.bind("<Control-Key-KP_Add>", self._live_increase_history_depth)
        self.live_canvas.bind("<Control-Key-minus>", self._live_decrease_history_depth)
        self.live_canvas.bind("<Control-Key-KP_Subtract>", self._live_decrease_history_depth)
        self.live_canvas.bind("<Control-Key-equal>", self._live_increase_history_depth)
        self.live_canvas.bind("<Control-Key-underscore>", self._live_decrease_history_depth)
        for digit in range(10):
            self.live_canvas.bind(str(digit), lambda _e, d=digit: self._live_set_history_depth(d))
            self.live_canvas.bind(f"<KP_{digit}>", lambda _e, d=digit: self._live_set_history_depth(d))

        win.bind("<Escape>", self._live_reset_pan_center)
        win.bind("<Key-plus>", self._live_zoom_in)
        win.bind("<Key-KP_Add>", self._live_zoom_in)
        win.bind("<Key-minus>", self._live_zoom_out)
        win.bind("<Key-KP_Subtract>", self._live_zoom_out)
        win.bind("<Key-equal>", self._live_zoom_in)
        win.bind("<Shift-Key-plus>", self._live_increase_label_font)
        win.bind("<Shift-Key-KP_Add>", self._live_increase_label_font)
        win.bind("<Shift-Key-minus>", self._live_decrease_label_font)
        win.bind("<Shift-Key-KP_Subtract>", self._live_decrease_label_font)
        win.bind("<Shift-Key-underscore>", self._live_decrease_label_font)
        win.bind("<Control-Key-plus>", self._live_increase_history_depth)
        win.bind("<Control-Key-KP_Add>", self._live_increase_history_depth)
        win.bind("<Control-Key-minus>", self._live_decrease_history_depth)
        win.bind("<Control-Key-KP_Subtract>", self._live_decrease_history_depth)
        win.bind("<Control-Key-equal>", self._live_increase_history_depth)
        win.bind("<Control-Key-underscore>", self._live_decrease_history_depth)
        for digit in range(10):
            win.bind(str(digit), lambda _e, d=digit: self._live_set_history_depth(d))
            win.bind(f"<KP_{digit}>", lambda _e, d=digit: self._live_set_history_depth(d))

        self.live_capture_window.protocol("WM_DELETE_WINDOW", self._on_liveplay_window_close)
        self.center_toplevel_near_screen(win, min_width=960, min_height=620, margin_x=120, margin_y=90, width_ratio=0.66, height_ratio=0.84, max_width_cap=1180, max_height_cap=920, grow_y_up_ratio=0.20)
        try:
            win.after(150, lambda w=win: self.center_toplevel_near_screen(w, min_width=960, min_height=620, margin_x=120, margin_y=90, width_ratio=0.66, height_ratio=0.84, max_width_cap=1180, max_height_cap=920, grow_y_up_ratio=0.20))
        except Exception:
            pass
        self._draw_liveplay_radar()
        self._bring_liveplay_to_front()

    def _on_liveplay_window_close(self):
        self.stop_live_capture(close_window=True)

    def _liveplay_calc_geom(self):
        if not self.live_canvas:
            return None
        width = max(self.live_canvas.winfo_width(), 220)
        height = max(self.live_canvas.winfo_height(), 220)
        side = min(width, height) - 110
        radius = max(side / 2, 90)
        cx = width / 2
        cy = height / 2
        return {
            'width': width, 'height': height, 'radius': radius,
            'cx': cx, 'cy': cy,
            'x1': cx - radius, 'y1': cy - radius, 'x2': cx + radius, 'y2': cy + radius
        }

    def _draw_liveplay_radar(self):
        if not self.live_canvas or self.live_state is None:
            return

        canvas = self.live_canvas
        canvas.delete("all")
        try:
            self.live_state.setdefault('label_track_map', {}).clear()
        except Exception:
            self.live_state['label_track_map'] = {}
        geom = self._liveplay_calc_geom()
        if not geom:
            return

        cx, cy, radius = geom['cx'], geom['cy'], geom['radius']
        x1, y1, x2, y2 = geom['x1'], geom['y1'], geom['x2'], geom['y2']

        def get_label_font_size():
            level = int(self.live_state.get('label_font_level', 1))
            level = max(1, min(4, level))
            return {1: 8, 2: 9, 3: 10, 4: 11}.get(level, 8)

        def get_visible_range():
            # Fixed full-scale radar range: at zoom=1 the outer circle represents
            # 250 NM using the fixed coordinate scale. With the default
            # 1/32 NM scale this is 8000 raw AIRCAT units.
            zoom = max(1.0, float(self.live_state.get('zoom_factor', 1.0)))
            max_range = _display_range_raw_units(self.live_coordinate_scale_var.get())
            return max(1.0, max_range / zoom)

        def should_draw_track(track):
            if track.get('is_cancellation'):
                return False
            if track.get('is_weather'):
                return bool(self.live_show_weather_var.get())
            if track.get('psr') and not self.live_show_psr_var.get():
                return False
            is_low = _is_low_quality_track(track)
            if is_low and not self.live_show_low_quality_tracks_var.get():
                return False
            if (not is_low) and not self.live_show_high_quality_tracks_var.get():
                return False
            return True

        def track_to_canvas_xy(track):
            visible_range = get_visible_range()
            try:
                if track.get('x') is not None and track.get('y') is not None:
                    x_raw = float(track.get('x') or 0.0)
                    y_raw = float(track.get('y') or 0.0)
                else:
                    rng = float(track.get('range', 0.0) or 0.0)
                    ta = math.radians(track.get('angle_deg', self.live_state.get('angle_deg', -90.0)))
                    x_raw = rng * math.cos(ta)
                    y_raw = -rng * math.sin(ta)

                center_x = float(self.live_state.get('view_center_x', 0.0) or 0.0)
                center_y = float(self.live_state.get('view_center_y', 0.0) or 0.0)
                rel_x = x_raw - center_x
                rel_y = y_raw - center_y
                if math.hypot(rel_x, rel_y) > visible_range:
                    return None
                scale = radius / max(1.0, visible_range)
                tx = cx + (rel_x * scale)
                ty = cy - (rel_y * scale)
                return tx, ty
            except Exception:
                return None

        def build_track_label(track):
            lines = []
            if track.get('is_weather'):
                if self.live_show_weather_var.get():
                    lines.append("W")
                return "\n".join(lines)

            # Label order: PSR/W status first, Track + cancellation on one line,
            # A, C, speed, range, quality, LogSigma, then the rest.
            if track.get('psr') and self.live_show_psr_var.get():
                lines.append("PSR")

            track_line = None
            if self.live_show_track_number_var.get() and track.get('track_no') is not None:
                track_line = f"Track:{track['track_no']}"
            if track.get('track_cancelled'):
                if track_line:
                    track_line += " / Track cancelled"
                else:
                    track_line = "Track cancelled"
            if track_line:
                lines.append(track_line)

            if self.live_show_tpr_var.get() and track.get('tpr_number') is not None:
                lines.append(f"TPR#{int(track.get('tpr_number'))}")

            if self.live_show_mode_a_var.get() and track.get('mode_a'):
                a_txt = f"A:{track['mode_a']}"
                if track.get('mode_a_status') == "invalid":
                    a_txt += " invalid"
                lines.append(a_txt)

            if self.live_show_mode_c_var.get() and track.get('mode_c'):
                c_txt = f"C:{track['mode_c']}"
                if track.get('mode_c_status'):
                    c_txt += f" {track['mode_c_status']}"
                lines.append(c_txt)

            if self.live_show_speed_var.get() and track.get('speed_kt') is not None:
                lines.append(f"spd: {int(track['speed_kt'])} kt")

            if self.live_show_range_var.get():
                lines.extend(_format_track_range_lines(track, self.live_coordinate_scale_var.get()))

            if self.live_show_quality_q_var.get() and track.get('quality') is not None:
                q_max = _track_quality_max(track)
                if q_max:
                    lines.append(f"Quality:{int(track['quality'])}/{q_max}")
                else:
                    lines.append(f"Quality:{int(track['quality'])}")

            if self.live_show_log_sigma_var.get() and int(track.get('type') or 0) == 0xFF and track.get('log_sigma_present'):
                if track.get('log_sigma_v') is not None:
                    lines.append(f"LogSigma: {track['log_sigma_v']:.2f}V / 2.5V")

            if self.live_show_time_since_north_var.get() and track.get('time_since_north_sec') is not None:
                lines.append(f"TN:{_format_time_since_north(track.get('time_since_north_sec'))}")
            if self.live_show_tracking_window_var.get() and track.get('tracking_window_short'):
                lines.append(f"W:{track.get('tracking_window_short')}")
            if self.live_show_smoothing_k_var.get() and track.get('smoothing_k') is not None:
                lines.append(f"K:{track.get('smoothing_k')}")

            if self.live_show_psr_airport_var.get() and track.get('psr'):
                if track.get('psr_airport_slow'):
                    lines.append("SLOW AIRPORT")
                if track.get('psr_airport_fast'):
                    lines.append("FAST AIRPORT")

            if self.live_show_psr_test_beacon_var.get() and track.get('psr'):
                if track.get('psr_test_beacon'):
                    lines.append("TEST BEACON")
                if track.get('psr_tvd900_test'):
                    lines.append("TVD900 TEST")

            if self.live_show_detection_misses_var.get():
                misses = track.get('detection_misses')
                if misses is not None and int(misses) > 0:
                    lines.append(f"misses: {int(misses)}")

            if track.get('maneuver'):
                lines.append("Unstable")

            return "\n".join(lines)

        def history_color(age_index, total_depth):
            if total_depth <= 1:
                gray = 0
            else:
                gray = int(round((age_index / max(1, total_depth - 1)) * 210))
            gray = max(0, min(220, gray))
            return f"#{gray:02X}{gray:02X}{gray:02X}"

        def draw_live_target_symbol(track, tx, ty, color):
            if track.get('is_weather'):
                draw_color = "#800080"
                canvas.create_rectangle(tx - 3, ty - 3, tx + 3, ty + 3, fill=draw_color, outline=draw_color)
                return

            if _is_special_mode_a_alert_track(track):
                _draw_special_mode_a_plus(canvas, tx, ty, color)
                return

            is_psr = bool(track.get('psr'))
            is_ssr = bool(track.get('has_ssr'))
            is_combined = bool(track.get('is_combined'))

            if is_combined:
                points = [tx, ty - 4, tx - 4, ty + 3, tx + 4, ty + 3]
                canvas.create_polygon(points, outline=color, fill="", width=1)
                canvas.create_oval(tx - 1.5, ty - 1.5, tx + 1.5, ty + 1.5, fill=color, outline=color)
            elif is_psr and not is_ssr:
                canvas.create_oval(tx - 2, ty - 2, tx + 2, ty + 2, fill=color, outline=color)
            else:
                points = [tx, ty - 4, tx - 4, ty + 3, tx + 4, ty + 3]
                canvas.create_polygon(points, outline=color, fill="", width=1)

        def draw_velocity_vector(track, tx, ty, color):
            if not self.live_show_velocity_vector_var.get():
                return
            if track.get('track_cancelled'):
                return
            dx = track.get('dx')
            dy = track.get('dy')
            if dx is None or dy is None:
                return
            try:
                dx = float(dx)
                dy = float(dy)
            except Exception:
                return
            if dx == 0 and dy == 0:
                return

            visible_range = get_visible_range()
            scale = radius / max(1.0, visible_range)
            vx = dx * scale
            vy = -dy * scale
            length = math.hypot(vx, vy)
            if length <= 0:
                return
            if length > 42:
                factor = 42.0 / length
                vx *= factor
                vy *= factor
            elif length < 8:
                factor = 8.0 / length
                vx *= factor
                vy *= factor

            canvas.create_line(tx, ty, tx + vx, ty + vy, fill=color, width=1, arrow=tk.LAST)

        def draw_track_list(track_list, draw_labels=True, history_age=None, history_depth=0):
            for track in track_list:
                if not should_draw_track(track):
                    continue
                xy = track_to_canvas_xy(track)
                if xy is None:
                    continue
                tx, ty = xy

                color = "#0033AA"
                is_low_quality = _is_low_quality_track(track)
                is_red_alert = _is_red_target_alert_track(track)
                if is_low_quality or is_red_alert:
                    color = "red"
                if history_age is not None and not is_low_quality and not is_red_alert:
                    color = history_color(history_age, max(1, history_depth))

                # History traces stay lightweight by design: position symbol only.
                # Current targets keep the full symbol / vector / label information.
                if history_age is None:
                    draw_velocity_vector(track, tx, ty, color)
                draw_live_target_symbol(track, tx, ty, color)

                effective_draw_labels = bool(draw_labels) and history_age is None

                if effective_draw_labels:
                    label_size = get_label_font_size()
                    label_txt = build_track_label(track)
                    flag_lines = _track_status_flag_lines(track)
                    label_key = _track_label_offset_key(track)
                    offset_x, offset_y = (0.0, 0.0)
                    if label_key:
                        try:
                            offset_x, offset_y = self.live_state.setdefault('label_offsets', {}).get(label_key, (0.0, 0.0))
                        except Exception:
                            offset_x, offset_y = (0.0, 0.0)
                    label_x = tx + 1 + float(offset_x)
                    label_y = ty + float(offset_y)
                    label_tags = _track_label_canvas_tags(track)
                    if label_key:
                        try:
                            self.live_state.setdefault('label_track_map', {})[label_key] = track
                        except Exception:
                            pass
                    if _has_manual_label_offset(offset_x, offset_y):
                        try:
                            canvas.create_line(
                                tx, ty, label_x, label_y,
                                fill="#0066CC", width=1
                            )
                        except Exception:
                            pass
                    label_line_count = label_txt.count("\n") + 1 if label_txt else 0
                    if flag_lines:
                        flag_y = label_y - (label_line_count * (label_size + 2))
                        canvas.create_text(
                            label_x, flag_y,
                            text="\n".join(flag_lines),
                            anchor="sw",
                            justify="left",
                            fill="red",
                            font=("Arial", label_size, "bold"),
                            tags=label_tags
                        )
                    if label_txt:
                        canvas.create_text(
                            label_x, label_y,
                            text=label_txt,
                            anchor="sw",
                            justify="left",
                            fill="red" if _is_low_quality_track(track) else "#202020",
                            font=("Arial", label_size),
                            tags=label_tags
                        )

        alert_active = bool(self.live_state.get('alert_active') and self.live_state.get('alert_message'))
        outline_color = "black"
        sector_line_color = "#BFBFBF"
        north_line_color = "#808080"
        radar_fill = ""  # PPI never flashes red; alert shown below the canvas.

        canvas.create_oval(x1, y1, x2, y2, outline=outline_color, fill=radar_fill, width=2)
        _draw_nm_range_rings(
            canvas, cx, cy, radius,
            get_visible_range(),
            self.live_coordinate_scale_var.get()
        )

        for i in range(32):
            boundary_deg = -90.0 + (i * 360.0 / 32.0)
            rad = math.radians(boundary_deg)
            bx = cx + radius * math.cos(rad)
            by = cy + radius * math.sin(rad)
            canvas.create_line(cx, cy, bx, by, fill=sector_line_color)

            center_deg = -90.0 + ((i + 0.5) * 360.0 / 32.0)
            crad = math.radians(center_deg)
            tx = cx + (radius + 18) * math.cos(crad)
            ty = cy + (radius + 18) * math.sin(crad)
            canvas.create_text(tx, ty, text=f"{i:02X}", font=("Arial", 8), fill="#707070")

        if self.live_state.get('last_time') is not None:
            ts = format_capture_time(self.live_state.get('last_time'))
            if " " in ts:
                time_only = ts.split(" ", 1)[1]
            else:
                time_only = ts
            packet_no = self.live_state.get('last_frame_no', '')
            canvas.create_text(
                cx, max(12, y1 - 42),
                text=f"{time_only} | packet #{packet_no}",
                anchor="n",
                justify="center",
                fill="#505050",
                font=("Arial", 11)
            )

        canvas.create_text(cx, y1 - 20, text="N", font=("Arial", 12, "bold"), fill="#606060")
        north_rad = math.radians(-90.0)
        nx = cx + radius * math.cos(north_rad)
        ny = cy + radius * math.sin(north_rad)
        canvas.create_line(cx, cy, nx, ny, fill=north_line_color, dash=(4, 2))

        right_x = geom['width'] - 10
        alert_y = 8
        alert_title_font = ("Arial", 11, "bold")
        alert_font = ("Arial", 12, "bold")
        canvas.create_text(
            right_x, alert_y,
            text="System alerts",
            anchor="ne", justify="right", fill="#606060", font=alert_title_font
        )
        canvas.create_text(
            right_x, alert_y + 18,
            text=f"sector missing {self.live_state.get('sector_alert_total', 0)}",
            anchor="ne", justify="right", fill="red", font=alert_font
        )
        canvas.create_text(
            right_x, alert_y + 36,
            text=f"scan missed {self.live_state.get('scan_missed_total', 0)}",
            anchor="ne", justify="right", fill="red", font=alert_font
        )
        canvas.create_text(
            right_x, alert_y + 54,
            text=f"north jitter {self.live_state.get('north_jitter_total', 0)}",
            anchor="ne", justify="right", fill="#cc5500", font=alert_font
        )
        # v10.0: technical counters stay in USB Status, away from the radar picture.  The USB Status
        # button shows them on demand, without covering targets/sector labels.
        self._update_live_rec_overlay()
        self._update_live_ignored_udp_overlay()

        hist_depth = int(self.live_state.get('history_depth', 0) or 0)
        if hist_depth > 0:
            for _sector_no, hist_list in self.live_state.get('sector_history', {}).items():
                visible_hist = hist_list[:hist_depth]
                for hist_idx in range(len(visible_hist) - 1, -1, -1):
                    draw_track_list(
                        visible_hist[hist_idx],
                        draw_labels=False,
                        history_age=hist_idx,
                        history_depth=hist_depth,
                    )

        for _sector_no, tracks in self.live_state.get('sector_memory', {}).items():
            draw_track_list(tracks, draw_labels=True)

        angle_rad = math.radians(self.live_state.get('angle_deg', -90.0))
        rx = cx + radius * math.cos(angle_rad)
        ry = cy + radius * math.sin(angle_rad)
        canvas.create_line(cx, cy, rx, ry, fill="red", width=3)

        right_x = geom['width'] - 10
        help_y = geom['height'] - 100
        help_font = ("Arial", 10)
        try:
            div = _coordinate_scale_divisor(self.live_coordinate_scale_var.get())
            cx_nm = float(self.live_state.get('view_center_x', 0.0) or 0.0) / div
            cy_nm = float(self.live_state.get('view_center_y', 0.0) or 0.0) / div
            center_txt = f"Center X={cx_nm:.1f}NM Y={cy_nm:.1f}NM"
        except Exception:
            center_txt = "Center X=0.0NM Y=0.0NM"
        canvas.create_text(
            right_x, help_y,
            text=f"+/- Zoom x{self.live_state.get('zoom_factor', 1.0):.1f}",
            anchor="ne", justify="right", fill="#505050", font=help_font
        )
        canvas.create_text(
            right_x, help_y + 18,
            text=center_txt,
            anchor="ne", justify="right", fill="#505050", font=help_font
        )
        canvas.create_text(
            right_x, help_y + 36,
            text=f"Shift +/- Labels L{self.live_state.get('label_font_level', 1)}/4",
            anchor="ne", justify="right", fill="#505050", font=help_font
        )
        canvas.create_text(
            right_x, help_y + 54,
            text=f"Ctrl +/- Track history H{self.live_state.get('history_depth', 0)}/20",
            anchor="ne", justify="right", fill="#505050", font=help_font
        )
        canvas.create_text(
            right_x, help_y + 72,
            text="Drag label | Esc defaults",
            anchor="ne", justify="right", fill="#505050", font=help_font
        )


    def _cancel_live_render_timer(self):
        if self.live_render_after_id is not None:
            try:
                self.root.after_cancel(self.live_render_after_id)
            except Exception:
                pass
            self.live_render_after_id = None

    def _request_liveplay_render(self, immediate=False):
        """Schedule one LivePlay redraw without blocking packet processing.

        Incoming data updates the live model and protocol counters immediately.
        Canvas drawing is rate-limited on the Tk event loop, so the operator sees
        continuous radar motion instead of short freezes that could be mistaken
        for real line interruptions.
        """
        if self.live_state is None or self.live_canvas is None:
            return
        self.live_display_dirty = True
        if self.live_render_after_id is not None:
            return

        delay_ms = 0
        if not immediate:
            try:
                now = time.perf_counter()
                min_interval = 1.0 / 30.0
                delay_ms = max(0, int((float(self.live_last_render_time or 0.0) + min_interval - now) * 1000.0))
            except Exception:
                delay_ms = 16

        try:
            self.live_render_after_id = self.root.after(delay_ms, self._live_render_tick)
        except Exception:
            self.live_render_after_id = None

    def _live_render_tick(self):
        self.live_render_after_id = None
        if self.live_state is None or self.live_canvas is None:
            self.live_display_dirty = False
            return
        if not self.live_display_dirty:
            return
        self.live_display_dirty = False
        try:
            if self.live_status_var is not None:
                self.live_status_var.set(self._format_live_status_text())
            self._draw_liveplay_radar()
            self.live_last_render_time = time.perf_counter()
        except Exception:
            pass

    def _apply_live_record(self, rec, redraw=True):
        if self.live_state is None:
            return

        if rec.get('_lab_gap'):
            self.live_state.update(current_cycle_active=False,current_cycle_north_time=None,
                current_cycle_north_frame_no=None,current_cycle_sectors=[],current_scan_records=[],
                valid_north_times=[],north_intervals_sec=[],last_sector_time=None,sector_intervals_sec=[])
            self.live_state.get('sector_memory',{}).clear()
            self.live_state.get('sector_history',{}).clear()
            self.live_state['last_sector']=None
            self.live_state['lab_gaps']=self.live_state.get('lab_gaps',0)+1
            self.live_state['last_label']='LAB GAP'
            return
        payload = rec.get('payload', b'')
        info = rec.get('_aircat_info') or classify_aircat_payload(payload)
        if not info or not info.get('is_aircat_like'):
            # Normal live capture filters these packets in the reader thread
            # before they reach the GUI queue.  Keep this fallback for safety if
            # records are injected from another path.
            return

        self.live_state['last_time'] = rec.get('timestamp')
        self.live_state['last_frame_no'] = rec.get('frame_no')

        if info.get('is_north'):
            self._live_finalize_current_cycle(closing_rec=rec)
            self.live_state['scan_count'] = int(self.live_state.get('scan_count', 0) or 0) + 1
            _purge_expired_cancelled_tracks(self.live_state.get('sector_memory', {}), self.live_state.get('scan_count', 0))
            self.live_state['current_cycle_active'] = True
            self.live_state['current_cycle_north_time'] = rec.get('timestamp')
            self.live_state['current_cycle_north_frame_no'] = rec.get('frame_no')
            self.live_state['current_cycle_sectors'] = []
            self._live_snapshot_usb_cycle_integrity(rec)
            self.live_state['current_scan_records'] = []
            self._live_append_current_scan_record(rec, info, kind='north', sector=None)
            self.live_state['angle_deg'] = -90.0
            self.live_state['last_label'] = 'North'
            self.live_state['last_sector'] = None
        elif info.get('is_sector'):
            sector = info.get('sector')
            live_scan_index = self._live_append_current_scan_record(rec, info, kind='sector', sector=sector)
            parsed_items = _parse_replay_tracks_from_payload(payload)
            for _t in parsed_items:
                try:
                    _t.setdefault('source_frame_no', rec.get('frame_no'))
                    _t.setdefault('source_time', rec.get('timestamp'))
                    _t.setdefault('source_live_scan_index', live_scan_index)
                    _t.setdefault('source_sector', sector)
                except Exception:
                    pass
            cancellations = [t for t in parsed_items if t.get('is_cancellation')]
            tracks = [t for t in parsed_items if not t.get('is_cancellation')]
            if tracks:
                self.live_state['max_track_range'] = max(
                    self.live_state.get('max_track_range', 1.0),
                    max(t.get('range', 0.0) for t in tracks)
                )

            if self.live_track_cancellation_enable_var.get() and cancellations:
                for cancellation in cancellations:
                    _mark_cancelled_tracks(self.live_state.get('sector_memory', {}), cancellation, self.live_state.get('scan_count', 0))
                self.live_state['track_cancellations'] = int(self.live_state.get('track_cancellations', 0) or 0) + len(cancellations)

            if sector is not None:
                self._live_register_sector_time(rec.get('timestamp'))
                self._live_record_sector_for_cycle(sector, rec)
                # Preserve the old stable behavior: the live sector is replaced
                # immediately with the newest sector data. If the message only
                # contains FB cancellation records, do not clear the sector memory;
                # just mark the matching track label as cancelled when enabled.
                if tracks or not cancellations:
                    previous = self.live_state['sector_memory'].get(sector, [])
                    _drop_cancelled_tracks_replaced_by_updates(self.live_state.get('sector_memory', {}), tracks)
                    if previous and int(self.live_state.get('history_depth', 0) or 0) > 0:
                        hist = self.live_state['sector_history'].setdefault(sector, [])
                        hist.insert(0, [dict(t) for t in previous])
                        self.live_state['sector_history'][sector] = hist[:20]
                    self.live_state['sector_memory'][sector] = _merge_pending_cancelled_tracks(
                        previous,
                        tracks,
                        self.live_state.get('scan_count', 0)
                    )
                self.live_state['angle_deg'] = -90.0 + ((sector + 0.5) * 360.0 / 32.0)
                self.live_state['last_label'] = f"Sector {sector:02X}"
                self.live_state['last_sector'] = sector

        elif info.get('type') == 0x2A and info.get('addr') == 0x40:
            # Keep weather messages non-intrusive, as in 1405. The setting is
            # available for future weather decoding but it must not disturb playback.
            if self.live_state.get('current_cycle_active'):
                self._live_append_current_scan_record(rec, info, kind='weather', sector=self.live_state.get('last_sector'))
            self.live_state['last_label'] = "Weather"

        if redraw:
            self._request_liveplay_render(immediate=True)

    def _live_capture_reader(self):
        proc = self.live_capture_proc
        try:
            while self.live_capture_running and proc and proc.stdout:
                line = proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue

                parts = line.split("\t")
                if len(parts) < 3:
                    continue

                try:
                    frame_no = int(parts[0]) if parts[0].strip() else None
                except Exception:
                    frame_no = None
                try:
                    ts = float(parts[1]) if parts[1].strip() else None
                except Exception:
                    ts = None

                hex_payload = parts[2].replace(":", "").replace(" ", "").strip()
                if not hex_payload:
                    continue
                try:
                    payload = bytes.fromhex(hex_payload)
                except Exception:
                    continue

                item = {
                    'timestamp': ts,
                    'payload': payload,
                    'frame_no': frame_no,
                }

                # Classify once in the reader thread.  The result is reused both
                # by the recording filters and by the fast GUI discard path.
                info = classify_aircat_payload(payload)

                # Record directly from the reader thread so GUI redraw delays
                # cannot delay or lose the saved UDP packet.  The Record Filters
                # decide whether this packet is actually written to the CSV.
                self._enqueue_live_udp_record_packet_from_capture_thread(item, info)

                # Fast-path reject unrelated UDP traffic before it reaches the
                # Tkinter GUI queue. This keeps the radar smooth even on noisy
                # networks. The ignored packet counter is still updated.
                if not info or not info.get('is_aircat_like'):
                    self._register_live_non_aircat_udp_ignored_from_capture_thread()
                    continue
                item['_aircat_info'] = info
                self.live_capture_queue.put(item)
        except Exception as e:
            self.live_capture_queue.put({'_live_error': str(e)})
        finally:
            if self.live_capture_running and proc:
                try:
                    rc = proc.poll()
                    if rc not in (None, 0):
                        err_txt = ""
                        try:
                            err_txt = proc.stderr.read().strip()
                        except Exception:
                            pass
                        self.live_capture_queue.put({'_live_error': err_txt or f"TShark τερμάτισε με κωδικό {rc}"})
                except Exception:
                    pass

    def _drain_live_capture_queue(self):
        self.live_capture_after_id = None

        processed = 0
        start_clock = time.perf_counter()
        max_packets_per_tick = 200
        max_seconds_per_tick = 0.008
        had_data = False

        while processed < max_packets_per_tick and (time.perf_counter() - start_clock) < max_seconds_per_tick:
            try:
                item = self.live_capture_queue.get_nowait()
            except queue.Empty:
                break

            if item.get('_live_error'):
                self.stop_live_capture()
                messagebox.showerror("LivePlay", item.get('_live_error'))
                return

            # Recording no longer depends on this GUI-side drain.
            self._apply_live_record(item, redraw=False)
            processed += 1
            had_data = True

        if had_data:
            # Packet parsing/counter updates are already applied.  Drawing is
            # scheduled separately at a steady frame rate to avoid GUI freezes.
            self._request_liveplay_render(immediate=False)

        if self.live_capture_running:
            try:
                has_more = not self.live_capture_queue.empty()
            except Exception:
                has_more = False
            # If there is backlog, continue almost immediately; otherwise use
            # the normal light polling interval.
            self.live_capture_after_id = self.root.after(1 if has_more else 25, self._drain_live_capture_queue)

    def start_live_capture(self):
        if self.live_capture_running:
            return

        tshark_path = self._find_tshark_path()
        if not tshark_path:
            messagebox.showerror("LivePlay", "Δεν βρέθηκε το tshark. Εγκατέστησε το Wireshark/TShark ή πρόσθεσέ το στο PATH.")
            return

        iface_idx, iface_desc = self._pick_ethernet_interface(tshark_path)
        if not iface_idx:
            # Detailed diagnostics are already shown by _pick_ethernet_interface.
            return

        self._discard_stale_live_packets()
        self.live_capture_source = 'ethernet'
        self._ensure_liveplay_window()
        self.live_interface_label = f"[{iface_desc}]"
        self.live_state = self._new_live_state()
        self._reset_live_non_aircat_counters()
        if self.live_status_var is not None:
            self.live_status_var.set(f"LIVE {self.live_interface_label} | αναμονή valid UDP packets...")

        cmd = [
            tshark_path,
            "-l",
            "-n",
            "-i", str(iface_idx),
            "-f", "udp",
            "-T", "fields",
            "-E", "separator=\t",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "udp.payload",
        ]
        popen_kwargs = {
            'stdout': subprocess.PIPE,
            'stderr': subprocess.PIPE,
            'text': True,
            'bufsize': 1,
            'encoding': 'utf-8',
            'errors': 'ignore',
        }
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        try:
            self.live_capture_proc = subprocess.Popen(cmd, **popen_kwargs)
        except Exception as e:
            messagebox.showerror("LivePlay", f"Αποτυχία έναρξης live capture:\n{e}")
            return

        self.live_capture_running = True
        self._set_liveplay_button_state(True)
        self._start_live_monitor_timer()

        self.live_capture_thread = threading.Thread(target=self._live_capture_reader, daemon=True)
        self.live_capture_thread.start()

        if self.live_capture_after_id is None:
            self.live_capture_after_id = self.root.after(40, self._drain_live_capture_queue)

        self._draw_liveplay_radar()
        self._bring_liveplay_to_front()

    def stop_live_capture(self, close_window=False):
        was_recording = self.live_udp_recording
        self.live_usb_stop_flag.set()
        if self.wifi_receiver is not None:
            try:self.wifi_receiver.close()
            except OSError:pass
        self.live_usb_session_id += 1
        self.live_capture_running = False
        self._live_cancel_alert_timer()
        self._cancel_live_render_timer()
        self._cancel_live_monitor_timer()

        if not was_recording:
            self._cancel_live_udp_record_timer()

        if was_recording:
            self._stop_live_udp_recording(prompt_save=True)

        if self.live_capture_after_id is not None:
            try:
                self.root.after_cancel(self.live_capture_after_id)
            except Exception:
                pass
            self.live_capture_after_id = None

        proc = self.live_capture_proc
        self.live_capture_proc = None
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=1.5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        self._set_liveplay_button_state(False)
        self.live_capture_source = None

        if self.live_status_var is not None:
            self.live_status_var.set(self._format_live_status_text())

        if close_window and self.live_capture_window is not None:
            try:
                self.live_capture_window.destroy()
            except Exception:
                pass
            self.live_capture_window = None
            self.live_canvas = None
            self.live_status_var = None
            self.live_state = None
            self.live_record_button = None
            self.live_record_button_default_bg = None
            self.live_record_button_default_fg = None
            self.live_record_timer_after_id = None


    # ===== v9.13: Ethernet/RICI5000 and USB/SYNC2USB integrated entry points =====
    def show_liveplay_monitor_menu(self):
        """Unified source/mode dialog; no device ports are opened until confirmed."""
        win = tk.Toplevel(self.root)
        win.title('LivePlay / Monitor — Επιλογή διεπαφής')
        win.resizable(False, False)
        win.transient(self.root)
        win.configure(bg='#ededed')
        style = ttk.Style(win)
        style.configure('AirSelect.TFrame', background='#ededed')
        style.configure('AirSelect.TLabel', background='#ededed', foreground='#161616')
        style.configure('AirSelect.TRadiobutton', background='#ededed', foreground='#161616', font=('Segoe UI', 10))
        style.map('AirSelect.TRadiobutton', background=[('active', '#ededed')])
        style.configure('AirSelect.TLabelframe', background='#ededed', foreground='#161616')
        style.configure('AirSelect.TLabelframe.Label', background='#ededed', foreground='#161616')
        style.configure('AirSelect.TButton', padding=(13, 6))
        body = ttk.Frame(win, padding=19, style='AirSelect.TFrame')
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='LivePlay / Monitor', style='AirSelect.TLabel',
                  font=('Segoe UI', 17, 'bold')).pack(anchor='w', pady=(0, 8))
        ttk.Label(body, text='1. Επιλογή διεπαφής δεδομένων RADAR',
                  style='AirSelect.TLabel').pack(anchor='w', pady=(0, 7))
        source = tk.StringVar(value='ethernet')
        usb_mode = tk.StringVar(value='radar')
        ttk.Radiobutton(body, text='RICI5000 (RS232 SYNC to LAN conversion)',
                        value='ethernet', variable=source, style='AirSelect.TRadiobutton').pack(anchor='w', pady=3)
        ttk.Radiobutton(body, text='SYNC2USB (RS232 SYNC to USB conversion)',
                        value='usb', variable=source, style='AirSelect.TRadiobutton').pack(anchor='w', pady=3)
        ttk.Radiobutton(body, text='SYNC2WIFI — TCP LAB (synthetic data only)',
                        value='wifi', variable=source, style='AirSelect.TRadiobutton').pack(anchor='w', pady=3)
        usb_panel = ttk.LabelFrame(body, text='2. Λειτουργία Live Radar / Serial Monitoring', padding=11, style='AirSelect.TLabelframe')
        ttk.Radiobutton(usb_panel, text='Live Radar Display — κλασική οθόνη RADAR',
                        value='radar', variable=usb_mode, style='AirSelect.TRadiobutton').pack(anchor='w', pady=4)
        ttk.Radiobutton(usb_panel, text='Radar Serial Line Monitoring — HEX / CRC / CLOCK',
                        value='monitor', variable=usb_mode, style='AirSelect.TRadiobutton').pack(anchor='w', pady=4)

        def update():
            if source.get() in ('usb', 'wifi'):
                usb_panel.pack(fill='x', pady=(9, 2))
            else:
                usb_panel.pack_forget()

        source.trace_add('write', lambda *_: update())
        update()
        ttk.Label(body, text='TCP LAB: synthetic generator only; legacy USB/LAN remain unchanged.',
                  foreground='#333333', style='AirSelect.TLabel').pack(anchor='w', pady=(12, 5))
        buttons = ttk.Frame(body, style='AirSelect.TFrame')
        buttons.pack(fill='x', pady=(9, 0))
        ttk.Button(buttons, text='Άκυρο', command=win.destroy, style='AirSelect.TButton').pack(side='right', padx=4)

        def proceed():
            chosen_source = source.get()
            chosen_mode = usb_mode.get()
            win.destroy()
            if chosen_source == 'ethernet':
                self._close_sync2usb_monitor()
                self._close_sync2wifi_monitor()
                if self.live_capture_running or self.live_capture_window is not None:
                    self.stop_live_capture(close_window=True)
                self.start_live_capture()  # unchanged UDP/TShark path
            elif chosen_source == 'wifi':
                create_wifi_source_dialog(self.root,
                    lambda pin: self._open_wifi_mode(chosen_mode, pin))
            elif chosen_mode == 'monitor':
                self._close_sync2wifi_monitor()
                self.open_sync2usb_serial_monitor()
            else:
                self._close_sync2wifi_monitor()
                self.start_usb_live_radar()

        ttk.Button(buttons, text='Άνοιγμα', command=proceed, style='AirSelect.TButton').pack(side='right', padx=4)
        win.bind('<Return>', lambda event: proceed())
        win.update_idletasks()
        x = self.root.winfo_rootx() + max(0, (self.root.winfo_width()-win.winfo_reqwidth())//2)
        y = self.root.winfo_rooty() + 90
        win.geometry(f'+{x}+{y}')
        win.grab_set()
        win.focus_force()

    def _usb_monitor_present(self):
        win = self.sync_monitor_window
        if win is None:
            return False
        try:
            return bool(win.winfo_exists())
        except tk.TclError:
            return False

    def _close_sync2usb_monitor(self):
        if self._usb_monitor_present():
            self.sync_monitor_window.on_close()
        self.sync_monitor_window = None

    def open_sync2usb_serial_monitor(self):
        """Open the v0.7 CRC GUI as Toplevel inside the Analyzer process."""
        if serial is None:
            messagebox.showerror('SYNC2USB', 'Απαιτείται pyserial: py -m pip install pyserial')
            return
        if self._usb_monitor_present():
            win = self.sync_monitor_window
            win.deiconify()
            win.lift()
            win.focus_force()
            return
        self._close_sync2wifi_monitor()
        if self.live_capture_running:
            self.stop_live_capture(close_window=True)
        self.sync_monitor_window = Sync2UsbMonitorWindow(self.root, owner=self)
        self.sync_monitor_window.lift()
        self.sync_monitor_window.focus_force()

    def _choose_usb_data_port(self):
        """Choose only from confidently detected native USB, or ask user."""
        if list_ports is None:
            messagebox.showerror('USB / SYNC2USB', 'Δεν βρέθηκε το pyserial: py -m pip install pyserial')
            return None
        devices = list(list_ports.comports())
        if not devices:
            messagebox.showerror('USB / SYNC2USB', 'Δεν βρέθηκε καμία σειριακή COM. Έλεγξε το native USB του SYNC2USB.')
            return None
        data, _diag, _msg = detect_usb_ports(devices)
        if data:
            return data
        # For ambiguous USB descriptors do not guess by COM number.
        dialog = tk.Toplevel(self.root)
        dialog.title('USB / SYNC2USB — DATA COM')
        dialog.transient(self.root)
        dialog.resizable(False, False)
        box = ttk.Frame(dialog, padding=16)
        box.pack(fill='both', expand=True)
        ttk.Label(box, text='Δεν αναγνωρίστηκε με βεβαιότητα η Native USB DATA COM.').pack(anchor='w', pady=(0, 6))
        ttk.Label(box, text='Επίλεξε τη COM του SYNC2USB (όχι την USB-UART/CH340):').pack(anchor='w', pady=(0, 10))
        names = [p.device for p in devices]
        current = tk.StringVar(value=names[0])
        combo = ttk.Combobox(box, values=names, textvariable=current, state='readonly', width=20)
        combo.pack(fill='x')
        description = tk.StringVar()
        def update(*_):
            p = next((p for p in devices if p.device == current.get()), None)
            description.set(str(p.description if p is not None else ''))
        current.trace_add('write', update)
        update()
        ttk.Label(box, textvariable=description, foreground='#52697b').pack(anchor='w', pady=(4, 8))
        result = {'port': None}
        def choose():
            result['port'] = current.get()
            dialog.destroy()
        btns = ttk.Frame(box)
        btns.pack(fill='x', pady=(4, 0))
        ttk.Button(btns, text='Άκυρο', command=dialog.destroy).pack(side='right', padx=4)
        ttk.Button(btns, text='Σύνδεση', command=choose).pack(side='right', padx=4)
        dialog.grab_set()
        self.root.wait_window(dialog)
        return result['port']

    def _discard_stale_live_packets(self):
        while True:
            try:
                self.live_capture_queue.get_nowait()
            except queue.Empty:
                break

    def _usb_live_capture_reader(self, session_id):
        """Capture native USB bytes, verify AIRCAT BSC CRC, feed classic LivePlay.

        Importantly, only CRC-validated frames are forwarded to the existing
        UDP-payload decoder; all serial I/O happens in this worker thread.
        """
        port = self.live_usb_data_com
        parser = self.live_usb_observer
        try:
            with serial.Serial(port=port, baudrate=19200, bytesize=serial.EIGHTBITS,
                               parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
                               timeout=0.15, xonxoff=False, rtscts=False, dsrdtr=False) as com:
                while (not self.live_usb_stop_flag.is_set() and self.live_capture_running
                       and session_id == self.live_usb_session_id):
                    data = com.read(min(4096, max(1, com.in_waiting)))
                    if not data:
                        continue
                    with self.live_usb_observer_lock:
                        events = parser.feed(data)
                    time_received = time.time()
                    for event in events:
                        if self.live_usb_stop_flag.is_set() or session_id != self.live_usb_session_id:
                            break
                        if event['result'] != 'CRC OK':
                            continue
                        payload = event.get('payload', b'')
                        info = classify_aircat_payload(payload)
                        if not info or not info.get('is_aircat_like'):
                            continue
                        self.live_usb_frame_count += 1
                        item = dict(timestamp=time_received, payload=payload,
                                    frame_no=self.live_usb_frame_count,
                                    _aircat_info=info, _usb_crc_ok=True,
                                    _usb_crc_fail_total=event.get('crc_fail_total', 0),
                                    _usb_framing_total=event.get('framing_error_total', 0))
                        self._enqueue_live_udp_record_packet_from_capture_thread(item, info)
                        self.live_capture_queue.put(item)
        except Exception as exc:
            if (not self.live_usb_stop_flag.is_set() and self.live_capture_running
                    and session_id == self.live_usb_session_id):
                self.live_capture_queue.put({'_live_error': f'USB/SYNC2USB ({port}): {exc}'})

    def start_usb_live_radar(self):
        """Start the original radar display with CRC-validated USB BSC frames."""
        if serial is None:
            messagebox.showerror('USB / SYNC2USB', 'Απαιτείται pyserial: py -m pip install pyserial')
            return
        # Releasing the monitor first prevents two readers opening one COM.
        self._close_sync2usb_monitor()
        self._close_sync2wifi_monitor()
        if self.live_capture_running or self.live_capture_window is not None:
            self.stop_live_capture(close_window=True)
        port = self._choose_usb_data_port()
        if not port:
            return
        self._discard_stale_live_packets()
        self.live_usb_data_com = port
        self.live_usb_stop_flag.clear()
        self.live_usb_session_id += 1
        session_id = self.live_usb_session_id
        self.live_usb_frame_count = 0
        with self.live_usb_observer_lock:
            self.live_usb_observer = BSCObserver()
        self.live_capture_source = 'usb'
        self.live_interface_label = f'[USB/SYNC2USB {port}]'
        self._ensure_liveplay_window()
        self.live_state = self._new_live_state()
        self._reset_live_non_aircat_counters()
        self.live_capture_running = True
        self._set_liveplay_button_state(True)
        if self.live_status_var is not None:
            self.live_status_var.set(f'USB {port} | αναμονή BSC CRC-valid AIRCAT frames...')
        self._start_live_monitor_timer()
        self.live_capture_thread = threading.Thread(target=self._usb_live_capture_reader,
                                                     args=(session_id,), name='AIRCAT SYNC2USB USB Live', daemon=True)
        self.live_capture_thread.start()
        if self.live_capture_after_id is None:
            self.live_capture_after_id = self.root.after(40, self._drain_live_capture_queue)
        self._draw_liveplay_radar()
        self._bring_liveplay_to_front()

    # -------------------- v20.0: SYNC2WIFI source --------------------
    def _close_sync2wifi_monitor(self):
        win = self.wifi_monitor_window
        if win is not None:
            try:
                if win.winfo_exists(): win.on_close()
            except tk.TclError:
                pass
        self.wifi_monitor_window = None

    def _open_wifi_mode(self, selected_mode, pin):
        self.wifi_pin = pin
        self._close_sync2usb_monitor()
        if self.live_capture_running or self.live_capture_window is not None:
            self.stop_live_capture(close_window=True)
        self._close_sync2wifi_monitor()
        if selected_mode == 'monitor':
            self.wifi_monitor_window = WifiLineMonitor(
                self.root, LabBSCObserver, pin=pin,
                on_close=lambda:setattr(self,'wifi_monitor_window',None))
            self.wifi_monitor_window.lift()
            self.wifi_monitor_window.focus_force()
        else:
            self.start_wifi_live_radar(pin)

    def _show_live_wifi_status(self):
        rx=self.wifi_receiver
        if rx is None:
            messagebox.showinfo('TCP LAB','No active laboratory session.')
            return
        with self.live_usb_observer_lock:
            c=self.live_usb_observer.counters() if self.live_usb_observer else {}
        text=(f"TCP LAB synthetic data only\nRecords: {rx.udp_received:,}\n"
              f"Continuity gaps: {rx.udp_lost:,}\nTransport CRC32: {rx.udp_bad_crc32:,}\n"
              f"BSC CRC FAIL: {c.get('crc_errors',0):,}\n"
              f"Observed missing sectors: {c.get('lost_sectors',0):,}\n"
              f"Last gap: {rx.gap_reason or '—'}")
        messagebox.showinfo('TCP LAB Status',text,parent=self.live_capture_window or self.root)

    def _wifi_live_capture_reader(self, session_id, pin):
        receiver=WifiReceiver(pin=pin)
        self.wifi_receiver=receiver
        parser=self.live_usb_observer
        segment=0
        def active():
            return self.live_capture_running and not self.live_usb_stop_flag.is_set() and session_id==self.live_usb_session_id
        def boundary(reason):
            nonlocal segment
            segment+=1
            record={'_lab_gap':reason,'_lab_segment':segment,'timestamp':None,'payload':b''}
            self._enqueue_live_udp_record_packet_from_capture_thread(record)
            if active():self.live_capture_queue.put(record)
        try:
            receiver.open()
            while active():
                block=receiver.read()
                if block is None:continue
                if not active():break
                if not block:
                    with self.live_usb_observer_lock:parser.lab_gap()
                    boundary(receiver.gap_reason)
                    continue
                with self.live_usb_observer_lock:
                    events,valid=parser.lab_feed(block)
                if not valid:
                    boundary('BSC invalid or ambiguous rotation')
                    continue
                event=events[0]
                payload=event['payload']
                info=classify_aircat_payload(payload)
                if not info or not info.get('is_aircat_like'):
                    boundary('Unrecognized synthetic payload')
                    continue
                self.live_usb_frame_count+=1
                record={'timestamp':receiver.source_epoch,'payload':payload,
                        'frame_no':self.live_usb_frame_count,'_aircat_info':info,
                        '_lab_segment':segment,'_lab_source_us':receiver.source_us,
                        '_usb_crc_fail_total':event.get('crc_fail_total',0),
                        '_usb_framing_total':event.get('framing_error_total',0)}
                self._enqueue_live_udp_record_packet_from_capture_thread(record,info)
                if active():self.live_capture_queue.put(record)
        except Exception as err:
            if active():
                boundary('TCP LAB receiver error')
                self.live_capture_queue.put({'_live_error':'TCP LAB: '+str(err)})
        finally:
            receiver.close()
            if self.wifi_receiver is receiver:self.wifi_receiver=None

    def start_wifi_live_radar(self, pin):
        self._discard_stale_live_packets()
        self.live_usb_stop_flag.clear()
        self.live_usb_session_id+=1
        session_id=self.live_usb_session_id
        self.live_usb_frame_count=0
        with self.live_usb_observer_lock:
            self.live_usb_observer=LabBSCObserver()
        self.live_capture_source='wifi'
        self.live_interface_label='[TCP LAB · synthetic SYNC-LAB]'
        self._ensure_liveplay_window()
        self.live_state=self._new_live_state()
        self._reset_live_non_aircat_counters()
        self.live_capture_running=True
        self._set_liveplay_button_state(True)
        if self.live_status_var:
            self.live_status_var.set('TCP LAB | αναμονή συνθετικών δεδομένων...')
        self._start_live_monitor_timer()
        self.live_capture_thread=threading.Thread(target=self._wifi_live_capture_reader,
                 args=(session_id,pin),name='SYNC2WIFI Live Radar',daemon=True)
        self.live_capture_thread.start()
        if self.live_capture_after_id is None:
            self.live_capture_after_id=self.root.after(40,self._drain_live_capture_queue)
        self._draw_liveplay_radar()
        self._bring_liveplay_to_front()

    def toggle_live_play(self):
        """Compatibility alias; all new entry paths use the unified chooser."""
        self.show_liveplay_monitor_menu()

    def _autosize_tree_by_headers(self, tree, headers, extra_pad=24, min_width=70, max_width=420):
        try:
            heading_font = tkfont.nametofont("TkHeadingFont")
        except Exception:
            heading_font = None

        for col, header in headers.items():
            if heading_font is not None:
                width = heading_font.measure(header) + extra_pad
            else:
                width = len(str(header)) * 9 + extra_pad
            width = max(min_width, min(width, max_width))
            tree.column(col, width=width)


    def _coerce_sort_value(self, value):
        if value is None:
            return (2, "")
        s = str(value).strip()
        if s == "" or s == "-":
            return (2, "")
        try:
            return (0, int(s))
        except Exception:
            pass
        try:
            return (0, float(s.replace(",", ".")))
        except Exception:
            pass
        return (1, s.casefold())

    def _treeview_sort_by(self, tree, col, descending):
        items = []
        for item_id in tree.get_children(""):
            val = tree.set(item_id, col)
            items.append((self._coerce_sort_value(val), item_id))

        items.sort(reverse=descending)

        for index, (_, item_id) in enumerate(items):
            tree.move(item_id, "", index)

        heading_text = tree.heading(col, "text")
        clean_text = heading_text.replace(" ▲", "").replace(" ▼", "")
        arrow = " ▼" if descending else " ▲"

        for c in tree["columns"]:
            txt = tree.heading(c, "text")
            tree.heading(c, text=txt.replace(" ▲", "").replace(" ▼", ""))

        tree.heading(
            col,
            text=clean_text + arrow,
            command=lambda: self._treeview_sort_by(tree, col, not descending)
        )

    def _enable_treeview_sorting(self, tree):
        for col in tree["columns"]:
            clean_text = tree.heading(col, "text").replace(" ▲", "").replace(" ▼", "")
            tree.heading(
                col,
                text=clean_text,
                command=lambda c=col: self._treeview_sort_by(tree, c, False)
            )


    def show_filters(self):
        win = tk.Toplevel(self.root)
        win.title("Φίλτρα")
        win.resizable(False, False)
        try:
            win.transient(self.root)
            win.grab_set()
        except Exception:
            pass

        frame = ttk.Frame(win, padding=12)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Επιλογές ανάλυσης:").pack(anchor="w", pady=(0, 8))

        options = [
            "All packets",
            "UDP packets only",
            "AIRCAT-like only",
            "Known AIRCAT only",
        ]
        for option in options:
            ttk.Radiobutton(frame, text=option, value=option, variable=self.filter_mode).pack(anchor="w", pady=2)

        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(16, 6))
        ttk.Button(btns, text="OK", command=win.destroy).pack(side="right")

        win.update_idletasks()
        ww, wh = 360, 230
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = max((sw - ww) // 2, 0)
        y = max((sh - wh) // 2, 0)
        win.geometry(f"{ww}x{wh}+{x}+{y}")

    
    def show_alerts(self):
        if not self.last_stats:
            messagebox.showinfo("Alerts", "Δεν υπάρχουν ακόμη στατιστικά για εμφάνιση.")
            return

        stats = self.last_stats
        events = list(stats.get('aircat_alert_events', []) or [])
        counts = dict(stats.get('aircat_alert_counts', {}) or {})
        counts_by_source = dict(stats.get('aircat_alert_counts_by_source', {}) or {})

        def _source_order(src):
            order = {'PSR': 0, 'MSSR': 1, 'Other': 2}
            return order.get(str(src), 99)

        def _source_from_event(evt):
            src = evt.get('track_source', '')
            if src in ('PSR', 'MSSR', 'Other'):
                return src
            t = str(evt.get('track_type', '')).upper()
            if t == '0XFE':
                return 'PSR'
            if t == '0XFF':
                return 'MSSR'
            return 'Other'

        # Backward-compatible split if an older stats object does not contain the
        # precomputed PSR/MSSR counters.
        if not counts_by_source and events:
            for evt in events:
                kind = evt.get('kind', 'Unknown')
                src = _source_from_event(evt)
                counts_by_source.setdefault(kind, {})
                counts_by_source[kind][src] = int(counts_by_source[kind].get(src, 0) or 0) + 1

        win = tk.Toplevel(self.root)
        win.title("AIRCAT Alerts")
        ww, wh = 1120, 560
        win.geometry(f"{ww}x{wh}")
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = max((sw - ww) // 2, 0)
        y = max((sh - wh) // 2, 0)
        win.geometry(f"{ww}x{wh}+{x}+{y}")

        notebook = ttk.Notebook(win)
        notebook.pack(fill="both", expand=True, padx=10, pady=(10, 6))

        alert_report_data = []

        def add_tree_tab(title, cols, headers, rows, widths=None):
            rows_snapshot = [tuple(row) for row in rows]
            alert_report_data.append({
                'title': title,
                'cols': tuple(cols),
                'headers': dict(headers),
                'rows': rows_snapshot,
            })

            frame = ttk.Frame(notebook)
            notebook.add(frame, text=title)
            tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="extended")
            for col in cols:
                tree.heading(col, text=headers.get(col, col))
                tree.column(col, anchor="w")
            if widths:
                for col, width in widths.items():
                    tree.column(col, width=width)
            self._enable_treeview_sorting(tree)
            self._autosize_tree_by_headers(tree, headers, max_width=520)
            vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
            hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
            tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
            tree.grid(row=0, column=0, sticky="nsew")
            vsb.grid(row=0, column=1, sticky="ns")
            hsb.grid(row=1, column=0, sticky="ew")
            frame.rowconfigure(0, weight=1)
            frame.columnconfigure(0, weight=1)
            for row in rows:
                tree.insert("", "end", values=row)

            def copy_selected_rows(_event=None):
                selected = list(tree.selection())
                if not selected:
                    focus_item = tree.focus()
                    selected = [focus_item] if focus_item else []
                if not selected:
                    return "break"
                copied_lines = []
                for item_id in selected:
                    values = tree.item(item_id, "values")
                    copied_lines.append("\t".join(str(v) for v in values))
                self.root.clipboard_clear()
                self.root.clipboard_append("\n".join(copied_lines))
                return "break"

            def select_all_rows(_event=None):
                tree.selection_set(tree.get_children(""))
                return "break"

            def show_tree_context_menu(event):
                row_id = tree.identify_row(event.y)
                if row_id and row_id not in tree.selection():
                    tree.selection_set(row_id)
                    tree.focus(row_id)
                menu = tk.Menu(tree, tearoff=0)
                menu.add_command(label="Copy selected", command=copy_selected_rows)
                menu.add_command(label="Select All", command=select_all_rows)
                menu.tk_popup(event.x_root, event.y_root)
                return "break"

            tree.bind("<Control-c>", copy_selected_rows)
            tree.bind("<Control-C>", copy_selected_rows)
            tree.bind("<Control-Key-c>", copy_selected_rows)
            tree.bind("<Control-Key-C>", copy_selected_rows)
            tree.bind("<Control-a>", select_all_rows)
            tree.bind("<Control-A>", select_all_rows)
            tree.bind("<Control-Key-a>", select_all_rows)
            tree.bind("<Control-Key-A>", select_all_rows)
            tree.bind("<<Copy>>", copy_selected_rows)
            tree.bind("<Button-1>", lambda _e, t=tree: t.focus_set(), add="+")
            tree.bind("<Button-3>", show_tree_context_menu)
            return tree

        summary_rows = []
        for idx, (kind, count) in enumerate(sorted(counts.items(), key=lambda x: (-int(x[1]), x[0])), start=1):
            split = counts_by_source.get(kind, {}) or {}
            summary_rows.append((
                idx,
                kind,
                int(split.get('PSR', 0) or 0),
                int(split.get('MSSR', 0) or 0),
                int(split.get('Other', 0) or 0),
                int(count)
            ))
        if not summary_rows:
            summary_rows.append((1, "Δεν βρέθηκαν AIRCAT alerts", 0, 0, 0, 0))

        add_tree_tab(
            "Σύνοψη",
            ("seq", "kind", "psr", "mssr", "other", "count"),
            {"seq": "#", "kind": "Alert", "psr": "PSR", "mssr": "MSSR", "other": "Other", "count": "Σύνολο"},
            summary_rows,
            {"seq": 60, "kind": 220, "psr": 90, "mssr": 90, "other": 90, "count": 120}
        )

        validation_rows = []
        seq = 1
        for label, key in (("Mode A", 'mode_a_validation_counts_by_source'), ("Mode C", 'mode_c_validation_counts_by_source')):
            root = stats.get(key, {}) or {}
            for source in ('PSR', 'MSSR', 'Other'):
                src_counts = root.get(source, {}) or {}
                if not src_counts:
                    continue
                valid = int(src_counts.get('valid', 0) or 0)
                invalid = int(src_counts.get('invalid', 0) or 0)
                total_val = valid + invalid
                pct_invalid = (invalid / total_val * 100.0) if total_val else 0.0
                validation_rows.append((seq, label, source, valid, invalid, total_val, f"{pct_invalid:.2f}%"))
                seq += 1
        if not validation_rows:
            validation_rows.append((1, "not transmitted", "", 0, 0, 0, "0.00%"))
        add_tree_tab(
            "Mode validation",
            ("seq", "mode", "source", "valid", "invalid", "total", "invalid_pct"),
            {"seq": "#", "mode": "Mode", "source": "PSR/MSSR", "valid": "Valid", "invalid": "Invalid", "total": "Σύνολο", "invalid_pct": "% Invalid"},
            validation_rows,
            {"seq": 60, "mode": 90, "source": 100, "valid": 90, "invalid": 90, "total": 100, "invalid_pct": 100}
        )

        common_cols = ("seq", "frame", "ts", "sector", "track_no", "source", "track_type", "mode_a", "mode_c", "quality", "tn", "window", "k", "service", "validation", "details", "prefix")
        common_headers = {
            "seq": "#",
            "frame": "Wireshark #",
            "ts": "Timestamp",
            "sector": "Sector",
            "track_no": "Track #",
            "source": "PSR/MSSR",
            "track_type": "Type",
            "mode_a": "Mode A",
            "mode_c": "Mode C",
            "quality": "Quality",
            "tn": "Time Since North",
            "window": "Tracking Window",
            "k": "K",
            "service": "Service byte",
            "validation": "Validation byte",
            "details": "Details",
            "prefix": "Payload prefix",
        }
        common_widths = {"seq": 55, "frame": 100, "ts": 180, "sector": 70, "track_no": 80, "source": 90, "track_type": 70, "mode_a": 80, "mode_c": 100, "quality": 80, "tn": 120, "window": 120, "k": 50, "service": 95, "validation": 110, "details": 250, "prefix": 140}

        def _sector_txt(value):
            if value is None or value == "":
                return ""
            try:
                return f"{int(value):02X}"
            except Exception:
                return str(value)

        def _event_to_common_row(idx, evt):
            return (
                idx,
                evt.get('frame_no', ''),
                format_capture_time(evt.get('time')),
                _sector_txt(evt.get('sector')),
                evt.get('track_no', ''),
                _source_from_event(evt),
                evt.get('track_type', ''),
                evt.get('mode_a', ''),
                evt.get('mode_c', ''),
                evt.get('quality', ''),
                evt.get('time_since_north', ''),
                evt.get('tracking_window', ''),
                evt.get('smoothing_k', ''),
                evt.get('service_byte', ''),
                evt.get('validation_byte', ''),
                evt.get('details', ''),
                evt.get('payload_prefix', ''),
            )

        special_code_kinds = {f"Mode A {code}" for code in ("7500", "7600", "7601", "7700")}
        special_code_events = [evt for evt in events if evt.get('kind') in special_code_kinds]
        if special_code_events:
            special_rows = [_event_to_common_row(idx, evt) for idx, evt in enumerate(special_code_events, start=1)]
            add_tree_tab("Special Codes", common_cols, common_headers, special_rows, common_widths)

        for kind in sorted(counts.keys(), key=lambda k: (-int(counts.get(k, 0)), k)):
            if kind in special_code_kinds:
                continue
            for source in sorted((counts_by_source.get(kind, {}) or {}).keys(), key=_source_order):
                source_events = [e for e in events if e.get('kind') == kind and _source_from_event(e) == source]
                if not source_events:
                    continue
                rows = []
                for idx, evt in enumerate(source_events, start=1):
                    rows.append(_event_to_common_row(idx, evt))
                tab_title = f"{kind} {source}" if source in ('PSR', 'MSSR') else f"{kind} Other"
                add_tree_tab(tab_title, common_cols, common_headers, rows, common_widths)

        optional_cols = (
            "seq", "frame", "ts", "sector", "track_no", "source", "track_type",
            "mode_a", "mode_c", "quality", "tn", "window", "k",
            "validation", "log_sigma", "details", "prefix"
        )
        optional_headers = {
            "seq": "#",
            "frame": "Wireshark #",
            "ts": "Timestamp",
            "sector": "Sector",
            "track_no": "Track #",
            "source": "PSR/MSSR",
            "track_type": "Type",
            "mode_a": "Mode A",
            "mode_c": "Mode C",
            "quality": "Quality",
            "tn": "Time Since North",
            "window": "Tracking Window",
            "k": "K",
            "validation": "Validation byte",
            "log_sigma": "Log Sigma",
            "details": "Details",
            "prefix": "Payload prefix",
        }
        optional_widths = {
            "seq": 55, "frame": 100, "ts": 180, "sector": 70, "track_no": 80,
            "source": 90, "track_type": 70, "mode_a": 80, "mode_c": 100,
            "quality": 80, "tn": 120, "window": 120, "k": 50,
            "validation": 110, "log_sigma": 95, "details": 280, "prefix": 140
        }

        def add_optional_detail_tab(title, container_key, empty_detail):
            detail_events = list(stats.get(container_key, []) or [])
            rows = []
            for idx, evt in enumerate(detail_events, start=1):
                rows.append((
                    idx,
                    evt.get('frame_no', ''),
                    format_capture_time(evt.get('time')),
                    _sector_txt(evt.get('sector')),
                    evt.get('track_no', ''),
                    _source_from_event(evt),
                    evt.get('track_type', ''),
                    evt.get('mode_a', ''),
                    evt.get('mode_c', ''),
                    evt.get('quality', ''),
                    evt.get('time_since_north', ''),
                    evt.get('tracking_window', ''),
                    evt.get('smoothing_k', ''),
                    evt.get('validation_byte', ''),
                    evt.get('log_sigma', ''),
                    evt.get('details', ''),
                    evt.get('payload_prefix', ''),
                ))
            if not rows:
                rows.append((1, "", "", "", "", "not transmitted", "", "", "", "", "", "", "", "", "", empty_detail, ""))
            add_tree_tab(title, optional_cols, optional_headers, rows, optional_widths)

        # Keep optional diagnostic tabs as the last tabs in the Alerts notebook.
        add_optional_detail_tab("Mode C Byte21", "mode_c_byte21_events", "Byte 21 Mode C validation details not transmitted")
        add_optional_detail_tab("Tracking Window", "tracking_window_events", "Tracking Window optional fields not transmitted")
        add_optional_detail_tab("Smoothing K", "smoothing_k_events", "Smoothing K optional fields not transmitted")
        add_optional_detail_tab("Log Sigma", "log_sigma_events", "Log Sigma amplitude not transmitted")

        def build_alerts_report_text():
            lines = []
            lines.append("AIRCAT Alerts - Report")
            lines.append("=" * 80)
            if self.current_file:
                lines.append(f"Αρχείο: {os.path.basename(self.current_file)}")
            lines.append(f"Ημερομηνία δημιουργίας: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append("")
            for table in alert_report_data:
                title = table.get('title', '')
                cols = table.get('cols', ())
                headers = table.get('headers', {})
                rows = table.get('rows', [])
                lines.append(title)
                lines.append("-" * max(12, len(title)))
                lines.append("\t".join(str(headers.get(col, col)) for col in cols))
                if rows:
                    for row in rows:
                        values = list(row)
                        if len(values) < len(cols):
                            values += [""] * (len(cols) - len(values))
                        lines.append("\t".join(str(v) for v in values[:len(cols)]))
                else:
                    lines.append("(χωρίς εγγραφές)")
                lines.append("")
            return "\n".join(lines)

        def show_alerts_text_report():
            report_win = tk.Toplevel(win)
            report_win.title("Report AIRCAT Alerts")
            report_win.resizable(True, True)
            ww2, wh2 = 980, 640
            report_win.update_idletasks()
            sw2 = report_win.winfo_screenwidth()
            sh2 = report_win.winfo_screenheight()
            x2 = max((sw2 - ww2) // 2, 0)
            y2 = max((sh2 - wh2) // 2, 0)
            report_win.geometry(f"{ww2}x{wh2}+{x2}+{y2}")
            report_win.minsize(760, 420)

            outer2 = ttk.Frame(report_win, padding=10)
            outer2.pack(fill="both", expand=True)
            txt_report = scrolledtext.ScrolledText(outer2, wrap="none", font=("Consolas", 10), exportselection=False)
            txt_report.pack(fill="both", expand=True)
            txt_report.insert("1.0", build_alerts_report_text())

            def copy_report_selection(_event=None):
                try:
                    selected = txt_report.get("sel.first", "sel.last")
                except Exception:
                    return "break"
                self.root.clipboard_clear()
                self.root.clipboard_append(selected)
                return "break"

            def select_all_report(_event=None):
                txt_report.tag_add("sel", "1.0", "end-1c")
                txt_report.mark_set("insert", "1.0")
                txt_report.see("insert")
                return "break"

            def show_report_context_menu(event):
                menu = tk.Menu(txt_report, tearoff=0)
                menu.add_command(label="Copy", command=copy_report_selection)
                menu.add_command(label="Select All", command=select_all_report)
                menu.tk_popup(event.x_root, event.y_root)
                return "break"

            txt_report.bind("<Control-c>", copy_report_selection)
            txt_report.bind("<Control-C>", copy_report_selection)
            txt_report.bind("<Control-Key-c>", copy_report_selection)
            txt_report.bind("<Control-Key-C>", copy_report_selection)
            txt_report.bind("<<Copy>>", copy_report_selection)
            txt_report.bind("<Control-a>", select_all_report)
            txt_report.bind("<Control-A>", select_all_report)
            txt_report.bind("<Control-Key-a>", select_all_report)
            txt_report.bind("<Control-Key-A>", select_all_report)
            txt_report.bind("<Button-3>", show_report_context_menu)
            btns2 = ttk.Frame(outer2)
            btns2.pack(fill="x", pady=(8, 0))
            ttk.Button(btns2, text="Close", command=report_win.destroy).pack(side="right")
            txt_report.focus_set()

        btns = ttk.Frame(win)
        btns.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(btns, text="Report", command=show_alerts_text_report).pack(side="right")

    def show_tables(self):
        if not self.last_stats:
            messagebox.showinfo("Πίνακες", "Δεν υπάρχουν ακόμη στατιστικά για εμφάνιση.")
            return

        stats = self.last_stats
        win = tk.Toplevel(self.root)
        win.title("Πίνακες σφαλμάτων")
        ww, wh = 1040, 520
        win.geometry(f"{ww}x{wh}")
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = max((sw - ww) // 2, 0)
        y = max((sh - wh) // 2, 0)
        win.geometry(f"{ww}x{wh}+{x}+{y}")

        notebook = ttk.Notebook(win)
        notebook.pack(fill="both", expand=True, padx=10, pady=(10, 6))

        table_report_data = []

        def add_tree_tab(title, cols, headers, rows, widths=None):
            rows_snapshot = [tuple(row) for row in rows]
            table_report_data.append({
                'title': title,
                'cols': tuple(cols),
                'headers': dict(headers),
                'rows': rows_snapshot,
            })

            frame = ttk.Frame(notebook)
            notebook.add(frame, text=title)
            tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="extended")
            for col in cols:
                tree.heading(col, text=headers.get(col, col))
                tree.column(col, anchor="w")
            if widths:
                for col, width in widths.items():
                    tree.column(col, width=width)
            self._enable_treeview_sorting(tree)
            self._autosize_tree_by_headers(tree, headers, max_width=520)
            vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
            hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
            tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
            tree.grid(row=0, column=0, sticky="nsew")
            vsb.grid(row=0, column=1, sticky="ns")
            hsb.grid(row=1, column=0, sticky="ew")
            frame.rowconfigure(0, weight=1)
            frame.columnconfigure(0, weight=1)
            for row in rows:
                tree.insert("", "end", values=row)

            def copy_selected_rows(_event=None):
                selected = list(tree.selection())
                if not selected:
                    focus_item = tree.focus()
                    selected = [focus_item] if focus_item else []
                if not selected:
                    return "break"

                copied_lines = []
                for item_id in selected:
                    values = tree.item(item_id, "values")
                    copied_lines.append("\t".join(str(v) for v in values))

                self.root.clipboard_clear()
                self.root.clipboard_append("\n".join(copied_lines))
                return "break"

            def select_all_rows(_event=None):
                tree.selection_set(tree.get_children(""))
                return "break"

            def show_tree_context_menu(event):
                row_id = tree.identify_row(event.y)
                if row_id and row_id not in tree.selection():
                    tree.selection_set(row_id)
                    tree.focus(row_id)

                menu = tk.Menu(tree, tearoff=0)
                menu.add_command(label="Copy selected", command=copy_selected_rows)
                menu.add_command(label="Select All", command=select_all_rows)
                menu.tk_popup(event.x_root, event.y_root)
                return "break"

            tree.bind("<Control-c>", copy_selected_rows)
            tree.bind("<Control-C>", copy_selected_rows)
            tree.bind("<Control-Key-c>", copy_selected_rows)
            tree.bind("<Control-Key-C>", copy_selected_rows)
            tree.bind("<Control-a>", select_all_rows)
            tree.bind("<Control-A>", select_all_rows)
            tree.bind("<Control-Key-a>", select_all_rows)
            tree.bind("<Control-Key-A>", select_all_rows)
            tree.bind("<<Copy>>", copy_selected_rows)
            tree.bind("<Button-1>", lambda _e, t=tree: t.focus_set(), add="+")
            tree.bind("<Button-3>", show_tree_context_menu)

            return tree

        missing_sector_counts = stats.get('missing_sector_counts', {}) or {}
        sector_without_prev_north_counts = stats.get('sector_without_prev_north_counts', {}) or {}
        out_of_order_valid_cycle_counts = stats.get('out_of_order_valid_cycle_counts', {}) or {}

        total_missing_sector = sum(int(v) for v in missing_sector_counts.values())
        total_sector_without_prev_north = sum(int(v) for v in sector_without_prev_north_counts.values())
        total_out_of_order_valid = sum(int(v) for v in out_of_order_valid_cycle_counts.values())
        total_scan_missed = len(_north_timing_scan_missed_alerts(stats))
        total_north_jitter = len(_north_timing_jitter_alerts(stats))
        total_protocol = len(stats.get('north_protocol_alerts', []))

        total_unknown_types = sum(int(count) for key, count in stats.get('type_counts', {}).items() if 'Unknown' in key)
        total_unknown_prefix_packets = sum(int(v) for v in stats.get('unknown_prefix_counts', {}).values())
        total_unknown_prefix_unique = len(stats.get('unknown_prefix_counts', {}))

        summary_rows = [
            ("Scan missed", total_scan_missed),
            ("North jitter >5%", total_north_jitter),
            ("North missing valid sectors", total_protocol),
            ("Invalid North cycles (diagnostic, non-additive)", total_scan_missed + total_protocol),
            ("Sector missing συνολικά", total_missing_sector),
            ("Συνολικά σφάλματα (χωρίς διπλομέτρηση)", count_distinct_scan_faults(stats)),
            ("Sector without prev North συνολικά", total_sector_without_prev_north),
            ("Out-of-order sectors μέσα σε valid cycle συνολικά", total_out_of_order_valid),
            ("Unknown protocol types αθροιστικά", total_unknown_types),
            ("Άγνωστα prefixes packets αθροιστικά", total_unknown_prefix_packets),
            ("Άγνωστα prefixes unique", total_unknown_prefix_unique),
            ("Malformed packets", len(stats.get('malformed_packets', []))),
            ("Decoder unmapped elements", len(stats.get('decoder_unmapped_elements', []))),
        ]
        add_tree_tab(
            "Σύνοψη",
            ("metric", "value"),
            {"metric": "Μέτρηση", "value": "Τιμή"},
            summary_rows,
            {"metric": 360, "value": 120}
        )

        scan_missed_rows = []
        for idx, item in enumerate(_north_timing_scan_missed_alerts(stats), start=1):
            scan_missed_rows.append((
                idx,
                item.get('frame_no_prev', ''),
                format_capture_time(item.get('time_prev')),
                item.get('frame_no_curr', ''),
                format_capture_time(item.get('time_curr')),
                f"{item.get('interval', 0):.1f}",
                f"{item.get('ratio', 0):.2f}",
                int(item.get('estimated_missed_scans', 0) or 0),
            ))
        add_tree_tab(
            "Scan missed",
            ("seq", "prev_no", "prev_ts", "curr_no", "curr_ts", "dt", "ratio", "missed"),
            {
                "seq": "#",
                "prev_no": "Prev #",
                "prev_ts": "Prev North",
                "curr_no": "Curr #",
                "curr_ts": "Current North",
                "dt": "Δt",
                "ratio": "Ratio",
                "missed": "Est. missed",
            },
            scan_missed_rows,
            {"seq": 60, "prev_no": 90, "prev_ts": 180, "curr_no": 90, "curr_ts": 180, "dt": 80, "ratio": 80, "missed": 90}
        )

        jitter_rows = []
        for idx, item in enumerate(_north_timing_jitter_alerts(stats), start=1):
            try:
                variation_pct = abs(float(item.get('ratio') or 0.0) - 1.0) * 100.0
            except Exception:
                variation_pct = 0.0
            jitter_rows.append((
                idx,
                item.get('frame_no_prev', ''),
                format_capture_time(item.get('time_prev')),
                item.get('frame_no_curr', ''),
                format_capture_time(item.get('time_curr')),
                f"{item.get('interval', 0):.1f}",
                f"{item.get('ratio', 0):.2f}",
                f"{variation_pct:.1f}%",
            ))
        add_tree_tab(
            "North jitter",
            ("seq", "prev_no", "prev_ts", "curr_no", "curr_ts", "dt", "ratio", "variation"),
            {
                "seq": "#",
                "prev_no": "Prev #",
                "prev_ts": "Prev North",
                "curr_no": "Curr #",
                "curr_ts": "Current North",
                "dt": "Δt",
                "ratio": "Ratio",
                "variation": "Variation",
            },
            jitter_rows,
            {"seq": 60, "prev_no": 90, "prev_ts": 180, "curr_no": 90, "curr_ts": 180, "dt": 80, "ratio": 80, "variation": 100}
        )

        protocol_rows = []
        for idx, item in enumerate(stats.get('north_protocol_alerts', []), start=1):
            missing = ",".join(f"{int(s):02X}" for s in item.get('missing_sectors', [])) if item.get('missing_sectors') else "-"
            protocol_rows.append((
                idx,
                item.get('north_frame_no', ''),
                format_capture_time(item.get('time')),
                item.get('sector_count', ''),
                missing,
            ))
        add_tree_tab(
            "Protocol / sectors",
            ("seq", "frame", "ts", "count", "missing"),
            {
                "seq": "#",
                "frame": "North frame",
                "ts": "Timestamp",
                "count": "Sectors",
                "missing": "Missing sectors",
            },
            protocol_rows,
            {"seq": 60, "frame": 100, "ts": 180, "count": 80, "missing": 260}
        )

        unknown_type_rows = []
        stats_base_tables = stats.get('accepted_records') or stats.get('total_records') or 1
        for idx, (key, count) in enumerate(
            sorted(
                [(key, int(count)) for key, count in stats.get('type_counts', {}).items() if 'Unknown' in key],
                key=lambda x: (-x[1], x[0])
            ),
            start=1
        ):
            pct = (count / stats_base_tables * 100.0) if stats_base_tables else 0.0
            unknown_type_rows.append((idx, key, count, f"{pct:.2f}%"))

        if unknown_type_rows:
            add_tree_tab(
                "Protocol types unknown/errors",
                ("seq", "type", "count", "pct"),
                {
                    "seq": "#",
                    "type": "Protocol type / identifier",
                    "count": "Count",
                    "pct": "%",
                },
                unknown_type_rows,
                {"seq": 60, "type": 280, "count": 100, "pct": 80}
            )

        unknown_prefix_rows = []
        for idx, (prefix, count) in enumerate(
            sorted(stats.get('unknown_prefix_counts', {}).items(), key=lambda x: (-int(x[1]), x[0]))[:200],
            start=1
        ):
            first_frame = stats.get('unknown_prefix_first_frame', {}).get(prefix, '')
            unknown_prefix_rows.append((idx, first_frame, prefix, int(count)))

        if unknown_prefix_rows:
            add_tree_tab(
                "Unknown prefixes",
                ("seq", "first_frame", "prefix", "count"),
                {
                    "seq": "#",
                    "first_frame": "First Frame",
                    "prefix": "Prefix",
                    "count": "Count",
                },
                unknown_prefix_rows,
                {"seq": 60, "first_frame": 110, "prefix": 160, "count": 100}
            )

        if stats.get('out_of_order_valid_cycle_events'):
            oo_rows = []
            for idx, item in enumerate(stats.get('out_of_order_valid_cycle_events', []), start=1):
                oo_rows.append((
                    idx,
                    item.get('north_frame_no', ''),
                    item.get('frame_no', ''),
                    format_capture_time(item.get('time')),
                    f"{int(item.get('expected_sector', 0)):02X}",
                    f"{int(item.get('actual_sector', 0)):02X}",
                ))
            add_tree_tab(
                "Out-of-order",
                ("seq", "north_frame", "sector_frame", "ts", "expected", "actual"),
                {
                    "seq": "#",
                    "north_frame": "North frame",
                    "sector_frame": "Sector frame",
                    "ts": "Timestamp",
                    "expected": "Expected",
                    "actual": "Actual",
                },
                oo_rows
            )

        if stats.get('malformed_packets'):
            malformed_rows = []
            for idx, item in enumerate(stats.get('malformed_packets', []), start=1):
                malformed_rows.append((
                    idx,
                    item.get('frame_no', ''),
                    format_capture_time(item.get('time')),
                    item.get('location', ''),
                    item.get('problem', ''),
                ))
            add_tree_tab(
                "Malformed",
                ("seq", "frame", "ts", "location", "problem"),
                {"seq": "#", "frame": "Frame", "ts": "Timestamp", "location": "Σημείο", "problem": "Πρόβλημα"},
                malformed_rows
            )

        if stats.get('decoder_unmapped_elements'):
            unmapped_rows = []
            for idx, item in enumerate(stats.get('decoder_unmapped_elements', []), start=1):
                unmapped_rows.append((
                    idx,
                    item.get('frame_no', ''),
                    format_capture_time(item.get('time')),
                    item.get('location', ''),
                    item.get('problem', ''),
                    item.get('raw', ''),
                ))
            add_tree_tab(
                "Unmapped",
                ("seq", "frame", "ts", "location", "problem", "raw"),
                {"seq": "#", "frame": "Frame", "ts": "Timestamp", "location": "Σημείο", "problem": "Περιγραφή", "raw": "Raw"},
                unmapped_rows
            )

        def build_tables_report_text():
            lines = []
            lines.append("Πίνακες σφαλμάτων - Report")
            lines.append("=" * 80)
            if self.current_file:
                lines.append(f"Αρχείο: {os.path.basename(self.current_file)}")
            lines.append(f"Ημερομηνία δημιουργίας: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append("")

            for table in table_report_data:
                title = table.get('title', '')
                cols = table.get('cols', ())
                headers = table.get('headers', {})
                rows = table.get('rows', [])

                lines.append(title)
                lines.append("-" * max(12, len(title)))
                lines.append("\t".join(str(headers.get(col, col)) for col in cols))

                if rows:
                    for row in rows:
                        values = list(row)
                        if len(values) < len(cols):
                            values += [""] * (len(cols) - len(values))
                        lines.append("\t".join(str(v) for v in values[:len(cols)]))
                else:
                    lines.append("(χωρίς εγγραφές)")

                lines.append("")

            return "\n".join(lines)

        def show_tables_text_report():
            report_win = tk.Toplevel(win)
            report_win.title("Report πινάκων σφαλμάτων")
            report_win.resizable(True, True)

            ww2, wh2 = 980, 640
            report_win.update_idletasks()
            sw2 = report_win.winfo_screenwidth()
            sh2 = report_win.winfo_screenheight()
            x2 = max((sw2 - ww2) // 2, 0)
            y2 = max((sh2 - wh2) // 2, 0)
            report_win.geometry(f"{ww2}x{wh2}+{x2}+{y2}")
            report_win.minsize(760, 420)

            outer2 = ttk.Frame(report_win, padding=10)
            outer2.pack(fill="both", expand=True)

            txt_report = scrolledtext.ScrolledText(
                outer2,
                wrap="none",
                font=("Consolas", 10),
                exportselection=False
            )
            txt_report.pack(fill="both", expand=True)
            txt_report.insert("1.0", build_tables_report_text())

            def copy_report_selection(_event=None):
                try:
                    selected = txt_report.get("sel.first", "sel.last")
                except Exception:
                    return "break"
                self.root.clipboard_clear()
                self.root.clipboard_append(selected)
                return "break"

            def select_all_report(_event=None):
                txt_report.tag_add("sel", "1.0", "end-1c")
                txt_report.mark_set("insert", "1.0")
                txt_report.see("insert")
                return "break"

            def show_report_context_menu(event):
                menu = tk.Menu(txt_report, tearoff=0)
                menu.add_command(label="Copy", command=copy_report_selection)
                menu.add_command(label="Select All", command=select_all_report)
                menu.tk_popup(event.x_root, event.y_root)
                return "break"

            txt_report.bind("<Control-c>", copy_report_selection)
            txt_report.bind("<Control-C>", copy_report_selection)
            txt_report.bind("<Control-Key-c>", copy_report_selection)
            txt_report.bind("<Control-Key-C>", copy_report_selection)
            txt_report.bind("<<Copy>>", copy_report_selection)
            txt_report.bind("<Control-a>", select_all_report)
            txt_report.bind("<Control-A>", select_all_report)
            txt_report.bind("<Control-Key-a>", select_all_report)
            txt_report.bind("<Control-Key-A>", select_all_report)
            txt_report.bind("<Button-3>", show_report_context_menu)

            btns2 = ttk.Frame(outer2)
            btns2.pack(fill="x", pady=(8, 0))
            ttk.Button(btns2, text="Close", command=report_win.destroy).pack(side="right")
            txt_report.focus_set()

        btns = ttk.Frame(win)
        btns.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(btns, text="Report", command=show_tables_text_report).pack(side="right")

    def _get_ordered_records(self, records):
        ordered = []
        for idx, rec in enumerate(records):
            r = dict(rec)
            r['_order'] = idx
            ordered.append(r)
        if ordered and all(rec.get('timestamp') is not None for rec in ordered):
            ordered.sort(key=lambda rec: (rec.get('timestamp'), rec.get('_order', 0)))
        return ordered

    def _compute_bar_chart_counts(self, records):
        ordered = self._get_ordered_records(records)
        current_cycle = None
        valid_cycles = []

        for rec in ordered:
            info = classify_aircat_payload(rec.get('payload', b''))
            if not info:
                continue

            if current_cycle is None:
                if info.get('is_north'):
                    current_cycle = {'north_rec': rec, 'sectors': []}
            else:
                if info.get('is_north'):
                    if len(current_cycle['sectors']) == 32:
                        valid_cycles.append(current_cycle)
                    current_cycle = {'north_rec': rec, 'sectors': []}
                elif info.get('is_sector'):
                    current_cycle['sectors'].append(info.get('sector'))

        if current_cycle is not None and len(current_cycle['sectors']) == 32:
            valid_cycles.append(current_cycle)

        if not valid_cycles:
            raise ValueError("Δεν βρέθηκαν valid North cycles με 32 sectors για το ραβδόγραμμα.")

        first_valid = valid_cycles[0]['north_rec']
        last_valid = valid_cycles[-1]['north_rec']

        extension_count = 0
        weather_count = 0

        use_time = first_valid.get('timestamp') is not None and last_valid.get('timestamp') is not None
        first_time = first_valid.get('timestamp')
        last_time = last_valid.get('timestamp')
        first_order = first_valid.get('_order', 0)
        last_order = last_valid.get('_order', 0)

        for rec in ordered:
            if use_time:
                ts = rec.get('timestamp')
                if ts is None or ts < first_time or ts > last_time:
                    continue
            else:
                order_no = rec.get('_order', 0)
                if order_no < first_order or order_no > last_order:
                    continue

            info = classify_aircat_payload(rec.get('payload', b''))
            if not info:
                continue

            if info.get('type') == 0x0D and info.get('addr') == 0x40:
                extension_count += 1
            elif info.get('type') == 0x2A and info.get('addr') == 0x40:
                weather_count += 1

        stats = self.last_stats or {}
        valid_norths = int(stats.get('valid_norths', 0) or 0)
        invalid_norths = int(stats.get('invalid_norths', 0) or 0)
        missing_sector_counts = stats.get('missing_sector_counts', {}) or {}
        sector_without_prev_north_counts = stats.get('sector_without_prev_north_counts', {}) or {}

        labels = ["North Messages", "Radar Extension", "Weather messages"] + [f"{i:02X}" for i in range(32)]

        blue_values = [valid_norths, extension_count, weather_count]
        red_values = [invalid_norths, 0, 0]
        pink_values = [0, 0, 0]

        for i in range(32):
            blue_values.append(valid_norths)
            red_values.append(int(missing_sector_counts.get(i, 0) or 0))
            pink_values.append(int(sector_without_prev_north_counts.get(i, 0) or 0))

        total_values = [b + r + p for b, r, p in zip(blue_values, red_values, pink_values)]
        return labels, total_values, blue_values, red_values, pink_values


    def show_bar_chart(self):
        if not self.current_records:
            messagebox.showinfo("Ραβδοδιάγραμμα", "Δεν υπάρχει φορτωμένο αρχείο για δημιουργία ραβδοδιαγράμματος.")
            return

        try:
            labels, values, blue_values, red_values, pink_values = self._compute_bar_chart_counts(self.current_records)
        except Exception as e:
            messagebox.showerror("Ραβδοδιάγραμμα", str(e))
            return

        max_val = max(values) if values else 0
        sector_indices = [i for i, lab in enumerate(labels) if re.fullmatch(r"[0-9A-F]{2}", str(lab))]
        sector_values = [values[i] for i in sector_indices] if sector_indices else list(values)
        min_sector_val = min(sector_values) if sector_values else 0

        if max_val <= 0:
            messagebox.showinfo("Ραβδοδιάγραμμα", "Δεν βρέθηκαν δεδομένα για εμφάνιση.")
            return

        win = tk.Toplevel(self.root)
        win.title("Ραβδοδιάγραμμα")
        ww, wh = 1180, 760
        win.geometry(f"{ww}x{wh}")
        win.minsize(900, 560)
        win.resizable(True, True)
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = max((sw - ww) // 2, 0)
        y = max((sh - wh) // 2, 0)
        win.geometry(f"{ww}x{wh}+{x}+{y}")

        outer = ttk.Frame(win)
        outer.pack(fill="both", expand=True)

        info = ttk.Label(
            outer,
            text="Χρησιμοποίησε τα εργαλεία Pan / Zoom για κοντινή θέαση στις κορυφές των bars.",
            anchor="w"
        )
        info.pack(fill="x", padx=8, pady=(8, 0))

        fig = Figure(figsize=(12, 6.8), dpi=100)
        ax = fig.add_subplot(111)

        x_positions = list(range(len(labels)))
        bars_ok = ax.bar(x_positions, blue_values, color="#1f77b4", label="Correct")
        bars_err = ax.bar(x_positions, red_values, bottom=blue_values, color="#d62728", label="Sector missing")
        bars_pink = ax.bar(
            x_positions,
            pink_values,
            bottom=[b + r for b, r in zip(blue_values, red_values)],
            color="#ff69b4",
            label="Sector without prev North"
        )

        ax.set_xlabel("Radar Sector Messages", fontsize=12, labelpad=2)
        ax.set_ylabel("Count in file", fontsize=12)
        chart_file = os.path.basename(self.current_file) if self.current_file else "unknown file"
        ax.set_title(f"Counts from first valid North to last valid North\n({chart_file})", fontsize=13)

        ax.set_xlim(-0.5, len(labels) - 0.5)
        ax.set_xticks(x_positions)
        ax.set_xticklabels(labels)
        ax.xaxis.set_major_locator(MultipleLocator(1))
        ax.xaxis.set_minor_locator(MultipleLocator(0.5))
        ax.tick_params(axis="x", which="major", length=4)
        ax.tick_params(axis="x", which="minor", length=2)

        full_ymin = 0
        full_ymax = max_val
        ax.set_ylim(full_ymin, full_ymax)
        ax.yaxis.set_major_locator(MaxNLocator(nbins=14, integer=True, min_n_ticks=8))
        ax.yaxis.set_minor_locator(AutoMinorLocator(2))

        ax.set_axisbelow(True)
        ax.grid(axis="y", which="major", linestyle="-", linewidth=0.6, alpha=0.4)
        ax.grid(axis="y", which="minor", linestyle=":", linewidth=0.5, alpha=0.35)
        ax.grid(axis="x", which="major", linestyle=":", linewidth=0.35, alpha=0.20)

        for label in ax.get_xticklabels():
            label.set_rotation(45)
            label.set_ha('right')

        ax.legend(loc="upper left")

        bar_value_texts = []

        def update_bar_value_labels(*_args):
            nonlocal bar_value_texts
            for t in bar_value_texts:
                try:
                    t.remove()
                except Exception:
                    pass
            bar_value_texts = []

            x_left, x_right = ax.get_xlim()
            y_bottom, y_top = ax.get_ylim()

            for bar, value, ok_val, err_val, pink_val in zip(bars_ok, values, blue_values, red_values, pink_values):
                x_center = bar.get_x() + bar.get_width() / 2
                if x_center < x_left or x_center > x_right:
                    continue

                bar_top = ok_val + err_val + pink_val
                visible_bottom = max(0, y_bottom)
                visible_top = min(bar_top, y_top)

                if visible_top <= visible_bottom:
                    continue

                y_pos = (visible_bottom + visible_top) / 2.0
                txt = "\u2009".join(list(str(value)))

                t = ax.text(
                    x_center, y_pos, txt,
                    ha='center', va='center',
                    rotation=90,
                    fontsize=12,
                    fontweight='bold',
                    color='white',
                    clip_on=True
                )
                bar_value_texts.append(t)

        def apply_zoom_peak():
            peak_ymin = int(min_sector_val * 0.95)
            if peak_ymin < 0:
                peak_ymin = 0

            peak_ymax = max_val * 1.02 if max_val > 0 else 1
            if peak_ymax <= peak_ymin:
                peak_ymax = (max_val + 1) if max_val > peak_ymin else (peak_ymin + 1)

            ax.set_ylim(peak_ymin, peak_ymax)
            canvas.draw()

        def apply_zoom_out():
            ax.set_ylim(full_ymin, full_ymax)
            canvas.draw()

        update_bar_value_labels()
        ax.callbacks.connect('xlim_changed', update_bar_value_labels)
        ax.callbacks.connect('ylim_changed', update_bar_value_labels)

        fig.tight_layout()

        toolbar_frame = ttk.Frame(outer)
        toolbar_frame.pack(fill="x", padx=8, pady=(4, 0))

        canvas_frame = ttk.Frame(outer)
        canvas_frame.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        canvas = FigureCanvasTkAgg(fig, master=canvas_frame)
        canvas.draw()

        toolbar = NavigationToolbar2Tk(canvas, toolbar_frame, pack_toolbar=False)
        toolbar.update()
        toolbar.pack(side="left", fill="x")

        zoom_btns = ttk.Frame(toolbar_frame)
        zoom_btns.pack(side="right", padx=(8, 0))
        ttk.Button(zoom_btns, text="zoom peak", command=apply_zoom_peak).pack(side="left", padx=(0, 4))
        ttk.Button(zoom_btns, text="zoom out", command=apply_zoom_out).pack(side="left")

        # Default view: open the bar chart already focused on the peak area.
        apply_zoom_peak()

        canvas.get_tk_widget().pack(fill="both", expand=True)


    def _replay_worker_count(self, workload_size=0):
        cores = _available_cpu_cores()
        try:
            workload_size = int(workload_size or 0)
        except Exception:
            workload_size = 0
        if workload_size > 0:
            return max(1, min(cores, workload_size))
        return cores

    def _populate_replay_sector_tracks(self, events, sector_parse_items):
        """Decode sector track payloads, using all CPU cores for large replays.

        Tkinter drawing remains single-threaded, but the expensive AIRCAT track
        decoding that prepares Replay events can run in multiple processes.
        The function falls back to sequential decoding if multiprocessing is not
        available, if the file is small, or if a worker error occurs.
        """
        max_track_range = 1.0
        if not sector_parse_items:
            return max_track_range

        workers = self._replay_worker_count(len(sector_parse_items))
        use_parallel = workers > 1 and len(sector_parse_items) >= PARALLEL_REPLAY_MIN_SECTORS

        if use_parallel:
            try:
                try:
                    self.status_label.config(
                        text=f"Replay processing με {workers} CPU πυρήνες..."
                    )
                    self.root.update_idletasks()
                except Exception:
                    pass

                chunk_size = max(1, len(sector_parse_items) // (workers * 8))
                with ProcessPoolExecutor(max_workers=workers) as executor:
                    for event_index, tracks, local_max_range in executor.map(
                        _parse_replay_payload_worker,
                        sector_parse_items,
                        chunksize=chunk_size
                    ):
                        try:
                            events[event_index]['tracks'] = tracks
                        except Exception:
                            pass
                        if local_max_range and local_max_range > max_track_range:
                            max_track_range = local_max_range
                return max_track_range
            except Exception:
                # Multiprocessing can fail on some packaged/locked-down systems.
                # Replay must still work, so continue sequentially.
                try:
                    self.status_label.config(text="Replay processing fallback: single core...")
                    self.root.update_idletasks()
                except Exception:
                    pass

        for event_index, payload in sector_parse_items:
            tracks = _parse_replay_tracks_from_payload(payload)
            events[event_index]['tracks'] = tracks
            real_tracks = [t for t in tracks if not t.get('is_cancellation')]
            if real_tracks:
                try:
                    local_max_range = max(float(t.get('range', 0.0) or 0.0) for t in real_tracks)
                    if local_max_range > max_track_range:
                        max_track_range = local_max_range
                except Exception:
                    pass
        return max_track_range

    def _ensure_replay_tracks_for_event_range(self, events, start_index, end_index):
        """Decode Replay sector tracks only for the active hidden chunk.

        Version 8.13 keeps the full event timeline for the slider, but it no
        longer decodes every sector track of a many-hour capture up front.
        Instead, the active 30-minute window is decoded on demand and cached.
        """
        if not events:
            return 1.0

        start_index = max(0, min(int(start_index or 0), len(events) - 1))
        end_index = max(0, min(int(end_index or 0), len(events) - 1))
        if end_index < start_index:
            start_index, end_index = end_index, start_index

        sector_parse_items = []
        for idx in range(start_index, end_index + 1):
            evt = events[idx]
            if evt.get('kind') != 'sector':
                evt['_tracks_ready'] = True
                continue
            if evt.get('_tracks_ready'):
                continue
            payload = evt.get('_payload', b'') or b''
            if payload:
                sector_parse_items.append((idx, payload))
            else:
                evt['_tracks_ready'] = True

        if not sector_parse_items:
            return 1.0

        max_track_range = self._populate_replay_sector_tracks(events, sector_parse_items)
        for idx, _payload in sector_parse_items:
            try:
                events[idx]['_tracks_ready'] = True
            except Exception:
                pass
        return max_track_range


    def _compute_replay_events(self, records):
        ordered = self._get_ordered_records(records)
        if not ordered:
            raise ValueError("Δεν υπάρχουν records για replay.")

        current_cycle = None
        valid_cycles = []

        for rec in ordered:
            ts = rec.get('timestamp')
            info = classify_aircat_payload(rec.get('payload', b''))
            if not info or ts is None:
                continue

            if current_cycle is None:
                if info.get('is_north'):
                    current_cycle = {
                        'north': rec,
                        'events': [{'kind': 'north', 'rec': rec, 'sector': None}],
                        'sectors': [],
                    }
            else:
                if info.get('is_north'):
                    if len(current_cycle['sectors']) == 32:
                        valid_cycles.append(current_cycle)
                    current_cycle = {
                        'north': rec,
                        'events': [{'kind': 'north', 'rec': rec, 'sector': None}],
                        'sectors': [],
                    }
                elif info.get('is_sector'):
                    sector = info.get('sector')
                    current_cycle['events'].append({'kind': 'sector', 'rec': rec, 'sector': sector})
                    current_cycle['sectors'].append(sector)
                elif info.get('type') == 0x2A and info.get('addr') == 0x40:
                    sector = current_cycle['sectors'][-1] if current_cycle['sectors'] else None
                    current_cycle['events'].append({'kind': 'weather', 'rec': rec, 'sector': sector})

        if current_cycle is not None and len(current_cycle['sectors']) == 32:
            valid_cycles.append(current_cycle)

        if not valid_cycles:
            raise ValueError("Δεν βρέθηκαν valid North cycles με timestamps για replay.")

        events = []
        last_ts = None
        scan_no = 0

        for cycle in valid_cycles:
            for evt in cycle['events']:
                rec = evt['rec']
                ts = rec.get('timestamp')
                if ts is None:
                    continue
                if last_ts is not None and ts < last_ts:
                    continue

                if evt['kind'] == 'north':
                    scan_no += 1
                    label = 'North'
                elif evt['kind'] == 'weather':
                    label = f"Weather {evt.get('sector', 0):02X}" if evt.get('sector') is not None else "Weather"
                else:
                    label = f"Sector {evt.get('sector', 0):02X}"

                event = {
                    'kind': evt['kind'],
                    'time': ts,
                    'frame_no': rec.get('frame_no'),
                    'sector': evt.get('sector'),
                    'label': label,
                    'priority': 0,
                    'tracks': [],
                    'scan_no': scan_no,
                    '_payload': rec.get('payload', b''),
                    '_tracks_ready': evt['kind'] != 'sector',
                }

                events.append(event)

                last_ts = ts

        max_track_range = _display_range_raw_units(DEFAULT_COORDINATE_SCALE)

        if len(events) < 2:
            raise ValueError("Δεν βρέθηκαν αρκετά events για replay.")

        first_time = events[0]['time']
        last_time = events[-1]['time']

        stats = self.last_stats or {}
        alert_events = []

        for item in stats.get('invalid_north_details', []):
            ts = item.get('time')
            if ts is None or ts < first_time or ts > last_time:
                continue

            missing_sectors = [int(s) for s in item.get('missing_sectors', []) if s is not None]
            if missing_sectors:
                for missing_sector in missing_sectors:
                    alert_events.append({
                        'kind': 'alert_sector',
                        'time': ts,
                        'frame_no': item.get('frame_no'),
                        'sector': int(missing_sector),
                        'label': f'Sector {int(missing_sector):02X} missing',
                        'message': f'sector {int(missing_sector):02X} missing',
                        'missing_sectors': [int(missing_sector)],
                        'alert_anchor': 'sector',
                        'priority': 1,
                        'tracks': [],
                    })
            else:
                alert_events.append({
                    'kind': 'alert_sector',
                    'time': ts,
                    'frame_no': item.get('frame_no'),
                    'sector': None,
                    'label': 'Sector missing',
                    'message': 'sector missing',
                    'missing_sectors': [],
                    'alert_anchor': 'north',
                    'priority': 1,
                    'tracks': [],
                })

        for item in _north_timing_scan_missed_alerts(stats):
            ts = item.get('time_curr') if item.get('time_curr') is not None else item.get('time_prev')
            if ts is None or ts < first_time or ts > last_time:
                continue
            alert_events.append({
                'kind': 'alert_north',
                'time': ts,
                'frame_no': item.get('frame_no_curr') if item.get('frame_no_curr') is not None else item.get('frame_no_prev'),
                'sector': None,
                'label': 'Scan missed',
                'message': 'scan missed',
                'priority': 1,
                'tracks': [],
            })

        events.extend(alert_events)
        events.sort(key=lambda e: (e.get('time', 0), e.get('priority', 0), e.get('frame_no') or 0))

        return events, max_track_range





    def show_replay(self):
        if not self.current_records:
            browser = getattr(self, '_raw_bin_browser', None)
            if browser is not None and browser.ready and browser.winfo_exists():
                browser.load_window(replay=True)
                return
            messagebox.showinfo("Replay", "Δεν υπάρχει φορτωμένο αρχείο για replay.")
            return

        processing_win = None
        try:
            processing_win = tk.Toplevel(self.root)
            processing_win.title("Replay")
            processing_win.resizable(False, False)
            try:
                processing_win.transient(self.root)
                processing_win.attributes("-topmost", True)
            except Exception:
                pass

            frame = ttk.Frame(processing_win, padding=18)
            frame.pack(fill="both", expand=True)
            ttk.Label(
                frame,
                text=f"Processing...\nCPU cores detected: {_available_cpu_cores()}",
                font=("Arial", 13, "bold"),
                anchor="center"
            ).pack(padx=20, pady=10)

            processing_win.update_idletasks()
            ww = max(260, processing_win.winfo_reqwidth() + 20)
            wh = max(110, processing_win.winfo_reqheight() + 10)
            sw = processing_win.winfo_screenwidth()
            sh = processing_win.winfo_screenheight()
            x = max((sw - ww) // 2, 0)
            y = max((sh - wh) // 2, 0)
            processing_win.geometry(f"{ww}x{wh}+{x}+{y}")
            processing_win.lift()
            try:
                processing_win.focus_force()
            except Exception:
                pass
            self.root.update_idletasks()
            self.root.update()
        except Exception:
            processing_win = None

        try:
            events, max_track_range = self._compute_replay_events(self.current_records)
        except Exception as e:
            if processing_win is not None:
                try:
                    processing_win.destroy()
                except Exception:
                    pass
            messagebox.showerror("Replay", str(e))
            return

        timed_records = [r for r in self._get_ordered_records(self.current_records) if r.get('timestamp') is not None]
        capture_start_ts = timed_records[0].get('timestamp') if timed_records else None
        capture_end_ts = timed_records[-1].get('timestamp') if timed_records else None
        capture_duration_hours = None
        if capture_start_ts is not None and capture_end_ts is not None and capture_end_ts > capture_start_ts:
            capture_duration_hours = (capture_end_ts - capture_start_ts) / 3600.0

        win = tk.Toplevel(self.root)
        win.title("Replay")
        win.minsize(900, 560)
        win.resizable(True, True)
        self.center_toplevel_near_screen(win, min_width=960, min_height=620, margin_x=120, margin_y=90, width_ratio=0.62, height_ratio=0.84, max_width_cap=1120, max_height_cap=920, grow_y_up_ratio=0.20)

        outer = ttk.Frame(win, padding=8)
        outer.pack(fill="both", expand=True)

        if processing_win is not None:
            try:
                processing_win.destroy()
            except Exception:
                pass
        try:
            win.lift()
            win.focus_force()
        except Exception:
            pass

        control_row = ttk.Frame(outer)
        control_row.pack(fill="x", pady=(0, 8))

        status_var = tk.StringVar(value="Έτοιμο για replay.")
        speed_var = tk.StringVar(value="1x")
        frame_var = tk.IntVar(value=0)

        show_psr_var = tk.BooleanVar(value=True)
        show_weather_var = tk.BooleanVar(value=True)
        show_mode_a_var = tk.BooleanVar(value=True)
        show_mode_c_var = tk.BooleanVar(value=True)
        track_cancellation_enable_var = tk.BooleanVar(value=False)
        show_velocity_vector_var = tk.BooleanVar(value=False)
        show_velocity_dxdy_var = tk.BooleanVar(value=False)
        show_range_var = tk.BooleanVar(value=False)
        coordinate_scale_var = tk.StringVar(value=DEFAULT_COORDINATE_SCALE)
        show_speed_var = tk.BooleanVar(value=False)
        show_low_quality_tracks_var = tk.BooleanVar(value=True)
        show_high_quality_tracks_var = tk.BooleanVar(value=True)
        show_quality_q_var = tk.BooleanVar(value=False)
        show_detection_misses_var = tk.BooleanVar(value=False)
        show_track_number_var = tk.BooleanVar(value=False)
        show_tpr_var = tk.BooleanVar(value=False)
        show_log_sigma_var = tk.BooleanVar(value=False)
        show_time_since_north_var = tk.BooleanVar(value=False)
        show_tracking_window_var = tk.BooleanVar(value=False)
        show_smoothing_k_var = tk.BooleanVar(value=False)
        show_psr_airport_var = tk.BooleanVar(value=False)
        show_psr_test_beacon_var = tk.BooleanVar(value=False)

        ttk.Label(outer, textvariable=status_var, anchor="w").pack(fill="x", pady=(0, 1))

        slider_row = ttk.Frame(outer)
        slider_row.pack(fill="x", pady=(0, 2))
        ttk.Label(slider_row, text="Έναρξη από Wireshark Frame #:").pack(side="left")
        frame_scale = tk.Scale(
            slider_row,
            from_=0,
            to=max((evt.get('frame_no') or 0) for evt in events),
            orient="horizontal",
            variable=frame_var,
            showvalue=True,
            resolution=1
        )
        frame_scale.pack(side="left", fill="x", expand=True, padx=(8, 0))

        replay_radar_area = ttk.Frame(outer)
        replay_radar_area.pack(fill="both", expand=True)

        canvas = tk.Canvas(replay_radar_area, bg="white", highlightthickness=1, highlightbackground="#B0B0B0")
        canvas.pack(side="left", fill="both", expand=True)

        replay_settings_frame = ttk.LabelFrame(replay_radar_area, text="Label Filters", padding=(8, 6))
        replay_settings_frame.pack(side="right", fill="y", padx=(8, 0))

        replay_state = {
            'events': events,
            'index': 0,
            'running': False,
            'direction': None,
            'after_id': None,
            'angle_deg': -90.0,
            'speed': 1.0,
            'alert_message': '',
            'alert_active': False,
            'max_track_range': max_track_range if max_track_range > 0 else 1.0,
            'sector_memory': {},
            'sector_history': {},
            'history_depth': 0,
            'paused_by_alert': False,
            'scan_start_index': 0,
            'zoom_factor': 1.0,
            'view_center_x': 0.0,
            'view_center_y': 0.0,
            'pan_start': None,
            'label_offsets': {},
            'label_drag': None,
            'label_track_map': {},
            'label_font_level': 1,
            'radar_geom': None,
            'sector_alert_curr': 0,
            'north_alert_curr': 0,
            'sector_alert_total': 0,
            'north_alert_total': 0,
            'sector_alert_per_hour': 0.0,
            'north_alert_per_hour': 0.0,
            'all_alert_per_hour': 0.0,
            'programmatic_frame_update': False,
            'track_cancellations': 0,
            'scan_count': 0,
            'last_applied_event_index': None,
            'chunk_no': None,
            'chunk_warmup_start_index': 0,
            'chunk_start_index': 0,
            'chunk_end_index': len(events) - 1,
        }

        event_times = [float(evt.get('time') or 0.0) for evt in events]
        first_replay_time = event_times[0] if event_times else 0.0
        last_replay_time = event_times[-1] if event_times else first_replay_time

        frame_lookup = sorted(
            (int(evt.get('frame_no') or 0), idx)
            for idx, evt in enumerate(events)
            if evt.get('frame_no') is not None
        )
        frame_lookup_numbers = [item[0] for item in frame_lookup]
        frame_lookup_indices = [item[1] for item in frame_lookup]

        sector_alert_prefix = [0]
        north_alert_prefix = [0]
        for evt in events:
            sector_alert_prefix.append(
                sector_alert_prefix[-1] + (1 if evt.get('kind') == 'alert_sector' else 0)
            )
            north_alert_prefix.append(
                north_alert_prefix[-1] + (1 if evt.get('kind') == 'alert_north' else 0)
            )

        def get_speed():
            txt = speed_var.get().strip().lower().replace("x", "")
            try:
                if "/" in txt:
                    num, den = txt.split("/", 1)
                    value = float(num) / float(den)
                else:
                    value = float(txt)
                return value if value > 0 else 1.0
            except Exception:
                return 1.0

        def find_start_index_by_frame(frame_no):
            try:
                frame_no = int(frame_no)
            except Exception:
                frame_no = 0
            if frame_no <= 0 or not frame_lookup_numbers:
                return 0
            pos = bisect.bisect_left(frame_lookup_numbers, frame_no)
            if pos >= len(frame_lookup_indices):
                return len(events) - 1
            return max(0, min(frame_lookup_indices[pos], len(events) - 1))


        def find_next_sector_index(start_index):
            start_index = max(0, min(start_index, len(events) - 1))
            for i in range(start_index, len(events)):
                if events[i]['kind'] in ('sector', 'weather'):
                    return i
            return min(start_index, len(events) - 1)

        def find_next_north_index(start_index):
            start_index = max(0, min(start_index, len(events) - 1))
            for i in range(start_index, len(events)):
                if events[i]['kind'] == 'north':
                    return i
            return min(start_index, len(events) - 1)

        def update_alert_progress(current_index):
            current_index = max(0, min(current_index, len(events) - 1))
            prefix_index = max(0, min(current_index + 1, len(sector_alert_prefix) - 1))

            sector_curr = sector_alert_prefix[prefix_index]
            north_curr = north_alert_prefix[prefix_index]
            sector_total = sector_alert_prefix[-1]
            north_total = north_alert_prefix[-1]

            replay_state['sector_alert_curr'] = sector_curr
            replay_state['north_alert_curr'] = north_curr
            replay_state['sector_alert_total'] = sector_total
            replay_state['north_alert_total'] = north_total

            if capture_duration_hours and capture_duration_hours > 0:
                replay_state['sector_alert_per_hour'] = sector_total / capture_duration_hours
                replay_state['north_alert_per_hour'] = north_total / capture_duration_hours
                replay_state['all_alert_per_hour'] = (sector_total + north_total) / capture_duration_hours
            else:
                replay_state['sector_alert_per_hour'] = 0.0
                replay_state['north_alert_per_hour'] = 0.0
                replay_state['all_alert_per_hour'] = 0.0


        def event_angle_deg(evt):
            if evt['kind'] == 'north':
                return -90.0
            if evt['kind'] == 'alert_sector':
                if evt.get('alert_anchor') == 'north' or evt.get('sector') is None:
                    return -90.0
                sector = evt.get('sector')
                return -90.0 + ((sector + 0.5) * 360.0 / 32.0)
            if evt['kind'].startswith('alert_'):
                return None
            sector = evt.get('sector')
            if sector is None:
                return -90.0
            return -90.0 + ((sector + 0.5) * 360.0 / 32.0)

        def format_replay_progress_text(evt):
            ts = format_capture_time(evt.get('time'))
            if " " in ts:
                time_only = ts.split(" ", 1)[1]
            else:
                time_only = ts
            frame_no = evt.get('frame_no', '')
            return f"{time_only} | packet #{frame_no}"

        def format_replay_status_line2(evt):
            ts = format_capture_time(evt.get('time'))

            elapsed_txt = "n/a"
            pct_txt = "n/a"
            if capture_start_ts is not None and evt.get('time') is not None:
                elapsed_sec = max(0.0, evt.get('time') - capture_start_ts)
                total_minutes = int(elapsed_sec // 60)
                hours = total_minutes // 60
                minutes = total_minutes % 60
                elapsed_txt = f"{hours:02d}:{minutes:02d}"

                if capture_end_ts is not None and capture_end_ts > capture_start_ts:
                    pct = ((evt.get('time') - capture_start_ts) / (capture_end_ts - capture_start_ts)) * 100.0
                    pct_txt = f"{pct:.2f}%"

            return f"{ts} | elapsed {elapsed_txt} | {pct_txt}"

        def format_event_text(evt, idx):
            frame_no = evt.get('frame_no', '')
            hist_txt = f"history {replay_state.get('history_depth', 0)}"
            status_line2 = format_replay_status_line2(evt)

            if evt['kind'] == 'alert_sector':
                alert_txt = evt.get('message', 'sector missing')
                line1 = f"Replay: {idx + 1}/{len(events)} | {alert_txt} | Wireshark Frame #{frame_no} | {hist_txt}"
                return line1 + "\n" + status_line2

            if evt['kind'] == 'alert_north':
                alert_txt = evt.get('message', 'north missing')
                line1 = f"Replay: {idx + 1}/{len(events)} | {alert_txt} | Wireshark Frame #{frame_no} | {hist_txt}"
                return line1 + "\n" + status_line2

            track_count = len(evt.get('tracks', []))
            extra = f" | tracks {track_count}" if evt['kind'] in ('sector', 'weather') else ""
            line1 = f"Replay: {idx + 1}/{len(events)} | {evt['label']} | Wireshark Frame #{frame_no}{extra} | {hist_txt} | speed {speed_var.get()}"
            return line1 + "\n" + status_line2

        def apply_event_to_memory(evt, event_index=None, force=False):
            if event_index is None:
                event_index = replay_state.get('index')
            if not force and replay_state.get('last_applied_event_index') == event_index:
                return

            if evt.get('scan_no') is not None:
                replay_state['scan_count'] = int(evt.get('scan_no') or 0)

            if evt['kind'] == 'north':
                _purge_expired_cancelled_tracks(replay_state['sector_memory'], replay_state.get('scan_count', 0))
                replay_state['last_applied_event_index'] = event_index
                return

            if evt['kind'] == 'sector':
                sector = evt.get('sector')
                parsed_items = [dict(t) for t in evt.get('tracks', [])]
                for _t in parsed_items:
                    try:
                        _t.setdefault('source_frame_no', evt.get('frame_no'))
                        _t.setdefault('source_time', evt.get('time'))
                        _t.setdefault('source_event_index', event_index)
                        _t.setdefault('source_sector', sector)
                    except Exception:
                        pass
                cancellations = [t for t in parsed_items if t.get('is_cancellation')]
                tracks = [t for t in parsed_items if not t.get('is_cancellation')]

                if track_cancellation_enable_var.get() and cancellations:
                    for cancellation in cancellations:
                        _mark_cancelled_tracks(replay_state['sector_memory'], cancellation, replay_state.get('scan_count', 0))
                    replay_state['track_cancellations'] = int(replay_state.get('track_cancellations', 0) or 0) + len(cancellations)

                if sector is not None:
                    if tracks or not cancellations:
                        previous = replay_state['sector_memory'].get(sector, [])
                        _drop_cancelled_tracks_replaced_by_updates(replay_state['sector_memory'], tracks)
                        if previous:
                            hist = replay_state['sector_history'].setdefault(sector, [])
                            hist.insert(0, [dict(t) for t in previous])
                            replay_state['sector_history'][sector] = hist[:20]
                        replay_state['sector_memory'][sector] = _merge_pending_cancelled_tracks(
                            previous,
                            tracks,
                            replay_state.get('scan_count', 0)
                        )

            elif evt['kind'] == 'weather':
                sector = evt.get('sector')
                if sector is not None:
                    weather_marker = {
                        'type': 0x2A,
                        'track_no': None,
                        'x': 0.0,
                        'y': 0.0,
                        'range': replay_state.get('max_track_range', 1.0) * 0.92,
                        'angle_deg': -90.0 + ((sector + 0.5) * 360.0 / 32.0),
                        'mode_a': None,
                        'mode_c': None,
                        'psr': False,
                        'has_ssr': False,
                        'is_combined': False,
                        'is_weather': True,
                        'is_cancellation': False,
                    }
                    current = replay_state['sector_memory'].setdefault(sector, [])
                    current = [t for t in current if not t.get('is_weather')]
                    current.append(weather_marker)
                    replay_state['sector_memory'][sector] = current

            replay_state['last_applied_event_index'] = event_index

        def build_track_label(track):
            lines = []
            if track.get('is_weather'):
                if show_weather_var.get():
                    lines.append("W")
                return "\n".join(lines)

            # Label order: PSR/W status first, Track + cancellation on one line,
            # A, C, speed, range, quality, LogSigma, then the rest.
            if track.get('psr'):
                if show_psr_var.get():
                    lines.append("PSR")

            track_line = None
            if show_track_number_var.get() and track.get('track_no') is not None:
                track_line = f"Track:{track['track_no']}"
            if track.get('track_cancelled'):
                if track_line:
                    track_line += " / Track cancelled"
                else:
                    track_line = "Track cancelled"
            if track_line:
                lines.append(track_line)

            if show_tpr_var.get() and track.get('tpr_number') is not None:
                lines.append(f"TPR#{int(track.get('tpr_number'))}")

            if show_mode_a_var.get() and track.get('mode_a'):
                a_txt = f"A:{track['mode_a']}"
                if track.get('mode_a_status') == "invalid":
                    a_txt += " invalid"
                lines.append(a_txt)

            if show_mode_c_var.get() and track.get('mode_c'):
                c_txt = f"C:{track['mode_c']}"
                if track.get('mode_c_status'):
                    c_txt += f" {track['mode_c_status']}"
                lines.append(c_txt)

            if show_speed_var.get() and track.get('speed_kt') is not None:
                lines.append(f"spd: {int(track['speed_kt'])} kt")

            if show_range_var.get():
                lines.extend(_format_track_range_lines(track, coordinate_scale_var.get()))

            if show_quality_q_var.get() and track.get('quality') is not None:
                q_max = _track_quality_max(track)
                if q_max:
                    lines.append(f"Quality:{int(track['quality'])}/{q_max}")
                else:
                    lines.append(f"Quality:{int(track['quality'])}")

            if show_log_sigma_var.get() and int(track.get('type') or 0) == 0xFF and track.get('log_sigma_present'):
                if track.get('log_sigma_v') is not None:
                    lines.append(f"LogSigma: {track['log_sigma_v']:.2f}V / 2.5V")

            if show_time_since_north_var.get() and track.get('time_since_north_sec') is not None:
                lines.append(f"TN:{_format_time_since_north(track.get('time_since_north_sec'))}")
            if show_tracking_window_var.get() and track.get('tracking_window_short'):
                lines.append(f"W:{track.get('tracking_window_short')}")
            if show_smoothing_k_var.get() and track.get('smoothing_k') is not None:
                lines.append(f"K:{track.get('smoothing_k')}")

            if show_psr_airport_var.get() and track.get('psr'):
                if track.get('psr_airport_slow'):
                    lines.append("SLOW AIRPORT")
                if track.get('psr_airport_fast'):
                    lines.append("FAST AIRPORT")

            if show_psr_test_beacon_var.get() and track.get('psr'):
                if track.get('psr_test_beacon'):
                    lines.append("TEST BEACON")
                if track.get('psr_tvd900_test'):
                    lines.append("TVD900 TEST")

            if show_detection_misses_var.get():
                misses = track.get('detection_misses')
                if misses is not None and int(misses) > 0:
                    lines.append(f"misses: {int(misses)}")

            if track.get('maneuver'):
                lines.append("Unstable")

            return "\n".join(lines)

        def get_label_font_size():
            level = int(replay_state.get('label_font_level', 1))
            level = max(1, min(4, level))
            size_map = {1: 8, 2: 9, 3: 10, 4: 11}
            return size_map.get(level, 8)

        def get_visible_range():
            # Fixed full-scale radar range: at zoom=1 the outer circle represents
            # 250 NM using the fixed coordinate scale. With the default
            # 1/32 NM scale this is 8000 raw AIRCAT units.
            zoom = max(1.0, replay_state.get('zoom_factor', 1.0))
            max_range = _display_range_raw_units(coordinate_scale_var.get())
            return max(1.0, max_range / zoom)

        def history_color(age_index, total_depth):
            if total_depth <= 1:
                gray = 0
            else:
                gray = int(round((age_index / max(1, total_depth - 1)) * 210))
            gray = max(0, min(220, gray))
            return f"#{gray:02X}{gray:02X}{gray:02X}"

        def calc_geom():
            width = max(canvas.winfo_width(), 220)
            height = max(canvas.winfo_height(), 220)
            side = min(width, height) - 110
            radius = max(side / 2, 90)
            cx = width / 2
            cy = height / 2
            x1, y1, x2, y2 = cx - radius, cy - radius, cx + radius, cy + radius
            replay_state['radar_geom'] = {
                'width': width, 'height': height, 'radius': radius,
                'cx': cx, 'cy': cy, 'x1': x1, 'y1': y1, 'x2': x2, 'y2': y2
            }
            return replay_state['radar_geom']

        def draw_static_radar():
            geom = calc_geom()
            canvas.delete("static")
            cx, cy, radius = geom['cx'], geom['cy'], geom['radius']
            x1, y1, x2, y2 = geom['x1'], geom['y1'], geom['x2'], geom['y2']

            outline_color = "#9A9A9A" if replay_state.get('alert_active') else "black"
            sector_line_color = "#CFCFCF" if replay_state.get('alert_active') else "#BFBFBF"
            north_line_color = "#A8A8A8" if replay_state.get('alert_active') else "#808080"

            canvas.create_oval(x1, y1, x2, y2, outline=outline_color, width=2, tags=("static",))
            _draw_nm_range_rings(
                canvas, cx, cy, radius,
                get_visible_range(),
                coordinate_scale_var.get(),
                tags=("static",)
            )

            for i in range(32):
                boundary_deg = -90.0 + (i * 360.0 / 32.0)
                rad = math.radians(boundary_deg)
                bx = cx + radius * math.cos(rad)
                by = cy + radius * math.sin(rad)
                canvas.create_line(cx, cy, bx, by, fill=sector_line_color, tags=("static",))

                center_deg = -90.0 + ((i + 0.5) * 360.0 / 32.0)
                crad = math.radians(center_deg)
                tx = cx + (radius + 18) * math.cos(crad)
                ty = cy + (radius + 18) * math.sin(crad)
                canvas.create_text(tx, ty, text=f"{i:02X}", font=("Arial", 8), fill="#707070", tags=("static",))

            if replay_state.get('events'):
                curr_evt = replay_state['events'][max(0, min(replay_state.get('index', 0), len(replay_state['events']) - 1))]
                progress_txt = format_replay_progress_text(curr_evt)
                progress_y = max(12, y1 - 42)
                canvas.create_text(
                    cx, progress_y,
                    text=progress_txt,
                    anchor="n",
                    justify="center",
                    fill="#505050",
                    font=("Arial", 11),
                    tags=("static",)
                )

            canvas.create_text(cx, y1 - 20, text="N", font=("Arial", 12, "bold"), fill="#606060", tags=("static",))
            north_rad = math.radians(-90.0)
            nx = cx + radius * math.cos(north_rad)
            ny = cy + radius * math.sin(north_rad)
            canvas.create_line(cx, cy, nx, ny, fill=north_line_color, dash=(4, 2), tags=("static",))

            right_x = geom['width'] - 10

            alert_y = 8
            alert_title_font = ("Arial", 11, "bold")
            alert_font = ("Arial", 12, "bold")
            canvas.create_text(
                right_x, alert_y,
                text="System alerts",
                anchor="ne", justify="right", fill="#606060", font=alert_title_font, tags=("static",)
            )
            canvas.create_text(
                right_x, alert_y + 18,
                text=f"sector missing {replay_state.get('sector_alert_curr', 0)}/{replay_state.get('sector_alert_total', 0)}",
                anchor="ne", justify="right", fill="red", font=alert_font, tags=("static",)
            )
            canvas.create_text(
                right_x, alert_y + 36,
                text=f"north missing {replay_state.get('north_alert_curr', 0)}/{replay_state.get('north_alert_total', 0)}",
                anchor="ne", justify="right", fill="red", font=alert_font, tags=("static",)
            )
            help_y = geom['height'] - 100
            help_font = ("Arial", 11)
            try:
                div = _coordinate_scale_divisor(coordinate_scale_var.get())
                cx_nm = float(replay_state.get('view_center_x', 0.0) or 0.0) / div
                cy_nm = float(replay_state.get('view_center_y', 0.0) or 0.0) / div
                center_txt = f"Center X={cx_nm:.1f}NM Y={cy_nm:.1f}NM"
            except Exception:
                center_txt = "Center X=0.0NM Y=0.0NM"
            canvas.create_text(
                right_x, help_y,
                text=f"+/- Zoom x{replay_state['zoom_factor']:.1f}",
                anchor="ne", justify="right", fill="#505050", font=help_font, tags=("static",)
            )
            canvas.create_text(
                right_x, help_y + 18,
                text=center_txt,
                anchor="ne", justify="right", fill="#505050", font=help_font, tags=("static",)
            )
            canvas.create_text(
                right_x, help_y + 36,
                text=f"Shift +/- για labels | L{replay_state.get('label_font_level', 1)}/4",
                anchor="ne", justify="right", fill="#505050", font=help_font, tags=("static",)
            )
            canvas.create_text(
                right_x, help_y + 54,
                text=f"Ctrl +/- για track history | H{replay_state['history_depth']}/20",
                anchor="ne", justify="right", fill="#505050", font=help_font, tags=("static",)
            )
            canvas.create_text(
                right_x, help_y + 72,
                text="Drag label/pan | Ctrl+drag current scan raw | Esc defaults",
                anchor="ne", justify="right", fill="#505050", font=help_font, tags=("static",)
            )

        def should_draw_track(track):
            if track.get('is_cancellation'):
                return False
            if track.get('is_weather'):
                return bool(show_weather_var.get())
            if track.get('psr') and not show_psr_var.get():
                return False
            is_low = _is_low_quality_track(track)
            if is_low and not show_low_quality_tracks_var.get():
                return False
            if (not is_low) and not show_high_quality_tracks_var.get():
                return False
            return True

        def track_to_canvas_xy(track):
            geom = replay_state.get('radar_geom') or calc_geom()
            visible_range = get_visible_range()
            try:
                if track.get('x') is not None and track.get('y') is not None:
                    x_raw = float(track.get('x') or 0.0)
                    y_raw = float(track.get('y') or 0.0)
                else:
                    rng = float(track.get('range', 0.0) or 0.0)
                    ta = math.radians(track.get('angle_deg', replay_state['angle_deg']))
                    x_raw = rng * math.cos(ta)
                    y_raw = -rng * math.sin(ta)

                center_x = float(replay_state.get('view_center_x', 0.0) or 0.0)
                center_y = float(replay_state.get('view_center_y', 0.0) or 0.0)
                rel_x = x_raw - center_x
                rel_y = y_raw - center_y
                if math.hypot(rel_x, rel_y) > visible_range:
                    return None
                scale = geom['radius'] / max(1.0, visible_range)
                tx = geom['cx'] + (rel_x * scale)
                ty = geom['cy'] - (rel_y * scale)
                return tx, ty
            except Exception:
                return None

        def draw_velocity_vector(track, tx, ty, color, tag):
            if not show_velocity_vector_var.get():
                return
            if track.get('track_cancelled'):
                return
            dx = track.get('dx')
            dy = track.get('dy')
            if dx is None or dy is None:
                return
            try:
                dx = float(dx)
                dy = float(dy)
            except Exception:
                return
            if dx == 0 and dy == 0:
                return

            geom = replay_state.get('radar_geom') or calc_geom()
            visible_range = get_visible_range()
            scale = geom['radius'] / max(1.0, visible_range)
            vx = dx * scale
            vy = -dy * scale
            length = math.hypot(vx, vy)
            if length <= 0:
                return
            if length > 42:
                factor = 42.0 / length
                vx *= factor
                vy *= factor
            elif length < 8:
                factor = 8.0 / length
                vx *= factor
                vy *= factor

            # Tag the vector with the same sector/history tag as the symbol.
            # This prevents an old vector from remaining on the canvas when only one
            # sector is refreshed. Position and vector are therefore updated atomically.
            canvas.create_line(tx, ty, tx + vx, ty + vy, fill=color, width=1, arrow=tk.LAST, tags=(tag, "dynamic"))

        def draw_track_list(track_list, color, tag, draw_labels=False, is_history=False):
            canvas.delete(tag)
            for track in track_list:
                if not should_draw_track(track):
                    continue
                xy = track_to_canvas_xy(track)
                if xy is None:
                    continue
                tx, ty = xy

                draw_color = "red" if (_is_low_quality_track(track) or _is_red_target_alert_track(track)) else color

                if track.get('is_weather'):
                    weather_color = "#800080"
                    canvas.create_rectangle(tx - 3, ty - 3, tx + 3, ty + 3, fill=weather_color, outline=weather_color, tags=(tag, "dynamic"))
                else:
                    # History traces stay lightweight by design: position symbol only.
                    # Current targets keep the full symbol / vector / label information.
                    if not is_history:
                        draw_velocity_vector(track, tx, ty, draw_color, tag)

                    if _is_special_mode_a_alert_track(track):
                        _draw_special_mode_a_plus(canvas, tx, ty, draw_color, tags=(tag, "dynamic"))
                    else:
                        is_psr = bool(track.get('psr'))
                        is_ssr = bool(track.get('has_ssr'))
                        is_combined = bool(track.get('is_combined'))

                        if is_combined:
                            points = [tx, ty - 4, tx - 4, ty + 3, tx + 4, ty + 3]
                            canvas.create_polygon(points, outline=draw_color, fill="", width=1, tags=(tag, "dynamic"))
                            canvas.create_oval(tx - 1.5, ty - 1.5, tx + 1.5, ty + 1.5, fill=draw_color, outline=draw_color, tags=(tag, "dynamic"))
                        elif is_psr and not is_ssr:
                            canvas.create_oval(tx - 2, ty - 2, tx + 2, ty + 2, fill=draw_color, outline=draw_color, tags=(tag, "dynamic"))
                        else:
                            points = [tx, ty - 4, tx - 4, ty + 3, tx + 4, ty + 3]
                            canvas.create_polygon(points, outline=draw_color, fill="", width=1, tags=(tag, "dynamic"))

                effective_draw_labels = bool(draw_labels) and not is_history

                if effective_draw_labels:
                    label_size = get_label_font_size()
                    label_txt = build_track_label(track)
                    flag_lines = _track_status_flag_lines(track)
                    label_key = _track_label_offset_key(track)
                    offset_x, offset_y = (0.0, 0.0)
                    if label_key:
                        try:
                            offset_x, offset_y = replay_state.setdefault('label_offsets', {}).get(label_key, (0.0, 0.0))
                        except Exception:
                            offset_x, offset_y = (0.0, 0.0)
                    label_x = tx + 1 + float(offset_x)
                    label_y = ty + float(offset_y)
                    label_tags = _track_label_canvas_tags(track, tag, "dynamic")
                    if label_key:
                        try:
                            replay_state.setdefault('label_track_map', {})[label_key] = track
                        except Exception:
                            pass
                    if _has_manual_label_offset(offset_x, offset_y):
                        try:
                            canvas.create_line(
                                tx, ty, label_x, label_y,
                                fill="#0066CC", width=1, tags=(tag, "dynamic")
                            )
                        except Exception:
                            pass
                    label_line_count = label_txt.count("\n") + 1 if label_txt else 0
                    if flag_lines:
                        flag_y = label_y - (label_line_count * (label_size + 2))
                        canvas.create_text(
                            label_x, flag_y,
                            text="\n".join(flag_lines),
                            anchor="sw",
                            justify="left",
                            fill="red",
                            font=("Arial", label_size, "bold"),
                            tags=label_tags
                        )
                    if label_txt:
                        canvas.create_text(
                            label_x, label_y,
                            text=label_txt,
                            anchor="sw",
                            justify="left",
                            fill="red" if _is_low_quality_track(track) else "#202020",
                            font=("Arial", label_size),
                            tags=label_tags
                        )

        def rebuild_dynamic_layers():
            canvas.delete("dynamic")
            canvas.delete("sweep")
            canvas.delete("alert")
            try:
                replay_state.setdefault('label_track_map', {}).clear()
            except Exception:
                replay_state['label_track_map'] = {}

            hist_depth = replay_state.get('history_depth', 0)
            for sector_no, hist_list in replay_state.get('sector_history', {}).items():
                visible_hist = hist_list[:hist_depth]
                for hist_idx in range(len(visible_hist) - 1, -1, -1):
                    color = history_color(hist_idx, max(1, hist_depth))
                    draw_track_list(visible_hist[hist_idx], color, f"history_{sector_no}_{hist_idx}", draw_labels=False, is_history=True)

            for sector_no, tracks in replay_state.get('sector_memory', {}).items():
                draw_track_list(tracks, "#0033AA", f"sector_{sector_no}", draw_labels=True)

            geom = replay_state.get('radar_geom') or calc_geom()
            angle_rad = math.radians(replay_state['angle_deg'])
            rx = geom['cx'] + geom['radius'] * math.cos(angle_rad)
            ry = geom['cy'] + geom['radius'] * math.sin(angle_rad)
            canvas.create_line(geom['cx'], geom['cy'], rx, ry, fill="red", width=3, tags=("sweep",))

            if replay_state.get('alert_message'):
                canvas.create_text(
                    geom['cx'], geom['cy'],
                    text=replay_state['alert_message'],
                    fill="red",
                    font=("Arial", 18, "bold"),
                    tags=("alert",)
                )

        def redraw_sector_only(sector_no):
            if replay_state.get('alert_active'):
                rebuild_dynamic_layers()
                return
            if sector_no is None:
                rebuild_dynamic_layers()
                return

            # Refresh immediately both:
            # 1) the history already moved from current -> history
            # 2) the new current targets for this sector
            canvas.delete(f"sector_{sector_no}")
            hist_depth = replay_state.get('history_depth', 0)
            for hist_idx in range(20):
                canvas.delete(f"history_{sector_no}_{hist_idx}")

            hist_list = replay_state.get('sector_history', {}).get(sector_no, [])
            visible_hist = hist_list[:hist_depth]
            for hist_idx in range(len(visible_hist) - 1, -1, -1):
                color = history_color(hist_idx, max(1, hist_depth))
                draw_track_list(
                    visible_hist[hist_idx],
                    color,
                    f"history_{sector_no}_{hist_idx}",
                    draw_labels=False,
                    is_history=True
                )

            tracks = replay_state.get('sector_memory', {}).get(sector_no, [])
            draw_track_list(tracks, "#0033AA", f"sector_{sector_no}", draw_labels=True)

            canvas.delete("sweep")
            geom = replay_state.get('radar_geom') or calc_geom()
            angle_rad = math.radians(replay_state['angle_deg'])
            rx = geom['cx'] + geom['radius'] * math.cos(angle_rad)
            ry = geom['cy'] + geom['radius'] * math.sin(angle_rad)
            canvas.create_line(geom['cx'], geom['cy'], rx, ry, fill="red", width=3, tags=("sweep",))

        def draw_full_scene():
            draw_static_radar()
            rebuild_dynamic_layers()

        def update_view():
            ensure_replay_chunk_for_index(replay_state['index'])
            evt = replay_state['events'][replay_state['index']]
            update_alert_progress(replay_state['index'])
            sector_changed = None

            if evt['kind'] in ('north', 'sector', 'weather') and not replay_state.get('alert_active'):
                apply_event_to_memory(evt, replay_state['index'])
                sector_changed = evt.get('sector')

            new_angle = event_angle_deg(evt)

            if evt['kind'].startswith('alert_'):
                if new_angle is not None:
                    replay_state['angle_deg'] = new_angle
                replay_state['alert_message'] = evt.get('message', '')
                replay_state['alert_active'] = True
            else:
                if new_angle is not None:
                    replay_state['angle_deg'] = new_angle
                replay_state['alert_message'] = ''
                replay_state['alert_active'] = False

            status_var.set(format_event_text(evt, replay_state['index']))

            if evt['kind'] in ('sector', 'weather') and not replay_state.get('alert_active'):
                redraw_sector_only(sector_changed)
            else:
                draw_full_scene()

        def cancel_timer():
            after_id = replay_state.get('after_id')
            if after_id is not None:
                try:
                    win.after_cancel(after_id)
                except Exception:
                    pass
                replay_state['after_id'] = None


        def replay_delay_ms_between(prev_idx, target_idx):
            try:
                prev_evt = replay_state['events'][prev_idx]
                target_evt = replay_state['events'][target_idx]
                real_ms = int(round(
                    (float(target_evt.get('time') or 0.0) - float(prev_evt.get('time') or 0.0))
                    * 1000.0 / max(replay_state.get('speed', 1.0), 0.001)
                ))
                return max(1, real_ms)
            except Exception:
                return 1

        def choose_next_target_index(start_idx):
            return min(start_idx + 1, len(replay_state['events']) - 1)

        def chunk_bounds_for_index(index):
            index = max(0, min(int(index or 0), len(events) - 1))
            target_time = event_times[index] if event_times else first_replay_time
            if REPLAY_CHUNK_SECONDS <= 0:
                chunk_no = 0
            else:
                chunk_no = int(max(0.0, (target_time - first_replay_time)) // REPLAY_CHUNK_SECONDS)

            chunk_start_time = first_replay_time + (chunk_no * REPLAY_CHUNK_SECONDS)
            chunk_end_time = min(last_replay_time, chunk_start_time + REPLAY_CHUNK_SECONDS)
            decode_start_time = max(first_replay_time, chunk_start_time - REPLAY_CHUNK_WARMUP_SECONDS)

            decode_start_index = bisect.bisect_left(event_times, decode_start_time)
            chunk_start_index = bisect.bisect_left(event_times, chunk_start_time)
            chunk_end_index = bisect.bisect_right(event_times, chunk_end_time) - 1

            decode_start_index = max(0, min(decode_start_index, len(events) - 1))
            chunk_start_index = max(0, min(chunk_start_index, len(events) - 1))
            chunk_end_index = max(chunk_start_index, min(chunk_end_index, len(events) - 1))

            return decode_start_index, chunk_start_index, chunk_end_index, chunk_no, chunk_start_time, chunk_end_time

        def ensure_replay_chunk_for_index(index, force=False):
            decode_start_index, chunk_start_index, chunk_end_index, chunk_no, chunk_start_time, chunk_end_time = chunk_bounds_for_index(index)

            same_chunk = (
                replay_state.get('chunk_no') == chunk_no
                and replay_state.get('chunk_start_index') == chunk_start_index
                and replay_state.get('chunk_end_index') == chunk_end_index
            )
            if force or not same_chunk:
                local_max = self._ensure_replay_tracks_for_event_range(
                    events,
                    decode_start_index,
                    chunk_end_index
                )
                try:
                    replay_state['max_track_range'] = max(
                        float(replay_state.get('max_track_range', 1.0) or 1.0),
                        float(local_max or 1.0)
                    )
                except Exception:
                    pass

                replay_state['chunk_no'] = chunk_no
                replay_state['chunk_warmup_start_index'] = decode_start_index
                replay_state['chunk_start_index'] = chunk_start_index
                replay_state['chunk_end_index'] = chunk_end_index
                replay_state['chunk_start_time'] = chunk_start_time
                replay_state['chunk_end_time'] = chunk_end_time

            return decode_start_index, chunk_start_index, chunk_end_index

        def rebuild_replay_state_for_index(index):
            target_index = max(0, min(int(index or 0), len(events) - 1))
            ensure_replay_chunk_for_index(target_index)

            target_time = event_times[target_index] if event_times else first_replay_time
            warmup_start_time = max(first_replay_time, target_time - REPLAY_CHUNK_WARMUP_SECONDS)
            warmup_start_index = bisect.bisect_left(event_times, warmup_start_time)
            warmup_start_index = max(0, min(warmup_start_index, target_index))

            replay_state['index'] = target_index
            replay_state['alert_message'] = ''
            replay_state['alert_active'] = False
            replay_state['paused_by_alert'] = False
            replay_state['sector_memory'] = {}
            replay_state['sector_history'] = {}
            replay_state['track_cancellations'] = 0
            replay_state['scan_count'] = 0
            replay_state['last_applied_event_index'] = None
            replay_state['angle_deg'] = -90.0
            replay_state['scan_start_index'] = warmup_start_index

            for i in range(warmup_start_index, target_index + 1):
                evt_i = events[i]

                if evt_i['kind'] == 'north':
                    replay_state['scan_start_index'] = i

                if evt_i['kind'] in ('north', 'sector', 'weather'):
                    apply_event_to_memory(evt_i, i, force=True)

                angle_i = event_angle_deg(evt_i)
                if angle_i is not None:
                    replay_state['angle_deg'] = angle_i

            evt = events[target_index]
            angle = event_angle_deg(evt)
            if angle is not None:
                replay_state['angle_deg'] = angle

            if evt['kind'].startswith('alert_'):
                replay_state['alert_message'] = evt.get('message', '')
                replay_state['alert_active'] = True
                replay_state['paused_by_alert'] = True
            else:
                replay_state['alert_message'] = ''
                replay_state['alert_active'] = False
                replay_state['paused_by_alert'] = False

            update_alert_progress(target_index)
            return target_index, evt

        def schedule_next():
            cancel_timer()
            if not replay_state['running'] or replay_state.get('direction') != 'forward':
                return

            idx = replay_state['index']
            if idx >= len(replay_state['events']) - 1:
                replay_state['running'] = False
                status_var.set(status_var.get() + " | Τέλος replay")
                return

            target_index_for_timer = choose_next_target_index(idx)
            delta_ms = replay_delay_ms_between(idx, target_index_for_timer)

            def advance():
                replay_state['after_id'] = None
                if not replay_state['running'] or replay_state.get('direction') != 'forward':
                    return

                current_index = replay_state['index']
                target_index = choose_next_target_index(current_index)
                ensure_replay_chunk_for_index(target_index)

                replay_state['index'] = target_index
                evt = replay_state['events'][replay_state['index']]

                if evt['kind'] == 'north' and replay_state['index'] > replay_state['scan_start_index']:
                    replay_state['scan_start_index'] = replay_state['index']

                update_view()

                if evt['kind'].startswith('alert_'):
                    replay_state['running'] = False
                    replay_state['paused_by_alert'] = True
                    try:
                        canvas.focus_set()
                        win.focus_force()
                    except Exception:
                        pass
                    return


                schedule_next()

            replay_state['after_id'] = win.after(delta_ms, advance)

        def schedule_previous():
            cancel_timer()
            if not replay_state['running'] or replay_state.get('direction') != 'backward':
                return

            idx = replay_state['index']
            if idx <= 0:
                replay_state['running'] = False
                replay_state['direction'] = None
                status_var.set(status_var.get() + " | Αρχή replay")
                return

            target_index_for_timer = max(idx - 1, 0)
            delta_ms = replay_delay_ms_between(target_index_for_timer, idx)

            def advance_backward():
                replay_state['after_id'] = None
                if not replay_state['running'] or replay_state.get('direction') != 'backward':
                    return

                current_index = replay_state['index']
                target_index = max(current_index - 1, 0)
                target_index, evt = rebuild_replay_state_for_index(target_index)
                status_var.set("Go Back | " + format_event_text(evt, target_index))
                draw_full_scene()

                if target_index <= 0:
                    replay_state['running'] = False
                    replay_state['direction'] = None
                    status_var.set(status_var.get() + " | Αρχή replay")
                    return

                if evt['kind'].startswith('alert_'):
                    replay_state['running'] = False
                    replay_state['direction'] = None
                    replay_state['paused_by_alert'] = True
                    try:
                        canvas.focus_set()
                        win.focus_force()
                    except Exception:
                        pass
                    return

                schedule_previous()

            replay_state['after_id'] = win.after(delta_ms, advance_backward)


        def begin_replay_from_index(index):
            replay_state['running'] = False
            replay_state['direction'] = None
            cancel_timer()
            replay_state['speed'] = get_speed()
            speed_var.set(f"{replay_state['speed']:g}x")

            target_index, evt = rebuild_replay_state_for_index(index)
            replay_state['scan_start_index'] = target_index if evt['kind'] == 'north' else replay_state.get('scan_start_index', target_index)
            update_view()

            if evt['kind'].startswith('alert_'):
                return

            replay_state['running'] = True
            replay_state['direction'] = 'forward'
            schedule_next()


        def step_to_index(index):
            """Stop replay and reconstruct the radar state using the hidden warm-up window."""
            replay_state['running'] = False
            replay_state['direction'] = None
            cancel_timer()

            target_index, evt = rebuild_replay_state_for_index(index)

            # Τα Step Back / Step Forward δεν ενημερώνουν τη μπάρα.
            # Η μπάρα μένει στην τιμή που έχει επιλέξει ο χρήστης ως start point.
            status_var.set("Step | " + format_event_text(evt, target_index))
            draw_full_scene()

            try:
                canvas.focus_set()
                win.focus_force()
            except Exception:
                pass

            return "break"


        def step_back():
            return step_to_index(replay_state.get('index', 0) - 1)

        def step_forward():
            return step_to_index(replay_state.get('index', 0) + 1)

        def go_forward_from_current(_event=None):
            """Continue normal replay forward from the current step/replay position."""
            replay_state['running'] = False
            replay_state['direction'] = None
            cancel_timer()

            if replay_state['index'] >= len(replay_state['events']) - 1:
                evt = replay_state['events'][replay_state['index']]
                status_var.set("Go Fwd | " + format_event_text(evt, replay_state['index']) + " | Τέλος replay")
                return "break"

            replay_state['alert_message'] = ''
            replay_state['alert_active'] = False
            replay_state['paused_by_alert'] = False
            replay_state['speed'] = get_speed()

            evt = replay_state['events'][replay_state['index']]
            status_var.set("Go Fwd | " + format_event_text(evt, replay_state['index']))

            draw_full_scene()
            replay_state['running'] = True
            replay_state['direction'] = 'forward'
            schedule_next()

            try:
                canvas.focus_set()
                win.focus_force()
            except Exception:
                pass

            return "break"

        def go_backward_from_current(_event=None):
            """Run replay backward from the current step/replay position."""
            replay_state['running'] = False
            replay_state['direction'] = None
            cancel_timer()

            if replay_state['index'] <= 0:
                evt = replay_state['events'][replay_state['index']]
                status_var.set("Go Back | " + format_event_text(evt, replay_state['index']) + " | Αρχή replay")
                return "break"

            replay_state['alert_message'] = ''
            replay_state['alert_active'] = False
            replay_state['paused_by_alert'] = False
            replay_state['speed'] = get_speed()

            evt = replay_state['events'][replay_state['index']]
            status_var.set("Go Back | " + format_event_text(evt, replay_state['index']))

            draw_full_scene()
            replay_state['running'] = True
            replay_state['direction'] = 'backward'
            schedule_previous()

            try:
                canvas.focus_set()
                win.focus_force()
            except Exception:
                pass

            return "break"

        def start_replay():
            if replay_state['running']:
                return
            start_index = find_start_index_by_frame(frame_var.get())
            begin_replay_from_index(start_index)

        def pause_replay():
            replay_state['running'] = False
            replay_state['direction'] = None
            replay_state['paused_by_alert'] = False
            cancel_timer()
            evt = replay_state['events'][replay_state['index']]
            status_var.set(f"Pause | {format_event_text(evt, replay_state['index'])}")

        def reset_replay():
            replay_state['running'] = False
            replay_state['direction'] = None
            cancel_timer()

            # Restore replay runtime state to the same defaults used when the window opens.
            replay_state['angle_deg'] = -90.0
            replay_state['speed'] = get_speed()
            speed_var.set("1x")
            replay_state['alert_message'] = ''
            replay_state['alert_active'] = False
            replay_state['paused_by_alert'] = False
            replay_state['sector_memory'] = {}
            replay_state['sector_history'] = {}
            replay_state['track_cancellations'] = 0
            replay_state['scan_count'] = 0
            replay_state['last_applied_event_index'] = None
            replay_state['history_depth'] = 0
            replay_state['zoom_factor'] = 1.0
            replay_state['label_font_level'] = 1
            replay_state['sector_alert_curr'] = 0
            replay_state['north_alert_curr'] = 0

            # Keep the current slider-selected starting point, then start automatically.
            start_index = find_start_index_by_frame(frame_var.get())
            replay_state['index'] = start_index
            replay_state['scan_start_index'] = start_index
            update_alert_progress(start_index)
            draw_full_scene()
            win.after(10, lambda idx=start_index: begin_replay_from_index(idx))

        ttk.Button(control_row, text="Start", command=start_replay).pack(side="left")
        ttk.Button(control_row, text="Pause", command=pause_replay).pack(side="left", padx=(8, 0))
        ttk.Button(control_row, text="Go Back", command=go_backward_from_current).pack(side="left", padx=(8, 0))
        ttk.Button(control_row, text="Step Back", command=step_back).pack(side="left", padx=(8, 0))
        ttk.Button(control_row, text="Step Forward", command=step_forward).pack(side="left", padx=(8, 0))
        ttk.Button(control_row, text="Go Fwd", command=go_forward_from_current).pack(side="left", padx=(8, 0))
        ttk.Button(control_row, text="Reset", command=reset_replay).pack(side="left", padx=(8, 0))

        ttk.Label(control_row, text="Ταχύτητα:").pack(side="left", padx=(16, 4))
        speed_combo = ttk.Combobox(
            control_row,
            textvariable=speed_var,
            width=6,
            state="readonly",
            values=("1/32x", "1x", "2x", "5x", "10x", "20x", "50x")
        )
        speed_combo.pack(side="left")

        def refresh_label_filters_preserve_replay(rebuild_state=False):
            """Redraw Label Filters without changing replay mode or direction.

            A label-filter click must not turn Pause/Step into Go, must not stop
            an active Go Fwd / Go Back, and must not change the current replay
            index. Track cancellation needs a state rebuild because it affects
            how cancellations are applied, but the previous replay mode is
            restored immediately afterwards.
            """
            current_index = replay_state.get('index', 0)
            was_running = bool(replay_state.get('running'))
            saved_direction = replay_state.get('direction')
            saved_paused_by_alert = bool(replay_state.get('paused_by_alert'))
            saved_status = status_var.get()

            if rebuild_state:
                cancel_timer()
                replay_state['running'] = False
                target_index, _evt = rebuild_replay_state_for_index(current_index)
                replay_state['index'] = target_index
                draw_full_scene()
            else:
                draw_full_scene()

            # Restore the mode exactly as it was before the checkbox click.
            replay_state['paused_by_alert'] = saved_paused_by_alert
            status_var.set(saved_status)

            if was_running and saved_direction in ('forward', 'backward'):
                replay_state['running'] = True
                replay_state['direction'] = saved_direction
                if saved_direction == 'forward':
                    schedule_next()
                else:
                    schedule_previous()
            else:
                replay_state['running'] = False
                replay_state['direction'] = saved_direction

            try:
                canvas.focus_set()
            except Exception:
                pass

            return "break"

        def add_replay_setting(label, variable, command=None):
            ttk.Checkbutton(
                replay_settings_frame,
                text=label,
                variable=variable,
                command=command or refresh_label_filters_preserve_replay
            ).pack(anchor="w", pady=1)

        add_replay_setting("PSR", show_psr_var)
        add_replay_setting("Weather", show_weather_var)
        add_replay_setting("Mode A", show_mode_a_var)
        add_replay_setting("Mode C", show_mode_c_var)
        ttk.Separator(replay_settings_frame, orient="horizontal").pack(fill="x", pady=(6, 6))
        add_replay_setting("Track cancellation", track_cancellation_enable_var, lambda: refresh_label_filters_preserve_replay(rebuild_state=True))
        add_replay_setting("Velocity Vector", show_velocity_vector_var)
        add_replay_setting("Range", show_range_var)
        add_replay_setting("Speed", show_speed_var)
        add_replay_setting("Low quality tracks", show_low_quality_tracks_var)
        add_replay_setting("High quality tracks", show_high_quality_tracks_var)
        add_replay_setting("Quality Q", show_quality_q_var)
        add_replay_setting("Detection misses", show_detection_misses_var)
        add_replay_setting("Track number", show_track_number_var)
        add_replay_setting("TPR #", show_tpr_var)
        if self.optional_field_available('psr_airport'):
            add_replay_setting("Fast/Slow airport", show_psr_airport_var)
        if self.optional_field_available('psr_test_beacon'):
            add_replay_setting("Test beacon", show_psr_test_beacon_var)
        if self.optional_field_available('log_sigma'):
            add_replay_setting("LogSigma (SSR)", show_log_sigma_var)
        if self.optional_field_available('tracking_window'):
            add_replay_setting("Time Since North", show_time_since_north_var)
            add_replay_setting("Tracking Window", show_tracking_window_var)
        if self.optional_field_available('smoothing_k'):
            add_replay_setting("Smoothing K", show_smoothing_k_var)

        def radar_screen_scale():
            geom = replay_state.get('radar_geom') or calc_geom()
            visible_range = get_visible_range()
            return geom['radius'] / max(1.0, visible_range)

        def reset_radar_pan_center(_event=None):
            """Reset Replay radar pan center and all manual label offsets."""
            replay_state['view_center_x'] = 0.0
            replay_state['view_center_y'] = 0.0
            replay_state['pan_start'] = None
            replay_state['label_drag'] = None
            replay_state['label_offsets'] = {}
            return redraw_shortcut_preserve_replay_mode()

        def show_replay_current_scan_raw_for_track(track):
            try:
                cancel_timer()
                replay_state['running'] = False
                replay_state['direction'] = None
                replay_state['paused_by_alert'] = False
                idx = track.get('source_event_index') if isinstance(track, dict) else None
                if idx is None:
                    idx = replay_state.get('index', 0)
                idx = max(0, min(int(idx), len(events) - 1))
                scan_start = replay_state.get('scan_start_index')
                if scan_start is None or scan_start > idx:
                    scan_start = idx
                    for j in range(idx, -1, -1):
                        if events[j].get('kind') == 'north':
                            scan_start = j
                            break
                scan_items = []
                north_evt = events[int(scan_start)] if 0 <= int(scan_start) < len(events) else {}
                target_evt = events[idx]
                start_frame = north_evt.get('frame_no')
                target_frame = track.get('source_frame_no') if isinstance(track, dict) else None
                if target_frame is None:
                    target_frame = target_evt.get('frame_no')
                start_time = north_evt.get('time')
                target_time = track.get('source_time') if isinstance(track, dict) else None
                if target_time is None:
                    target_time = target_evt.get('time')

                # Prefer the original loaded records so the diagnostic window includes
                # every UDP payload after North, not only replay-visible sector events.
                try:
                    ordered_records = self._get_ordered_records(self.current_records or [])
                except Exception:
                    ordered_records = []

                if ordered_records and (start_frame is not None or start_time is not None):
                    for rec in ordered_records:
                        payload_r = rec.get('payload', b'') or b''
                        frame_r = rec.get('frame_no')
                        time_r = rec.get('timestamp')
                        include = False
                        try:
                            if start_frame is not None and target_frame is not None and frame_r is not None:
                                include = int(start_frame) <= int(frame_r) <= int(target_frame)
                            elif start_time is not None and target_time is not None and time_r is not None:
                                include = float(start_time) <= float(time_r) <= float(target_time)
                        except Exception:
                            include = False
                        if not include:
                            continue
                        info_r = classify_aircat_payload(payload_r)
                        if info_r and info_r.get('is_north'):
                            kind_r = 'north'
                        elif info_r and info_r.get('is_sector'):
                            kind_r = 'sector'
                        elif info_r and info_r.get('type') == 0x2A:
                            kind_r = 'weather'
                        else:
                            kind_r = 'other'
                        scan_items.append({
                            'kind': kind_r,
                            'payload': payload_r,
                            'frame_no': frame_r,
                            'time': time_r,
                            'sector': info_r.get('sector') if info_r else None,
                            'label': info_r.get('type_name') if info_r else 'Other UDP payload',
                        })

                if not scan_items:
                    for j in range(int(scan_start), idx + 1):
                        evt_j = events[j]
                        if evt_j.get('kind') not in ('north', 'sector', 'weather'):
                            continue
                        scan_items.append({
                            'kind': evt_j.get('kind'),
                            'payload': evt_j.get('_payload', b''),
                            'frame_no': evt_j.get('frame_no'),
                            'time': evt_j.get('time'),
                            'sector': evt_j.get('sector'),
                            'label': evt_j.get('label'),
                        })
                try:
                    status_var.set("Pause | " + format_event_text(events[replay_state['index']], replay_state['index']))
                except Exception:
                    pass
                return self._show_current_scan_raw_window(scan_items, track, "Replay current scan raw data")
            except Exception as exc:
                try:
                    messagebox.showerror("Replay current scan raw data", str(exc))
                except Exception:
                    pass
                return "break"

        def pan_radar_start(event=None):
            if event is None:
                return "break"
            try:
                label_key = _find_track_label_key_from_canvas_event(canvas, event)
                if label_key and self._is_control_pressed(event):
                    track = replay_state.setdefault('label_track_map', {}).get(label_key)
                    replay_state['pan_start'] = None
                    replay_state['label_drag'] = None
                    show_replay_current_scan_raw_for_track(track)
                elif label_key:
                    offsets = replay_state.setdefault('label_offsets', {})
                    ox, oy = offsets.get(label_key, (0.0, 0.0))
                    replay_state['label_drag'] = {
                        'key': label_key,
                        'screen_x': float(event.x),
                        'screen_y': float(event.y),
                        'offset_x': float(ox),
                        'offset_y': float(oy),
                    }
                    replay_state['pan_start'] = None
                else:
                    replay_state['pan_start'] = {
                        'screen_x': float(event.x),
                        'screen_y': float(event.y),
                        'center_x': float(replay_state.get('view_center_x', 0.0) or 0.0),
                        'center_y': float(replay_state.get('view_center_y', 0.0) or 0.0),
                    }
                    replay_state['label_drag'] = None
                canvas.focus_set()
            except Exception:
                replay_state['pan_start'] = None
                replay_state['label_drag'] = None
            return "break"

        def pan_radar_motion(event=None):
            if event is None:
                return "break"

            label_drag = replay_state.get('label_drag')
            if label_drag:
                try:
                    key = label_drag.get('key')
                    dx_pixels = float(event.x) - float(label_drag.get('screen_x', event.x))
                    dy_pixels = float(event.y) - float(label_drag.get('screen_y', event.y))
                    offsets = replay_state.setdefault('label_offsets', {})
                    offsets[key] = (
                        float(label_drag.get('offset_x', 0.0)) + dx_pixels,
                        float(label_drag.get('offset_y', 0.0)) + dy_pixels,
                    )
                    draw_full_scene()
                except Exception:
                    pass
                return "break"

            pan = replay_state.get('pan_start')
            if not pan:
                return "break"
            try:
                scale = radar_screen_scale()
                if not scale or scale <= 0:
                    return "break"
                dx_pixels = float(event.x) - float(pan.get('screen_x', event.x))
                dy_pixels = float(event.y) - float(pan.get('screen_y', event.y))
                # Drag behaves like grabbing the radar view: symbols follow the mouse.
                replay_state['view_center_x'] = float(pan.get('center_x', 0.0)) - (dx_pixels / scale)
                replay_state['view_center_y'] = float(pan.get('center_y', 0.0)) + (dy_pixels / scale)
                draw_full_scene()
            except Exception:
                pass
            return "break"

        def pan_radar_end(_event=None):
            replay_state['pan_start'] = None
            replay_state['label_drag'] = None
            return "break"

        def on_resize(_event=None):
            draw_full_scene()

        def redraw_shortcut_preserve_replay_mode():
            """Redraw after +/- / Shift+/- / Ctrl+/- without changing replay mode.

            Keyboard display shortcuts must not convert Pause/Step into Go, must
            not change the current packet index, and must not change an active
            Go Fwd / Go Back direction. Timers are intentionally left untouched.
            """
            saved_index = replay_state.get('index', 0)
            saved_running = bool(replay_state.get('running'))
            saved_direction = replay_state.get('direction')
            saved_paused_by_alert = bool(replay_state.get('paused_by_alert'))
            saved_alert_active = bool(replay_state.get('alert_active'))
            saved_alert_message = replay_state.get('alert_message', '')
            saved_status = status_var.get()

            replay_state['index'] = saved_index
            draw_full_scene()

            replay_state['index'] = saved_index
            replay_state['running'] = saved_running
            replay_state['direction'] = saved_direction
            replay_state['paused_by_alert'] = saved_paused_by_alert
            replay_state['alert_active'] = saved_alert_active
            replay_state['alert_message'] = saved_alert_message
            status_var.set(saved_status)

            try:
                canvas.focus_set()
            except Exception:
                pass

            return "break"

        def zoom_in(_event=None):
            replay_state['zoom_factor'] = min(50.0, replay_state.get('zoom_factor', 1.0) * 1.25)
            return redraw_shortcut_preserve_replay_mode()

        def zoom_out(_event=None):
            replay_state['zoom_factor'] = max(1.0, replay_state.get('zoom_factor', 1.0) / 1.25)
            return redraw_shortcut_preserve_replay_mode()

        def increase_label_font(_event=None):
            replay_state['label_font_level'] = min(4, int(replay_state.get('label_font_level', 1)) + 1)
            return redraw_shortcut_preserve_replay_mode()

        def decrease_label_font(_event=None):
            replay_state['label_font_level'] = max(1, int(replay_state.get('label_font_level', 1)) - 1)
            return redraw_shortcut_preserve_replay_mode()

        def set_history_depth(depth):
            replay_state['history_depth'] = max(0, min(20, int(depth)))
            replay_state['sector_history'] = {k: v[:20] for k, v in replay_state['sector_history'].items()}
            return redraw_shortcut_preserve_replay_mode()

        def increase_history_depth(_event=None):
            return set_history_depth(int(replay_state.get('history_depth', 0)) + 1)

        def decrease_history_depth(_event=None):
            return set_history_depth(int(replay_state.get('history_depth', 0)) - 1)

        def restart_from_current():
            current_index = replay_state.get('index', 0)
            begin_replay_from_index(current_index)

        def on_close():
            replay_state['running'] = False
            replay_state['direction'] = None
            cancel_timer()
            win.destroy()

        def on_frame_slider(_value=None):
            if replay_state.get('programmatic_frame_update'):
                return
            if replay_state['running']:
                return
            rebuild_replay_state_for_index(find_start_index_by_frame(frame_var.get()))
            update_view()


        def on_frame_release(_event=None):
            begin_replay_from_index(find_start_index_by_frame(frame_var.get()))
            return "break"

        def on_speed_change(_event=None):
            if replay_state['running']:
                replay_state['speed'] = get_speed()

        def on_space(_event=None):
            if replay_state.get('paused_by_alert') and not replay_state['running']:
                replay_state['alert_message'] = ''
                replay_state['alert_active'] = False
                replay_state['paused_by_alert'] = False
                draw_full_scene()

                if replay_state['index'] >= len(replay_state['events']) - 1:
                    status_var.set(status_var.get() + " | Τέλος replay")
                    return "break"

                replay_state['running'] = True
                replay_state['direction'] = 'forward'
                next_index = min(replay_state['index'] + 1, len(replay_state['events']) - 1)
                ensure_replay_chunk_for_index(next_index)
                replay_state['index'] = next_index
                evt = replay_state['events'][replay_state['index']]

                if evt['kind'] == 'north' and replay_state['index'] > replay_state['scan_start_index']:
                    replay_state['scan_start_index'] = replay_state['index']

                update_view()

                if evt['kind'].startswith('alert_'):
                    replay_state['running'] = False
                    replay_state['paused_by_alert'] = True
                    try:
                        canvas.focus_set()
                        win.focus_force()
                    except Exception:
                        pass
                    return "break"


                schedule_next()
                return "break"

            return "break"

        speed_combo.bind("<<ComboboxSelected>>", on_speed_change)
        frame_scale.configure(command=on_frame_slider)
        frame_scale.bind("<ButtonRelease-1>", on_frame_release)
        canvas.bind("<Configure>", on_resize)
        canvas.bind("<ButtonPress-1>", pan_radar_start, add="+")
        canvas.bind("<B1-Motion>", pan_radar_motion, add="+")
        canvas.bind("<ButtonRelease-1>", pan_radar_end, add="+")
        canvas.bind("<Escape>", reset_radar_pan_center)
        canvas.bind("<space>", on_space)
        canvas.bind("<Return>", on_space)
        canvas.bind("<KP_Enter>", on_space)
        for widget in (win, canvas, frame_scale):
            # Arrow shortcuts requested for Replay:
            #   Down  = continuous Go Back
            #   Up    = continuous Go Fwd
            #   Left  = one Step Back
            #   Right = one Step Forward
            widget.bind("<Down>", go_backward_from_current)
            widget.bind("<Up>", go_forward_from_current)
            widget.bind("<Left>", lambda _event=None: step_back())
            widget.bind("<Right>", lambda _event=None: step_forward())
        win.bind("<Escape>", reset_radar_pan_center)
        win.bind("<space>", on_space)
        win.bind("<Return>", on_space)
        win.bind("<KP_Enter>", on_space)
        win.bind("<Key-plus>", zoom_in)
        win.bind("<Key-KP_Add>", zoom_in)
        win.bind("<Key-minus>", zoom_out)
        win.bind("<Key-KP_Subtract>", zoom_out)
        win.bind("<Key-equal>", zoom_in)
        win.bind("<Shift-Key-plus>", increase_label_font)
        win.bind("<Shift-Key-KP_Add>", increase_label_font)
        win.bind("<Shift-Key-minus>", decrease_label_font)
        win.bind("<Shift-Key-KP_Subtract>", decrease_label_font)
        win.bind("<Shift-Key-underscore>", decrease_label_font)
        win.bind("<Control-Key-plus>", increase_history_depth)
        win.bind("<Control-Key-KP_Add>", increase_history_depth)
        win.bind("<Control-Key-minus>", decrease_history_depth)
        win.bind("<Control-Key-KP_Subtract>", decrease_history_depth)
        win.bind("<Control-Key-equal>", increase_history_depth)
        win.bind("<Control-Key-underscore>", decrease_history_depth)
        for digit in range(10):
            win.bind(str(digit), lambda _e, d=digit: set_history_depth(d))
            win.bind(f"<KP_{digit}>", lambda _e, d=digit: set_history_depth(d))
        win.protocol("WM_DELETE_WINDOW", on_close)

        self.center_toplevel_near_screen(win, min_width=960, min_height=620, margin_x=120, margin_y=90, width_ratio=0.62, height_ratio=0.84, max_width_cap=1120, max_height_cap=920, grow_y_up_ratio=0.20)
        try:
            win.after(150, lambda w=win: self.center_toplevel_near_screen(w, min_width=960, min_height=620, margin_x=120, margin_y=90, width_ratio=0.62, height_ratio=0.84, max_width_cap=1120, max_height_cap=920, grow_y_up_ratio=0.20))
        except Exception:
            pass

        draw_full_scene()
        reset_replay()
        try:
            canvas.focus_set()
            win.focus_force()
        except Exception:
            win.focus_set()

    def show_help(self):
        win = tk.Toplevel(self.root)
        win.title("Help - AIRCAT 500 Analyzer")
        win.resizable(True, True)
        try:
            win.transient(self.root)
            win.grab_set()
        except Exception:
            pass

        ww, wh = 1040, 720
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = max((sw - ww) // 2, 0)
        y = max((sh - wh) // 2, 0)
        win.geometry(f"{ww}x{wh}+{x}+{y}")
        win.minsize(900, 560)

        outer = ttk.Frame(win, padding=10)
        outer.pack(fill="both", expand=True)

        txt = scrolledtext.ScrolledText(
            outer,
            wrap="word",
            font=("Consolas", 10),
            padx=12,
            pady=10,
            exportselection=False
        )
        txt.pack(fill="both", expand=True)

        txt.tag_configure("title", font=("Consolas", 16, "bold"), spacing3=10)
        txt.tag_configure("subtitle", font=("Consolas", 10, "italic"), foreground="#404040", spacing3=3)
        txt.tag_configure("toc_title", font=("Consolas", 12, "bold"), spacing1=8, spacing3=4)
        txt.tag_configure("section", font=("Consolas", 13, "bold"), foreground="#003366", spacing1=6, spacing3=3)
        txt.tag_configure("item", font=("Consolas", 10, "bold"), foreground="#202020", spacing1=4)
        txt.tag_configure("body", font=("Consolas", 10), lmargin1=22, lmargin2=22, spacing3=2)
        txt.tag_configure("link", foreground="#005BBB", underline=True)
        txt.tag_configure("backlink", foreground="#606060", underline=True)
        txt.tag_configure("rule", foreground="#909090")

        def go_to_mark(mark_name):
            try:
                txt.config(state="normal")
                txt.see(mark_name)
                txt.mark_set("insert", mark_name)
                txt.focus_set()
            except Exception:
                pass
            return "break"

        def set_cursor_hand(_event=None):
            txt.config(cursor="hand2")

        def set_cursor_text(_event=None):
            txt.config(cursor="xterm")

        txt.insert("end", "AIRCAT 500 Analyzer - Help\n", "title")
        txt.insert("end", "Κάνε κλικ σε έναν τίτλο για να μεταφερθείς στην αντίστοιχη ενότητα.\n", "subtitle")

        txt.mark_set("top", "1.0")
        txt.mark_gravity("top", "left")

        sections = [
            ("sec_report", "Ορισμοί Report", [
                ("Αρχείο", "Το αρχείο pcap / pcapng / csv που αναλύθηκε."),
                ("Filter", "Το φίλτρο φόρτωσης: All packets, UDP packets only, AIRCAT-like only ή Known AIRCAT only."),
                ("Περίοδος valid καταγραφής", "Το διάστημα από το πρώτο valid North έως το τελευταίο valid North. Τα βασικά στατιστικά βασίζονται σε αυτήν την περίοδο."),
                ("Διάρκεια", "Ο συνολικός χρόνος της valid καταγραφής."),
                ("Packets φορτωμένα", "Το συνολικό πλήθος records / packets που διαβάστηκαν με το επιλεγμένο φίλτρο."),
                ("Ignored before first North", "Packets πριν από το πρώτο North. Αγνοούνται γιατί η καταγραφή μπορεί να ξεκινά στη μέση scan."),
                ("Ignored after last valid North / EOF partial cycle", "Packets στο τέλος μετά το τελευταίο valid North ή σε μερικό EOF cycle. Αγνοούνται γιατί η καταγραφή μπορεί να σταματά στη μέση scan."),
            ]),
            ("sec_filters", "Φίλτρα φόρτωσης / ανάλυσης", [
                ("All packets", "Φορτώνει όλα τα records που μπορεί να διαβάσει το πρόγραμμα."),
                ("UDP packets only", "Φορτώνει μόνο UDP packets. Είναι η συνήθης επιλογή για capture από radar stream."),
                ("AIRCAT-like only", "Κρατά payloads που μοιάζουν με AIRCAT 500, ακόμη και αν δεν είναι όλα πλήρως γνωστά στον decoder."),
                ("Known AIRCAT only", "Κρατά μόνο μηνύματα που αναγνωρίζονται ως γνωστοί AIRCAT 500 τύποι."),
            ]),
            ("sec_messages", "Σύνοψη μηνυμάτων", [
                ("AIRCAT-like", "Packets που μοιάζουν με AIRCAT 500 payload."),
                ("Known", "Packets με γνωστό AIRCAT 500 message type."),
                ("Sector 0x0C", "Radar Sector message."),
                ("North 0x19", "North Signal. Σηματοδοτεί την αρχή νέου scan."),
                ("Weather 0x2A", "Weather message."),
                ("Radar Extension 0x0D", "Radar extension message."),
                ("Processor State 0x1C", "Μετριέται στη λίστα Τύποι πριν από τα Unknown types."),
                ("Unknown types", "Μηνύματα που δεν αντιστοιχίζονται στον decoder. Αναλυτικά εμφανίζονται στους Πίνακες σφαλμάτων."),
            ]),
            ("sec_cycles", "Σύνοψη κύκλων North / sectors", [
                ("North examined", "Πόσα North cycles εξετάστηκαν στη valid περίοδο."),
                ("valid 32 sectors", "North cycles με ακριβώς 32 sectors."),
                ("invalid", "North cycles χωρίς πλήρη σωστή ακολουθία 32 sectors."),
                ("Accepted sector sequence OK", "Σωστές μεταβάσεις sector μέσα στους accepted cycles."),
                ("Discontinuities", "Ασυνέχειες στην ακολουθία των accepted sectors."),
            ]),
            ("sec_errors", "Σύνοψη σφαλμάτων", [
                ("Scan missed", "Timing-based έλεγχος. Μετρά μόνο περιπτώσεις North interval με ratio > 1.9, δηλαδή πραγματικά χαμένο scan και όχι απλό jitter. Ο υπολογισμός γίνεται από διαδοχικά πραγματικά North signals, όχι μόνο από valid sector cycles, ώστε ένα sector missing να μη δημιουργεί ψευδές scan missed."),
                ("North missing valid sectors", "Protocol-based έλεγχος. Μετά από North δεν ακολούθησαν 32 σωστά αριθμημένα sectors 00..1F."),
                ("Invalid North cycles", "Scan missed + North missing valid sectors."),
                ("Sector missing συνολικά", "Άθροισμα sectors που λείπουν. Αν λείπουν 03 και 04 στον ίδιο κύκλο, μετράει +2."),
                ("Sector without prev North", "Sectors που εμφανίστηκαν χωρίς σωστό προηγούμενο North."),
                ("Out-of-order sectors", "Sectors σε λάθος σειρά μέσα σε valid cycle."),
                ("Συνολικά σφάλματα", "Ανεξάρτητα συμβάντα: missing sector IDs + Scan missed + protocol-only κύκλοι χωρίς missing IDs. Οι invalid North cycles δεν προστίθενται ξανά."),
                ("Μέση τιμή Ρυθμού σφαλμάτων", "Δείχνει μέση χρονική απόσταση τύπου 1/χρόνο για Scan missed, North missing valid sectors και Invalid North cycles."),
            ]),
            ("sec_tables", "Πίνακες σφαλμάτων", [
                ("Σύνοψη", "Συγκεντρωτικοί αριθμοί σφαλμάτων και diagnostic counters."),
                ("Scan missed", "North timing alerts με ratio > 1.9. Περιέχει Prev #, Prev North, Curr #, Current North, Δt, Ratio και εκτιμώμενα χαμένα scans."),
                ("North jitter", "North timing variation >5% χωρίς πραγματικό scan missed."),
                ("Protocol / sectors", "Protocol alerts με North frame, timestamp, πλήθος sectors και missing sectors."),
                ("Out-of-order", "Out-of-order sector events, όταν υπάρχουν."),
                ("Malformed", "Malformed packets, όταν υπάρχουν."),
                ("Unmapped", "Decoder unmapped elements, όταν υπάρχουν."),
                ("Protocol types unknown/errors", "Unknown protocol type / identifier με count και ποσοστό."),
                ("Unknown prefixes", "Άγνωστα prefixes, πρώτο frame και πλήθος."),
                ("Copy", "Ctrl+C αντιγράφει επιλεγμένες γραμμές. Ctrl+A επιλέγει όλες τις γραμμές του ενεργού πίνακα."),
            ]),
            ("sec_aircat_alerts", "AIRCAT alerts", [
                ("Low quality <95/127", "Low quality κατάσταση. Τα ποσοστά υπολογίζονται ως προς το αντίστοιχο πλήθος decoded target messages, όχι ως προς το total της γραμμής alert."),
                ("Maneuver / Unstable", "Maneuver indication του track."),
                ("Track cancellation", "FB cancellation. Το πρόγραμμα προσπαθεί να το αντιστοιχίσει σε PSR/MSSR από το τελευταίο γνωστό source του ίδιου track #. Αν δεν γίνεται ασφαλής αντιστοίχιση μένει Other."),
                ("SPI", "Special Position Identification σε MSSR/SSR στόχο."),
                ("EMERGENCY", "Emergency indication. Στο Replay / LivePlay εμφανίζεται ολογράφως EMERGENCY."),
                ("Special Codes", "Οι Mode A/3 κωδικοί 7500, 7600, 7601 και 7700 μπαίνουν μαζί στο tab Special Codes."),
                ("Mode validation", "Mode A/C validation γίνεται dynamic. Αν υπάρχει Byte 21 χρησιμοποιούνται οι πλήρεις λεπτομέρειες. Αλλιώς χρησιμοποιείται όπου γίνεται το C bit του transmitted code."),
                ("Optional tabs", "Mode C Byte21, Tracking Window, Smoothing K και Log Sigma μπαίνουν στα τελευταία tabs και εμφανίζονται μόνο με τα διαθέσιμα δεδομένα."),
                ("Wireshark # / Timestamp", "Οι αναλυτικοί πίνακες alerts κρατούν πάντα Wireshark # και timestamp όπου υπάρχουν."),
            ]),
            ("sec_ssr", "SSR / MSSR decoding", [
                ("SSR code word types", "Σύνοψη bytes 13-18: No answer (empty SSR code word), Mode A/3 transponder code και C mode. Οι γραμμές μετά την πρώτη δείχνουν και διαφορά από την προηγούμενη τιμή."),
                ("Mode A/3 transponder code", "Ο Mode A / Mode 3-A κωδικός στόχου."),
                ("Special Mode A/3 Transponder Codes", "Αθροιστικά: 7000 VFR, 7500 unlawful interference / hijack, 7600 radio communication failure, 7601 Radio IFR/VMC failure, 7700 general emergency και Other Mode A/3 codes."),
                ("Log Sigma / Tracking Window / Smoothing K", "Αν δεν μεταδίδονται, το report γράφει ότι δεν μεταδόθηκαν. Αν υπάρχουν, ενεργοποιούνται δυναμικά σε Label Filters / diagnostic tabs."),
            ]),
            ("sec_replay", "Replay", [
                ("Chunked replay", "Το replay δουλεύει αόρατα σε 30λεπτα chunks με warm-up, ώστε τα μεγάλα αρχεία να παίζουν γρήγορα."),
                ("Go Back / Go Fwd", "Κάτω βέλος = Go Back, πάνω βέλος = Go Fwd."),
                ("Step Back / Step Forward", "Αριστερό βέλος = Step Back, δεξί βέλος = Step Forward."),
                ("Pause / Start", "Το replay state δεν αλλάζει όταν ο χρήστης αλλάζει Label Filters ή χρησιμοποιεί zoom/pan."),
                ("Zoom +/-", "Zoom γύρω από το τρέχον κέντρο προβολής."),
                ("Shift +/-", "Αυξομείωση label zoom."),
                ("Ctrl +/-", "Αυξομείωση track history."),
                ("Mouse drag", "Drag σε κενό radar κάνει pan. Drag πάνω σε label μετακινεί το label και εμφανίζει μπλε γραμμή σύνδεσης."),
                ("Esc", "Επαναφέρει κέντρο, labels και connector lines στα default."),
                ("Ctrl + drag σε label", "Κάνει pause και ανοίγει current scan raw data μέχρι το payload του επιλεγμένου στόχου."),
            ]),
            ("sec_liveplay", "LivePlay / Monitor", [
                ("LivePlay / Monitor", "Επιλογή RICI5000 (RS232 SYNC to LAN conversion) ή SYNC2USB (RS232 SYNC to USB conversion). USB: Live Radar Display ή Radar Serial Line Monitoring με CRC/HEX/CLOCK. USB mode χρειάζεται pyserial."),
                ("Smooth drawing", "Το packet processing είναι αποσυνδεδεμένο από το canvas drawing ώστε η οθόνη να ανανεώνεται ομαλά. Τα πραγματικά sector / North προβλήματα μετρώνται από τα δεδομένα της γραμμής. Το LivePlay εμφανίζει ως system alerts μόνο sector missing, scan missed και north jitter. Αν ένας κύκλος έχει sector missing, ο πραγματικός North χρόνος κρατιέται ως reference ώστε ο επόμενος κύκλος να μην μετρηθεί ψευδώς ως scan missed. Το North jitter υπολογίζεται με median των North intervals που έχουν ήδη ληφθεί και ενεργοποιείται μετά από warm-up 10 intervals, ώστε να προσεγγίζει την offline ανάλυση."),
                ("Fast non-AIRCAT reject", "Τα non-AIRCAT UDP packets απορρίπτονται άμεσα από το GUI drawing path. Μπορούν να γραφτούν στο Record μόνο αν το επιτρέπει το φίλτρο."),
                ("Record", "Η καταγραφή γράφει ζωντανά σε CSV μέσω writer thread. Γίνεται flush/fsync ώστε να προστατεύεται ό,τι έχει ήδη γραφτεί σε ξαφνικό κλείσιμο υπολογιστή."),
                ("Record Filters", "Default είναι AIRCAT-like only. Τα φίλτρα καθορίζουν τι γράφεται στο CSV: Radar Sector, North Signal, Radar Extension, Processor State, Weather, Other AIRCAT-like/unknown και non-AIRCAT UDP όταν AIRCAT-like only είναι OFF."),
                ("Record counters", "Στο πάνω αριστερά μέρος του LivePlay εμφανίζονται Recording time, Recorded UDP packets, non-AIRCAT UDP packets και non-AIRCAT pkts ignored/sec."),
                ("Label Filters", "PSR, Weather, Mode A, Mode C, Track cancellation, Velocity Vector, Range, Speed, quality, Detection misses, Track number, TPR # και δυναμικά optional fields όταν υπάρχουν."),
                ("USB Status", "Στη USB οθόνη το κουμπί USB Status εμφανίζει CRC OK/FAIL, framing και missing-sector diagnostics όταν χρειάζεται. Δεν εμφανίζονται τεχνικά counters πάνω στο RADAR."),
                ("LivePlay foreground", "Το LivePlay επανέρχεται στο foreground μετά το άνοιγμα και μετά την επιλογή αρχείου αποθήκευσης."),
            ]),
            ("sec_controls", "Κουμπιά και συντομεύσεις", [
                ("Άνοιγμα αρχείου", "Φορτώνει pcapng / pcap / csv και ξεκινά ανάλυση σε background thread ώστε το GUI να μένει responsive."),
                ("Αποθήκευση report", "Αποθηκεύει το τρέχον report σε txt."),
                ("Φίλτρα", "Ανοίγει φίλτρα φόρτωσης / ανάλυσης."),
                ("Πίνακες σφαλμάτων", "Ανοίγει αναλυτικούς diagnostic πίνακες."),
                ("Ραβδοδιάγραμμα", "Ανοίγει ραβδοδιαγράμματα με zoom peak / zoom out."),
                ("Alerts", "Ανοίγει τους αναλυτικούς πίνακες AIRCAT alerts."),
                ("Replay", "Ανοίγει το replay."),
                ("LivePlay", "Ανοίγει ή κλείνει το live capture window."),
                ("About", "Εμφανίζει έκδοση, πληροφορίες επικοινωνίας και στοιχεία CPU."),
                ("Help", "Ανοίγει αυτό το παράθυρο βοήθειας."),
                ("Ctrl+C / Ctrl+A", "Copy / Select all σε report, help και πίνακες."),
                ("Ctrl + + / Ctrl + - στο report", "Αυξομειώνει τη γραμματοσειρά του report."),
            ]),
        ]
        txt.insert("end", "Index / Πίνακας περιεχομένων\n", "toc_title")
        for mark_name, title, _items in sections:
            link_tag = f"toc_{mark_name}"
            txt.insert("end", f"  • {title}\n", ("link", link_tag))
            txt.tag_bind(link_tag, "<Button-1>", lambda _event=None, m=mark_name: go_to_mark(m))
            txt.tag_bind(link_tag, "<Enter>", set_cursor_hand)
            txt.tag_bind(link_tag, "<Leave>", set_cursor_text)
        txt.insert("end", "\n" + "-" * 72 + "\n", "rule")

        for mark_name, title, items in sections:
            anchor_index = txt.index("end-1c")
            txt.mark_set(mark_name, anchor_index)
            txt.mark_gravity(mark_name, "left")

            txt.insert("end", "\n" + title + "\n", "section")
            back_tag = f"back_{mark_name}"
            txt.insert("end", "↑ Πίνακας περιεχομένων\n", ("backlink", back_tag))
            txt.tag_bind(back_tag, "<Button-1>", lambda _event=None: go_to_mark("top"))
            txt.tag_bind(back_tag, "<Enter>", set_cursor_hand)
            txt.tag_bind(back_tag, "<Leave>", set_cursor_text)
            txt.insert("end", "")

            for item_title, item_body in items:
                txt.insert("end", item_title + "\n", "item")
                txt.insert("end", "  " + item_body + "\n", "body")

        def copy_help_selection(_event=None):
            try:
                selected = txt.get("sel.first", "sel.last")
            except Exception:
                return "break"
            self.root.clipboard_clear()
            self.root.clipboard_append(selected)
            return "break"

        def select_all_help(_event=None):
            txt.config(state="normal")
            txt.tag_add("sel", "1.0", "end-1c")
            txt.mark_set("insert", "1.0")
            txt.see("insert")
            return "break"

        def block_help_editing(event=None):
            # Keep the Help selectable/clickable, but prevent accidental editing.
            if event is not None:
                state = getattr(event, "state", 0)
                keysym = str(getattr(event, "keysym", "")).lower()
                char = getattr(event, "char", "")

                # Allow copy/select-all/navigation shortcuts.
                if state & 0x0004 and (keysym in ("c", "a") or char in ("\x03", "\x01")):
                    return None
                if keysym in (
                    "left", "right", "up", "down", "prior", "next",
                    "home", "end", "shift_l", "shift_r", "control_l", "control_r",
                ):
                    return None

            return "break"

        txt.bind("<Control-c>", copy_help_selection)
        txt.bind("<Control-C>", copy_help_selection)
        txt.bind("<<Copy>>", copy_help_selection)
        txt.bind("<Control-a>", select_all_help)
        txt.bind("<Control-A>", select_all_help)
        txt.bind("<KeyPress>", block_help_editing, add="+")
        txt.bind("<BackSpace>", block_help_editing)
        txt.bind("<Delete>", block_help_editing)

        btns = ttk.Frame(outer)
        btns.pack(fill="x", pady=(8, 0))
        ttk.Button(btns, text="OK", command=win.destroy).pack(side="right")

    def _license_days_remaining(self):
        today = date.today()
        return (LICENSE_EXPIRY_DATE - today).days

    def _is_license_expired(self):
        return FORCE_LICENSE_EXPIRED_FOR_TEST or self._license_days_remaining() < 0

    def _license_status_text(self):
        days_left = self._license_days_remaining()

        if FORCE_LICENSE_EXPIRED_FOR_TEST or days_left < 0:
            return "Ολοκλήρωση δοκιμαστικής λειτουργίας"

        return (
            "License status: OK\n"
            f"License valid until: {LICENSE_EXPIRY_DATE.strftime('%Y-%m-%d')}\n"
            f"Days remaining: {days_left}"
        )

    def _check_license_before_open_file(self):
        if self._is_license_expired():
            self.progress_var.set(0.0)
            self.status_label.config(text="Ολοκλήρωση δοκιμαστικής λειτουργίας")
            messagebox.showerror(
                APP_TITLE,
                "Ολοκλήρωση δοκιμαστικής λειτουργίας"
            )
            return False

        return True

    def show_about(self):
        now_txt = "08_11_26"
        about_lines = [
            "AIRCAT 500 Analyzer",
            f"Version {APP_VERSION} {now_txt}",
            "Info @Αp.Kotopoulis -6974126800-",
            "",
            "Βασικός έλεγχος Radar Raw DATA",
            "Online ή/και με βάση αρχείο καταγραφής",
            "Υποστηρίζονται αρχεία BIN / PCAP / PCAPNG / CSV",
            "",
            f"{_cpu_description()}",
            f"CPU cores detected: {_available_cpu_cores()}",
        ]
        width = max(len(line) for line in about_lines) + 12
        about_text = "\n".join(line.center(width) for line in about_lines)
        messagebox.showinfo("About", about_text)

    def clear_text(self):
        self.stop_live_capture()
        self.text.delete("1.0", "end")
        self.report_text = ""
        self.current_file = None
        self.current_records = None
        self.last_stats = None
        self.filter_mode = tk.StringVar(value="UDP packets only")
        self.progress_var.set(0.0)
        self.status_label.config(text="Έτοιμο.")

    def open_raw_bin_browser(self, path):
        """Main Analyzer BIN entry point (not the USB Monitor's offline CRC-only view)."""
        if not self._check_license_before_open_file():
            return
        old = getattr(self, '_raw_bin_browser', None)
        if old is not None:
            try:
                old.close()
            except Exception:
                pass
        self.current_records = None  # Never replay stale CSV/PCAP records.
        self.current_file = str(path)
        self.last_stats = None
        self.report_text = ''
        self.text.delete('1.0', 'end')
        self.text.insert('end', 'RAW BSC BIN: ' + Path(path).name + '\n'
                         'Σάρωση CRC-16/KERMIT όλου του αρχείου σε εξέλιξη.\n'
                         'Μετά τη σάρωση επέλεξε χρονικό παράθυρο για Analysis / Replay.\n')
        self._raw_bin_browser = RawBscBinBrowser(self, Path(path))

    def open_file(self):
        if not self._check_license_before_open_file():
            return

        if getattr(self, 'file_analysis_running', False):
            messagebox.showinfo(
                "Ανάλυση σε εξέλιξη",
                "Υπάρχει ήδη φόρτωση/ανάλυση αρχείου σε εξέλιξη. Περιμένετε να ολοκληρωθεί."
            )
            return

        path = filedialog.askopenfilename(
            title="Διάλεξε αρχείο",
            filetypes=[
                ("AIRCAT captures", "*.bin *.pcapng *.pcap *.csv"),
                ("RAW BSC USB BIN", "*.bin"),
                ("Capture / CSV", "*.pcapng *.pcap *.csv"),
                ("PCAPNG", "*.pcapng"),
                ("PCAP", "*.pcap"),
                ("CSV", "*.csv"),
                ("Όλα τα αρχεία", "*.*"),
            ]
        )
        if not path:
            return

        if Path(path).suffix.lower() == '.bin':
            self.open_raw_bin_browser(path)
            return

        self.text.delete("1.0", "end")
        self.text.insert("end", f"Φόρτωση αρχείου: {os.path.basename(path)}\n")
        self.progress_var.set(0.0)
        self.status_label.config(text="0.0% - Εμφάνιση μπάρας φόρτωσης...")
        self.root.update_idletasks()

        self.root.after(10, lambda p=path: self._load_selected_file(p))

    def _load_selected_file(self, path):
        try:
            selected_mode = self.filter_mode.get()
        except Exception:
            selected_mode = "UDP packets only"

        self.set_progress(0.0, "Έναρξη φόρτωσης/ανάλυσης σε background thread...")
        self._start_file_analysis_worker(path, selected_mode)

    def save_report(self):
        if not self.report_text.strip():
            messagebox.showinfo("Πληροφορία", "Δεν υπάρχει report για αποθήκευση.")
            return

        default_name = "aircat_report.txt"
        if self.current_file:
            base = os.path.splitext(os.path.basename(self.current_file))[0]
            default_name = f"{base}_report.txt"

        path = filedialog.asksaveasfilename(
            title="Αποθήκευση report",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text files", "*.txt"), ("Όλα τα αρχεία", "*.*")]
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.report_text)
            messagebox.showinfo("Έτοιμο", f"Το report αποθηκεύτηκε:\n{path}")
        except Exception as e:
            messagebox.showerror("Σφάλμα", str(e))


def _enable_windows_sharp_dpi():
    """Avoid Windows bitmap-stretching of Tk at 125%/150% display scaling.

    Must be called BEFORE tk.Tk() is constructed. If another host already set
    process DPI awareness, the OS refuses changes; keep running normally.
    """
    if os.name != 'nt':
        return False
    try:
        import ctypes
        user32 = ctypes.windll.user32
        try:
            # Windows 10+ Per Monitor V2 (-4).  Signed handle is important.
            user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
            user32.SetProcessDpiAwarenessContext.restype = ctypes.c_bool
            if user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
                return True
        except (AttributeError, OSError):
            pass
        try:
            # Win 8.1 fallback: system DPI aware.
            return ctypes.windll.shcore.SetProcessDpiAwareness(1) == 0
        except (AttributeError, OSError):
            pass
        try:
            return bool(user32.SetProcessDPIAware())
        except (AttributeError, OSError):
            return False
    except Exception:
        return False


if __name__ == "__main__":
    try:
        multiprocessing.freeze_support()
    except Exception:
        pass
    _enable_windows_sharp_dpi()
    root = tk.Tk()
    app = AircatStatsApp(root)
    root.mainloop()