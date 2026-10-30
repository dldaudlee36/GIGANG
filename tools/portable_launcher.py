"""Windows portable launcher. Config stays beside the EXE; app sources stay editable."""
import argparse
import json
import multiprocessing
import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import psutil

FROZEN = getattr(sys,'frozen',False)
HOME = Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parents[1]
APP = HOME/'app_files' if (HOME/'app_files').is_dir() else HOME
RUNTIME = HOME/'runtime'
RUNTIME.mkdir(exist_ok=True)
CA_RUNTIME_PEM='-----BEGIN TRUSTED CERTIFICATE-----\nMIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG\nEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNo\nbm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g\nRzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJ\nTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9s\nb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw\ndjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0\nWXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xyS\nfvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuB\nzhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggq\nhkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWB\nCUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD\n+JbNR6iC8hZVdyR+EhCVBCyjMAigBgYEVR0lAA==\n-----END TRUSTED CERTIFICATE-----\n'
# This bundled Python runtime requires its public CA file when creating TLS contexts.
# Carry it inside the launcher so replacing only the EXE also repairs older bundles.
if FROZEN:
    ca_path=Path(getattr(sys,'_MEIPASS',str(HOME/'_internal')))/'codex-rejected-cas.pem'
    if not ca_path.exists():
        try:ca_path.write_text(CA_RUNTIME_PEM,encoding='ascii')
        except OSError:pass
os.environ['GIGANG_APP_ROOT']=str(APP)
for folder in [APP,APP/'guard'/'agent',APP/'tools']:
    sys.path.insert(0,str(folder))
from dotenv import load_dotenv
load_dotenv(HOME/'.env',override=False)
load_dotenv(APP/'.env',override=False)


def listening(port):
    with socket.socket() as s:
        s.settimeout(.3)
        return s.connect_ex(('127.0.0.1',port))==0


def redirect_log(role):
    f=open(RUNTIME/(role+'.log'),'a',encoding='utf-8',buffering=1)
    sys.stdout=f;sys.stderr=f
    return f


def children():
    try:return json.loads((RUNTIME/'processes.json').read_text(encoding='utf-8'))
    except (OSError,ValueError):return {}


def own_process(row):
    try:
        p=psutil.Process(row['pid'])
        if abs(p.create_time()-row['created'])>.1:return None
        if os.path.normcase(p.exe())!=os.path.normcase(str(Path(sys.executable).resolve())):return None
        return p
    except (psutil.Error,KeyError):return None


def mode(value=None):
    path=RUNTIME/'mode.json'
    if value:
        temp=path.with_suffix('.tmp');temp.write_text(json.dumps({'mode':value}),encoding='utf-8');os.replace(temp,path)
    try:return json.loads(path.read_text(encoding='utf-8')).get('mode','running')
    except (OSError,ValueError):return 'running'


def start_role(role):
    records=children()
    if role in records and own_process(records[role]):return
    port={'bridge':8766,'agent':8765,'dashboard':8501}[role]
    if listening(port):raise RuntimeError(f'{port} 포트를 다른 프로그램이 사용 중입니다. 기존 GIGANG 실행을 먼저 종료하세요.')
    cmd=[sys.executable] if FROZEN else [sys.executable,str(Path(__file__).resolve())]
    p=subprocess.Popen(cmd+['--role',role],cwd=HOME,stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    records[role]={'pid':p.pid,'created':psutil.Process(p.pid).create_time()}
    (RUNTIME/'processes.json').write_text(json.dumps(records),encoding='utf-8')


def service_role(process):
    """Recognize this application's services, including another extracted copy."""
    try:
        exe=Path(process.exe()).resolve()
        if exe.name.lower()!='gigang.exe':return None
        args=process.cmdline()
        if '--role' not in args:return None
        index=args.index('--role')
        role=args[index+1] if index+1<len(args) else None
        if role not in ('agent','dashboard','bridge','api-only'):return None
        if not (exe.parent/'app_files'/'gigang').is_dir():return None
        return role
    except (psutil.Error,OSError):return None


def stop_roles():
    mode('stopped')
    targets={}
    roots={HOME}
    for process in psutil.process_iter():
        if service_role(process):
            targets[process.pid]=process
            try:roots.add(Path(process.exe()).resolve().parent)
            except psutil.Error:pass
    # Do not depend only on processes.json: multiple launcher windows/copies can have stale records.
    for process in list(targets.values()):
        try:
            for child in process.children(recursive=True):targets[child.pid]=child
        except psutil.Error:pass
    for folder in roots:
        try:
            runtime=folder/'runtime';runtime.mkdir(exist_ok=True)
            (runtime/'mode.json').write_text('{"mode":"stopped"}',encoding='utf-8')
        except OSError:pass
    refused=[]
    for process in targets.values():
        try:process.terminate()
        except psutil.NoSuchProcess:pass
        except psutil.AccessDenied:refused.append(process.pid)
    _,alive=psutil.wait_procs(list(targets.values()),timeout=3)
    for process in alive:
        try:process.kill()
        except psutil.NoSuchProcess:pass
        except psutil.AccessDenied:refused.append(process.pid)
    if alive:psutil.wait_procs(alive,timeout=2)
    remaining=[process.pid for process in psutil.process_iter() if service_role(process)]
    for folder in roots:
        try:
            state=folder/'runtime'/'processes.json'
            # Keep inaccessible surviving services discoverable on the next stop attempt.
            rows=json.loads(state.read_text(encoding='utf-8')) if state.exists() else {}
            rows={k:v for k,v in rows.items() if v.get('pid') in remaining}
            state.write_text(json.dumps(rows),encoding='utf-8')
        except (OSError,ValueError):pass
    if remaining:
        raise RuntimeError('아직 종료되지 않은 GIGANG 서버가 있습니다. 관리자 권한으로 실행 후 전체 중지를 눌러주세요.')
    hosts_note=''
    path=Path(os.environ.get('WINDIR','C:/Windows'))/'System32/drivers/etc/hosts'
    try:
        from stop import strip_managed
        original=path.read_bytes();cleaned=strip_managed(original)
        if cleaned!=original:path.write_bytes(cleaned)
    except (OSError,ValueError):
        hosts_note=' hosts 차단 해제는 관리자 권한이 필요할 수 있습니다.'
    occupied=[str(port) for port in (8501,8765,8766) if listening(port)]
    if occupied:
        return 'GIGANG 서버 종료 완료. 다른 프로그램이 사용하는 포트: '+', '.join(occupied)+hosts_note
    return '센서·관제·상태 서버 전체 종료 완료.'+hosts_note


def bridge():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path!='/mode':self.send_error(404);return
            body=json.dumps({'service':'GIGANGLifecycle','mode':mode()}).encode()
            self.send_response(200);self.send_header('Content-Type','application/json')
            self.send_header('Access-Control-Allow-Origin','*');self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    ThreadingHTTPServer(('127.0.0.1',8766),Handler).serve_forever()


def self_test(output):
    import importlib
    for name in ['streamlit','streamlit.web.cli','pandas','pydantic','requests','google.genai','PIL','gigang.engine.correlation','agent']:
        importlib.import_module(name)
    from gigang.engine import policy
    p=policy.load_policy();p['users']={'audit':'CS'}
    result=policy.judge_portal('COPY_ATTEMPT','audit',{'inspectable':True,'pattern_hits':{'rrn_high':3}},p)
    assert result.score==77
    assert (APP/'guard/agent/image_ocr.ps1').is_file()
    report={'status':'ok','source_score':result.score,'app_files':APP.is_dir(),
            'configured_keys':[k for k in ['GEMINI_API_KEY','RAILWAY_API_KEY','DB_API_KEY'] if os.getenv(k)]}
    Path(output).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')


def gui():
    import tkinter as tk
    from tkinter import messagebox
    root=tk.Tk();root.title('GIGANG · 회사 자료 보안 관제 · 중지 수정판');root.geometry('560x430');root.resizable(False,False)
    label=tk.Label(root,text='GIGANG 실행',font=('맑은 고딕',22,'bold'));label.pack(pady=(22,10))
    tk.Label(root,text='1. Chrome 확장 설치  →  2. 전체 시작',font=('맑은 고딕',11)).pack(pady=5)
    status=tk.StringVar(value='대기 중 · 키 설정은 같은 폴더의 .env 사용')
    def action(roles):
        try:
            mode('running')
            for role in roles:start_role(role)
            status.set('실행 요청 완료 · 상태 확인 버튼으로 확인하세요.')
            if 'dashboard' in roles:root.after(3500,lambda:webbrowser.open('http://127.0.0.1:8501'))
        except Exception as e:messagebox.showerror('실행 확인',str(e))
    def stop_all():
        try:status.set(stop_roles())
        except Exception as e:messagebox.showerror('중지 확인',str(e))
    def check():status.set(' / '.join(f'{name}: '+('켜짐' if listening(port) else '꺼짐') for name,port in [('센서',8765),('관제',8501)]))
    for text,cmd in [
        ('전체 시작',lambda:action(['bridge','agent','dashboard'])),
        ('직원 PC 센서만 시작',lambda:action(['bridge','agent'])),
        ('관리자 대시보드만 시작',lambda:action(['dashboard'])),
        ('전체 중지',stop_all),
        ('상태 확인',check),
        ('설치 안내 열기',lambda:os.startfile(str(HOME/'먼저읽기.txt'))),
        ('로그 폴더 열기',lambda:os.startfile(str(RUNTIME)))]:
        tk.Button(root,text=text,command=cmd,font=('맑은 고딕',10),width=42).pack(pady=3)
    tk.Label(root,textvariable=status,wraplength=520,font=('맑은 고딕',9)).pack(pady=10)
    root.mainloop()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--role',default='gui')
    parser.add_argument('--self-test-output');parser.add_argument('--port',type=int)
    args=parser.parse_args()
    if args.self_test_output:self_test(args.self_test_output);return
    if args.role=='gui':gui();return
    log=redirect_log(args.role)
    try:
        if args.role=='bridge':bridge()
        elif args.role in ('agent','api-only'):
            if args.port:os.environ['GIGANG_EXTENSION_PORT']=str(args.port)
            if args.role=='api-only':
                import agent;agent.start_server()
            else:runpy.run_path(str(APP/'guard/agent/agent.py'),run_name='__main__')
        elif args.role=='dashboard':
            os.chdir(APP)
            import streamlit.web.cli as cli
            sys.argv=['streamlit','run',str(APP/'app.py'),'--server.address=127.0.0.1',
                '--server.port='+str(args.port or 8501),'--server.headless=true',
                '--global.developmentMode=false','--browser.gatherUsageStats=false','--server.fileWatcherType=none']
            cli.main()
        elif args.role=='stop':stop_roles()
        else:raise RuntimeError('Unknown role')
    except Exception:
        import traceback;traceback.print_exc();raise

if __name__=='__main__':
    multiprocessing.freeze_support()
    main()
