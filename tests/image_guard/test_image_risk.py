from pathlib import Path
import sys
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).parent.parent.parent))
from gigang.engine.correlation import CorrelationEngine
from gigang.engine.policy import load_policy
from gigang.schemas.event import EventAction

engine=CorrelationEngine.__new__(CorrelationEngine)
engine.store=SimpleNamespace(get_active_risk=lambda user:None)
engine.policy=load_policy()
changes=[];incidents=[]
engine._apply_state_transition=lambda *args:changes.append(args)
engine._record_matched_attempt=lambda *args:incidents.append(args)
def event(outcome):
    return SimpleNamespace(action=EventAction.FILE_UPLOAD_ATTEMPT,actor=SimpleNamespace(user_id='image_test_user',src_ip='127.0.0.1'),
        target=SimpleNamespace(domain='chatgpt.com'),payload=SimpleNamespace(extra={'image_guard':{'outcome':outcome},
            'match_status':'matched' if outcome=='blocked_match' else 'not_checked',
            'match':{'source_domain':'desktop-oli.tail2bbbea.ts.net','source_path':'/db'}}))
for outcome in ('held_error','no_match'):
    engine.update_user_risk(event(outcome))
assert not changes and not incidents
engine.update_user_risk(event('blocked_match'))
assert changes[0][2]=='HIGH'
assert len(incidents)==1
assert any('차단' in reason for reason in incidents[0][2])
print('PASS: held/no-match leave risk unchanged; matched image records a blocked HIGH attempt.')
