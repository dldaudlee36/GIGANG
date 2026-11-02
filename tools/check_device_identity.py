"""Print the installed Agent identity without starting collection or changing grants."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'guard' / 'agent'))
from site_access import device_id, identity_file

if __name__ == '__main__':
    print('Identity file:', identity_file())
    print('Device ID:', device_id())
    print('Compare this Device ID across PCs: different PCs must have different values.')
    print('Run again on the same PC: the value must stay the same.')
