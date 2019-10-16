from ..i386 import *

import importlib
import os
import sys

sys.path.append(os.path.dirname(__file__)) 

hookdlls = {}
hooks = None
hooks = set(vars().keys())

# load default hook
from .tool.basehook import *

# remove default private vars 
hooks = [_x for _x in hooks if not _x.startswith('_') ]

#!!!!!!!!!!!!!!!!!!!!! DO NOT FORGET THIS PART!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# setup special name functions hooks 
from .tool.basehook import __p__fmode
from .tool.basehook import __getmainargs
from .tool.basehook import __set_app_type
from .tool.basehook import __p__commode
from .tool.basehook import __setusermatherr
from .tool.basehook import _controlfp
from .tool.basehook import _initterm
from .tool.basehook import _initterm_e
from .tool.basehook import _isctype
from .tool.basehook import _ismbblead

# load defined hooks
for f in os.listdir(os.path.dirname(__file__)):
    if not f.endswith('.py') or f == '__init__.py':
        continue
    name = f[:-3]
    m = importlib.import_module('.'.join(['unitracer', 'lib', 'windows', 'hooks', name]))
    hookdlls[name.upper()] = m

    for n in getattr(m, 'hooks'):
        mn = n # module name
        if n not in vars().keys():
            # check function for Unicode or ANSI Strings
            if mn + 'A' in vars().keys() or mn + 'W' in vars().keys():
                mn += 'A' # force convert to ANSI Strings
            else:
                continue
        globals()[mn].hook = getattr(m, n)


hooks = set(vars().keys()).difference(hooks)
