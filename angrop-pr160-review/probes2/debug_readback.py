"""
V2 review probe: debug the readback (state selection + endness convention).
"""
import os, logging as _logging
import angr, angrop  # noqa
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for name in ("angrop", "angr"):
    _logging.getLogger(name).setLevel(_logging.ERROR)
from angr import claripy

p = angr.Project("bins/vuln_client3", auto_load_libs=False)
s = p.factory.blank_state(add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
s.memory.map_region(0x50000000, 0x2000, 'rwx')
s.memory.store(0x50000f00, claripy.BVV(0x41414141, 64), endness=p.arch.memory_endness)
v1 = s.memory.load(0x50000f00, 8).concrete_value
v2 = s.memory.load(0x50000f00, 8, endness=p.arch.memory_endness).concrete_value
v3 = s.memory.load(0x50000f00, 8, endness='big').concrete_value
print("[*] round-trip BVV(0x41414141,64): default=%#x explicit_le=%#x big=%#x" % (v1, v2, v3))

# default load endness on arch
import inspect
print("[*] load signature:", inspect.signature(s.memory.load))
