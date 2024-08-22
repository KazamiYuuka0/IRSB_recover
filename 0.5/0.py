#!/usr/bin/env python


'''
ais3_crackme has been developed by Tyler Nighswander (tylerni7) for ais3.

It is an easy crackme challenge. It checks the command line argument.
'''

import angr
import claripy



project = angr.Project("./ais3_crackme", auto_load_libs=False)
argv1 = claripy.BVS("argv1",100*8)
initial_state = project.factory.entry_state(args=["./crackme1",argv1])
sm = project.factory.simulation_manager(initial_state)
sm.explore(find=0x400602)
found = sm.found[0]
solution = found.solver.eval(argv1, cast_to=bytes)
print(repr(solution))
solution = solution[:solution.find(b"\x00")]
print(solution)

