import angr,claripy
import copy
import pyvex
import time
#
import deepdiff
#
from invert import list2stmtlist
#
#创建实例1
project=angr.Project("./c",auto_load_libs=False)
#创建实例2
file=open('./IR1.txt')
IRSB_list=file.read().split('\n')
file.close()
irsb_old=project.factory.block(addr=0x4011e9).vex
result=list2stmtlist(IRSB_list,irsb_old)

for i in result.statements:
    print(i)

diff=deepdiff.DeepDiff(irsb_old,result)