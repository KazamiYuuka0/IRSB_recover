
import angr,claripy
import copy
import pyvex
import time
#
from invert import list2stmtlist
#
#计时器存储区(addr,time_used)
block=[]#for process
block_track=[]
#创建实例1
project=angr.Project("./a3",auto_load_libs=False)
#创建实例2
file=open('./IR1.txt')
IRSB_list=file.read().split('\n')
file.close()
irsb_old=project.factory.block(addr=0x400531).vex
result=list2stmtlist(IRSB_list,irsb_old)
#
#HOOK声明区域
#process
old_process=copy.deepcopy(angr.engines.SuccessorsMixin.process)
def hook_process(self, state, *args, **kwargs):#处理一个block
    #print('\n<process>',state)
    #start=time.time()
    r=old_process(self, state, *args, **kwargs)
    #end=time.time()
    #time_used=round((end-start)*1000,2)
    #addr=hex(state._ip.args[0])
    #global block
    #block.append((addr,time_used))
    #print('</process>',time_used,'ms')
    return r
############################syscall
old_process_successors_syscall=copy.deepcopy(angr.engines.SimEngineSyscall.process_successors)
def hook_process_successors_syscall(self, successors, **kwargs):
    #print('syscall')
    r=old_process_successors_syscall(self, successors, **kwargs)
    return r

############################unicorn
old_process_successors_unicorn=copy.deepcopy(angr.engines.SimEngineUnicorn.process_successors)
def hook_process_successors_unicorn(self, successors, **kwargs):
    #print('unicorn')
    r=old_process_successors_unicorn(self, successors, **kwargs)
    return r
old__execute_symbolic_instrs=copy.deepcopy(angr.engines.SimEngineUnicorn._execute_symbolic_instrs)
def hook__execute_symbolic_instrs(self, syscall_data):
    #print('<_execute_symbolic_instrs>:',self.state.os_name)
    #print('===>',self.state.unicorn._get_details_of_blocks_with_symbolic_vex_stmts())
    #for i in self.state.unicorn._get_details_of_blocks_with_symbolic_vex_stmts():
    #    print('======>',i)
    r=old__execute_symbolic_instrs(self, syscall_data)
    return r
old__execute_block_instrs_in_vex=copy.deepcopy(angr.engines.SimEngineUnicorn._execute_block_instrs_in_vex)
def hook__execute_block_instrs_in_vex(self, block_details):
    #print('<_execute_block_instrs_in_vex>')
    r=old__execute_block_instrs_in_vex(self, block_details)
    return r
############################heavy
old_process_successors_heavy=copy.deepcopy(angr.engines.HeavyVEXMixin.process_successors)
def hook_process_successors_heavy(self, successors, **kwargs):
    #print('heavy')
    r=old_process_successors_heavy(self, successors, **kwargs)
    return r
############################faliure
old_process_successors_failure=copy.deepcopy(angr.engines.SimEngineFailure.process_successors)
def hook_process_successors_failure(self, successors, **kwargs):
    #print('failure')
    r=old_process_successors_failure(self, successors, **kwargs)
    return r
############################hooks
old_process_successors_hooks=copy.deepcopy(angr.engines.HooksMixin.process_successors)
def hook_process_successors_hooks(self, successors, **kwargs):
    #print('hooks')
    r=old_process_successors_hooks(self, successors, **kwargs)
    return r
############################track
old_process_successors_track=copy.deepcopy(angr.engines.TrackActionsMixin.process_successors)
def hook_process_successors_track(self, successors, **kwargs):
    #print("=====================>",successors,kwargs)#说明irsb不传递
    #print('track')
    r=old_process_successors_track(self, successors, **kwargs)
    return r
    #its from heavy,but used here
old_handle_vex_block=copy.deepcopy(angr.engines.HeavyVEXMixin.handle_vex_block)
def hook_handle_vex_block(self, irsb):
    #print('<handle_vex_block>:',hex(irsb.addr))#说明主要由heavy处理
    global result
    global block_track
    if irsb.addr==0x400531:
        start2=time.time()
        #
        #r=old_handle_vex_block(self, irsb)
        r=old_handle_vex_block(self, result)
        #
        end2=time.time()
        time_used=round((end2-start2)*1000,2)
        addr=hex(irsb.addr)
        block_track.append((addr,time_used))
        #print(addr,time_used,'ms')
    else:
        r=old_handle_vex_block(self, irsb)
    return r
old__handle_vex_stmt=copy.deepcopy(angr.engines.HeavyVEXMixin._handle_vex_stmt)
def hook__handle_vex_stmt(self, stmt):
    try:
        r=old__handle_vex_stmt(self, stmt)
    except Exception as e:
        print('<_handle_vex_stmt>',stmt)
        print(f"An error occurred: {e}")
    return r
old__handle_vex_expr=copy.deepcopy(angr.engines.HeavyVEXMixin._handle_vex_expr)
def hook__handle_vex_expr(self, expr):
    try:
        r=old__handle_vex_expr(self, expr)
    except Exception as e:
        print('<_handle_vex_expr>',expr)
        print(f"An error occurred: {e}")
    return r
############################soot
old_process_successors_soot=copy.deepcopy(angr.engines.SootMixin.process_successors)
def hook_process_successors_soot(self, successors, **kwargs):
    #print('soot')
    r=old_process_successors_soot(self, successors, **kwargs)
    return r
#


#HOOK填充区域
angr.engines.SuccessorsMixin.process=hook_process
angr.engines.SimEngineSyscall.process_successors=hook_process_successors_syscall
angr.engines.SimEngineUnicorn.process_successors=hook_process_successors_unicorn
angr.engines.HeavyVEXMixin.process_successors=hook_process_successors_heavy
angr.engines.SimEngineFailure.process_successors=hook_process_successors_failure
angr.engines.HooksMixin.process_successors=hook_process_successors_hooks
angr.engines.TrackActionsMixin.process_successors=hook_process_successors_track
angr.engines.SootMixin.process_successors=hook_process_successors_soot

#angr.engines.SimEngineUnicorn._execute_symbolic_instrs=hook__execute_symbolic_instrs
#angr.engines.SimEngineUnicorn._execute_block_instrs_in_vex=hook__execute_block_instrs_in_vex

angr.engines.HeavyVEXMixin.handle_vex_block=hook_handle_vex_block
angr.engines.HeavyVEXMixin._handle_vex_stmt=hook__handle_vex_stmt
angr.engines.HeavyVEXMixin._handle_vex_expr=hook__handle_vex_expr
#执行
#state=project.factory.entry_state()#
#simgr=project.factory.simgr(state)
#simgr.explore(find=0x4007e4)
#simgr.explore(find=0x40139e,avoid=0x401399)
argv1 = claripy.BVS("argv1",100*8)
initial_state = project.factory.entry_state(args=["./crackme1",argv1])
'''
simgr = project.factory.simulation_manager(initial_state)
simgr.explore(find=0x400602)


block_track.sort(key=lambda x: x[1], reverse=True)#按时间排序，同addr的首个用时最长

print('<analyzed>')
for i in range(len(block_track)):
    if block_track[i]==(-1,-1):#快速识别
        continue
    for j in range(i+1,len(block_track)):#j一定在i之后
        if block_track[j][0]==block_track[i][0]:#出现重复addr，因为已排序，所以新的block一定更快
            block_track[j]=(-1,-1)#清除
block_track.sort(key=lambda x: x[1], reverse=True)#把被清除的排在最后
for i in range(len(block_track)-1,-1,-1):#从后往前
    if block_track[i]==(-1,-1):
        block_track.pop()
for i in block_track:
    print(i)
'''
def analyze():#输出一个用时
    global block_track
    block_track=[]
    
    simgr = project.factory.simulation_manager(initial_state)
    simgr.explore(find=0x400602)
    
    for i in range(len(block_track)):
        if block_track[i]==(-1,-1):#快速识别
            continue
        for j in range(i+1,len(block_track)):#j一定在i之后
            if block_track[j][0]==block_track[i][0]:#出现重复addr，因为已排序，所以新的block一定更快
                block_track[j]=(-1,-1)#清除
    block_track.sort(key=lambda x: x[1], reverse=True)#把被清除的排在最后
    for i in range(len(block_track)-1,-1,-1):#从后往前
        if block_track[i]==(-1,-1):
            block_track.pop()
    #for i in block_track:
    #    print(i[1])
    return block_track[0][1]


for i in range(100):#100次，每10次取平均算一次
    r=0
    for j in range(10):
        t=analyze()
        r+=t
    r=r/10
    print(r)
    
        
    