import lldb
def observe(frame,bp,dict):
 caller=frame.GetThread().GetFrameAtIndex(1)
 if caller.GetModule().GetFileSpec().GetFilename()=='efyca_p11_v1.dylib':
  error=lldb.SBError()
  address=frame.FindRegister('rdi').GetValueAsUnsigned()
  value=frame.GetThread().GetProcess().ReadCStringFromMemory(address,256,error)
  print('EFY_CALL '+frame.GetFunctionName()+' argument='+repr(value)+' caller='+hex(caller.GetPC()))
 return False
def __lldb_init_module(debugger,dict):
 target=debugger.GetSelectedTarget()
 for name in ['popen','stat','SCardEstablishContext','SCardConnect','SCardGetStatusChange']:
  bp=target.BreakpointCreateByName(name);bp.SetScriptCallbackFunction('efy_lldb_observe.observe')
