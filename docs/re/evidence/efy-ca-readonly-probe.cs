// EFY-CA research probe: no C_Login, C_Sign, key generation or PIN API.
// Reads PC/SC state (without SCardConnect/SCardTransmit), module and slot metadata.
using System;
using System.Text;
using System.Runtime.InteropServices;
class EfyReadOnlyProbe {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadLibraryW(string p);
 [DllImport("kernel32.dll",CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr h,string n);
 [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr h);
 [DllImport("winscard.dll")] static extern uint SCardEstablishContext(uint s,IntPtr a,IntPtr b,out IntPtr c);
 [DllImport("winscard.dll")] static extern uint SCardReleaseContext(IntPtr c);
 [DllImport("winscard.dll",CharSet=CharSet.Unicode)] static extern uint SCardListReadersW(IntPtr c,IntPtr g,IntPtr names,ref uint n);
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct ReaderState {
  [MarshalAs(UnmanagedType.LPWStr)] public string name; public IntPtr data; public uint current; public uint state; public uint atrLen;
  [MarshalAs(UnmanagedType.ByValArray,SizeConst=36)] public byte[] atr;
 }
 [DllImport("winscard.dll",CharSet=CharSet.Unicode)] static extern uint SCardGetStatusChangeW(IntPtr c,uint timeout,[In,Out] ReaderState[] states,uint count);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate uint Init(IntPtr p);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate uint GetInfo(IntPtr p);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate uint Slots(byte present,IntPtr p,ref uint n);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate uint SlotInfo(uint id,IntPtr p);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate uint Mechs(uint id,IntPtr p,ref uint n);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate uint MechInfo(uint id,uint mech,IntPtr p);
 static T Fn<T>(IntPtr h,string n) where T:class {IntPtr p=GetProcAddress(h,n);if(p==IntPtr.Zero)throw new Exception("missing "+n);return Marshal.GetDelegateForFunctionPointer(p,typeof(T)) as T;}
 static string S(IntPtr p,int off,int len){byte[] b=new byte[len];Marshal.Copy(IntPtr.Add(p,off),b,0,len);return Encoding.ASCII.GetString(b).Trim(' ','\0');}
 static void Readers(){
  IntPtr c;uint rv=SCardEstablishContext(0,IntPtr.Zero,IntPtr.Zero,out c);Console.WriteLine("PCSC.context=0x{0:X8}",rv);if(rv!=0)return;
  try{uint n=0;rv=SCardListReadersW(c,IntPtr.Zero,IntPtr.Zero,ref n);Console.WriteLine("PCSC.list=0x{0:X8}; chars={1}",rv,n);if(rv!=0||n>32768)return;
   IntPtr names=Marshal.AllocHGlobal((int)n*2);try{rv=SCardListReadersW(c,IntPtr.Zero,names,ref n);if(rv!=0)return;string all=Marshal.PtrToStringUni(names,(int)n);
    foreach(string name in all.Split(new char[]{'\0'},StringSplitOptions.RemoveEmptyEntries)){
     ReaderState[] st={new ReaderState{name=name,atr=new byte[36]}};rv=SCardGetStatusChangeW(c,0,st,1);
     Console.WriteLine("PCSC.reader={0}; status=0x{1:X8}; state=0x{2:X8}; ATR={3}",name,rv,st[0].state,BitConverter.ToString(st[0].atr,0,(int)Math.Min(st[0].atrLen,36)).Replace("-",""));
    }
   }finally{Marshal.FreeHGlobal(names);}
  }finally{SCardReleaseContext(c);}
 }
 static void Module(string path){
  Console.WriteLine("Module="+path);IntPtr h=LoadLibraryW(path);if(h==IntPtr.Zero){Console.WriteLine("LoadLibrary.error="+Marshal.GetLastWin32Error());return;}
  bool initialized=false;try{
   uint rv=Fn<Init>(h,"C_Initialize")(IntPtr.Zero);Console.WriteLine("C_Initialize=0x{0:X8}",rv);if(rv!=0)return;initialized=true;
   IntPtr inf=Marshal.AllocHGlobal(256);try{for(int z=0;z<256;z++)Marshal.WriteByte(inf,z,0);rv=Fn<GetInfo>(h,"C_GetInfo")(inf);byte[] rawInfo=new byte[80];Marshal.Copy(inf,rawInfo,0,80);Console.WriteLine("C_GetInfo.raw80="+BitConverter.ToString(rawInfo).Replace("-",""));Console.WriteLine("C_GetInfo=0x{0:X8}",rv);if(rv==0)Console.WriteLine("Cryptoki={0}.{1}; Manufacturer={2}; Description={3}; Library={4}.{5}",Marshal.ReadByte(inf,0),Marshal.ReadByte(inf,1),S(inf,2,32),S(inf,38,32),Marshal.ReadByte(inf,70),Marshal.ReadByte(inf,71));}finally{Marshal.FreeHGlobal(inf);}
   var slots=Fn<Slots>(h,"C_GetSlotList");foreach(byte present in new byte[]{0,1}){
    uint n=0;rv=slots(present,IntPtr.Zero,ref n);Console.WriteLine("C_GetSlotList.present={0}; rv=0x{1:X8}; count={2}",present,rv,n);if(rv!=0||n==0||n>64)continue;
    IntPtr ids=Marshal.AllocHGlobal((int)n*4);try{rv=slots(present,ids,ref n);if(rv!=0||n>64)continue;for(int i=0;i<n;i++){
     uint id=unchecked((uint)Marshal.ReadInt32(ids,i*4));IntPtr b=Marshal.AllocHGlobal(256);try{
      rv=Fn<SlotInfo>(h,"C_GetSlotInfo")(id,b);Console.WriteLine("Slot={0}; info=0x{1:X8}; description={2}",id,rv,rv==0?S(b,0,64):"");if(present==0)continue;
      rv=Fn<SlotInfo>(h,"C_GetTokenInfo")(id,b);Console.WriteLine("Token.slot={0}; rv=0x{1:X8}",id,rv);if(rv!=0)continue;Console.WriteLine("Token.label={0}; manufacturer={1}; model={2}; flags=0x{3:X8}",S(b,0,32),S(b,32,32),S(b,64,16),Marshal.ReadInt32(b,96));
      var ml=Fn<Mechs>(h,"C_GetMechanismList");uint count=0;rv=ml(id,IntPtr.Zero,ref count);Console.WriteLine("Mechanisms.slot={0}; rv=0x{1:X8}; count={2}",id,rv,count);if(rv!=0||count==0||count>256)continue;
      IntPtr mb=Marshal.AllocHGlobal((int)count*4);try{rv=ml(id,mb,ref count);if(rv!=0||count>256)continue;for(int j=0;j<count;j++){uint m=unchecked((uint)Marshal.ReadInt32(mb,j*4));rv=Fn<MechInfo>(h,"C_GetMechanismInfo")(id,m,b);Console.WriteLine("Mechanism=0x{0:X8}; rv=0x{1:X8}; min={2}; max={3}; flags=0x{4:X8}",m,rv,Marshal.ReadInt32(b,0),Marshal.ReadInt32(b,4),Marshal.ReadInt32(b,8));}}finally{Marshal.FreeHGlobal(mb);}
     }finally{Marshal.FreeHGlobal(b);}
    }}finally{Marshal.FreeHGlobal(ids);}
   }
  }finally{if(initialized)Console.WriteLine("C_Finalize=0x{0:X8}",Fn<Init>(h,"C_Finalize")(IntPtr.Zero));FreeLibrary(h);}
 }
 static void Main(string[] args){Console.WriteLine("Probe.processBits="+(IntPtr.Size*8));Readers();if(args.Length>0)Module(args[0]);}
}
