// Analyst capture transport. Never starts an invoice action: forwards only requests
// made by the user's original Windows plugin after a one-command LinkApi rewrite.
// No vendor assemblies, certificate store, system proxy or USB access.
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.7.2")]
sealed class MinvoiceBatchCaptureRelay {
    const int MaxBody=32*1024*1024;
    const int LifetimeMinutes=240;
    readonly string directory, prefix;
    readonly int invoiceCount;
    readonly HttpClient client;
    readonly object gate=new object();
    readonly JavaScriptSerializer json=new JavaScriptSerializer { MaxJsonLength=1024*1024, RecursionLimit=40 };
    int sequence, active, loginCount, uploadCount;
    volatile bool stopping;
    DateTime expiresAt=DateTime.UtcNow.AddMinutes(LifetimeMinutes);
    MinvoiceBatchCaptureRelay(string dir,string nonce,HttpMessageHandler handler,int expectedInvoices=3) {
        directory=dir; prefix="/capture-"+nonce; invoiceCount=expectedInvoices;
        client=new HttpClient(handler); client.Timeout=TimeSpan.FromMinutes(5);
    }
    static string Hex(byte[] value) {return BitConverter.ToString(value).Replace("-","").ToLowerInvariant();}
    static string Hash(byte[] value) {using(var h=SHA256.Create()) return Hex(h.ComputeHash(value));}
    static string NewNonce() {var b=new byte[16];using(var r=RandomNumberGenerator.Create())r.GetBytes(b);return Hex(b);}
    static bool Header(Dictionary<string,List<string>> h,string key) {return h.ContainsKey(key);}
    static string Value(Dictionary<string,List<string>> h,string key) {return h.ContainsKey(key)?string.Join(",",h[key]):"";}
    static bool ValidHeaderName(string name) {return Regex.IsMatch(name,@"^[A-Za-z0-9_-]+$");}
    static string ReadLine(Stream s,int limit) {
        var b=new List<byte>(); int c;
        while((c=s.ReadByte())!=-1) {
            if(c==10) {if(b.Count==0 || b[b.Count-1]!=13)throw new InvalidDataException();b.RemoveAt(b.Count-1);return Encoding.ASCII.GetString(b.ToArray());}
            if(c<0 || c>127 || b.Count>=limit)throw new InvalidDataException(); b.Add((byte)c);
        }
        throw new EndOfStreamException();
    }
    static byte[] ReadExact(Stream s,int n) {var b=new byte[n];int p=0;while(p<n){int k=s.Read(b,p,n-p);if(k==0)throw new EndOfStreamException();p+=k;}return b;}
    static byte[] ReadBody(Stream s,Dictionary<string,List<string>> headers) {
        bool length=Header(headers,"Content-Length"), chunked=Header(headers,"Transfer-Encoding");
        if(length && chunked)throw new InvalidDataException();
        if(chunked) {
            if(Value(headers,"Transfer-Encoding")!="chunked")throw new InvalidDataException();
            using(var body=new MemoryStream()) {
                for(;;) {
                    string line=ReadLine(s,128).Split(';')[0]; int n;
                    if(!int.TryParse(line,System.Globalization.NumberStyles.HexNumber,System.Globalization.CultureInfo.InvariantCulture,out n)||n<0||body.Length+n>MaxBody)throw new InvalidDataException();
                    if(n==0) {int trailers=0;while(ReadLine(s,8192)!="")if(++trailers>32)throw new InvalidDataException();return body.ToArray();}
                    var b=ReadExact(s,n);body.Write(b,0,b.Length);if(ReadLine(s,2)!="")throw new InvalidDataException();
                }
            }
        }
        if(!length)return new byte[0];
        int size;if(headers["Content-Length"].Count!=1||!int.TryParse(Value(headers,"Content-Length"),out size)||size<0||size>MaxBody)throw new InvalidDataException();
        return ReadExact(s,size);
    }
    static string Route(string method,string target,string prefix) {
        if(!target.StartsWith(prefix+"/api/",StringComparison.Ordinal))return null;
        string relative=target.Substring(prefix.Length), path=relative.Split('?')[0];
        if(relative.IndexOf('#')>=0||relative.IndexOf('\\')>=0||relative.Contains("%")||relative.Contains("..")||relative.IndexOf('\r')>=0||relative.IndexOf('\n')>=0)return null;
        if(method=="GET") {
            if(new[]{"/api/abp/application-configuration","/api/app/tenant-company/current-tenant","/api/app/release-invoice/tenant-setting-sign","/api/app/token/default-sign-usb"}.Contains(path) && !relative.Contains("?"))return path;
            if(Regex.IsMatch(relative,@"^/api/app/invoice/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/detail$"))return "/api/app/invoice/<GUID>/detail";
            if(Regex.IsMatch(relative,@"^/api/app/token/by-serial-number\?serialNumber=[0-9a-fA-F]{1,128}$"))return path+"?serialNumber=<redacted>";
        }
        if(method=="POST" && !relative.Contains("?") && new[]{"/api/account/login","/api/app/release-invoice/download-xml","/api/app/release-invoice/download-xml-invoice-cash","/api/app/release-invoice/delete-cache","/api/app/release-invoice/00000000-0000-0000-0000-000000000000/upload-xml"}.Contains(path))return path;
        return null;
    }
    static object Shape(object value,int depth=0,string name="") {
        if(depth>8)return "depth-limit";
        if(value==null)return "null";
        var dict=value as IDictionary<string,object>;
        if(dict!=null) {
            var result=new Dictionary<string,object>();
            foreach(var p in dict.Take(64)) {
                string key=Regex.IsMatch(p.Key,@"^[A-Za-z_][A-Za-z0-9_]{0,63}$")?p.Key:"<dynamic-key>";
                result[key]=Shape(p.Value,depth+1,key);
            }
            return result;
        }
        if(value is string)return "string";
        if(value is bool)return new[]{"status","success","isError"}.Contains(name)?value:(object)"boolean";
        if(value is int || value is long || value is decimal || value is double)return new[]{"code","errorCode"}.Contains(name)?value:(object)"number";
        var list=value as IList;
        if(list!=null)return new Dictionary<string,object>{{"type","array"},{"count",list.Count},{"item",list.Count==0?null:Shape(list[0],depth+1)}};
        return "other";
    }
    void Record(object row) {lock(gate)File.AppendAllText(Path.Combine(directory,"events.jsonl"),json.Serialize(row)+"\n",new UTF8Encoding(false));}
    static void Send(Stream stream,int status,Dictionary<string,IEnumerable<string>> headers,byte[] body) {
        var text=new StringBuilder("HTTP/1.1 "+status+" Relay\r\nConnection: close\r\nContent-Length: "+body.Length+"\r\n");
        foreach(var h in headers) {
            if(new[]{"connection","content-length","transfer-encoding","keep-alive","proxy-authenticate","proxy-authorization","trailer","upgrade"}.Contains(h.Key.ToLowerInvariant()))continue;
            foreach(var v in h.Value) {if(v.Contains("\r")||v.Contains("\n"))throw new InvalidDataException();text.Append(h.Key+": "+v+"\r\n");}
        }
        text.Append("\r\n");var head=Encoding.ASCII.GetBytes(text.ToString());stream.Write(head,0,head.Length);stream.Write(body,0,body.Length);
    }
    async Task Handle(TcpClient socket) {
        Interlocked.Increment(ref active);int id=Interlocked.Increment(ref sequence);string route=null,stage="request-line";
        using(socket)try {
            socket.ReceiveTimeout=30000;socket.SendTimeout=30000;
            var stream=socket.GetStream();var line=ReadLine(stream,8192).Split(' ');
            if(line.Length!=3 || line[2]!="HTTP/1.1")throw new InvalidDataException();
            var headers=new Dictionary<string,List<string>>(StringComparer.OrdinalIgnoreCase);int total=0;stage="request-headers";
            for(;;){string h=ReadLine(stream,8192);total+=h.Length;if(total>65536)throw new InvalidDataException();if(h=="")break;int i=h.IndexOf(':');if(i<1||!ValidHeaderName(h.Substring(0,i)))throw new InvalidDataException();string k=h.Substring(0,i),v=h.Substring(i+1).Trim();if(!headers.ContainsKey(k))headers[k]=new List<string>();headers[k].Add(v);}
            if((line[0]=="GET" || line[0]=="OPTIONS") && line[1]==prefix+"/status") {
                // Health only: no cookies, credentials, business responses or upstream request.
                var body=line[0]=="OPTIONS"?new byte[0]:Encoding.UTF8.GetBytes(json.Serialize(new{ready=!stopping && Volatile.Read(ref loginCount)==0 && expiresAt>DateTime.UtcNow.AddSeconds(60),expected_invoice_count=invoiceCount,expires_utc=expiresAt.ToString("o")}));
                Send(stream,line[0]=="OPTIONS"?204:200,new Dictionary<string,IEnumerable<string>>{
                    {"Content-Type",new[]{"application/json"}},{"Cache-Control",new[]{"no-store"}},
                    {"Access-Control-Allow-Origin",new[]{"*"}},{"Access-Control-Allow-Methods",new[]{"GET, OPTIONS"}},
                    {"Access-Control-Allow-Headers",new[]{"cache-control, pragma"}},
                    {"Access-Control-Allow-Private-Network",new[]{"true"}}
                },body);return;
            }
            stage="route";route=Route(line[0],line[1],prefix);
            if(route==null) {Send(stream,403,new Dictionary<string,IEnumerable<string>>(),new byte[0]);Record(new{sequence=id,rejected=true});return;}
            if(stopping || expiresAt<=DateTime.UtcNow)throw new InvalidDataException();
            if(route=="/api/account/login" && Interlocked.Increment(ref loginCount)>1)throw new InvalidDataException();
            if(route.EndsWith("/upload-xml") && Interlocked.Increment(ref uploadCount)>invoiceCount)throw new InvalidDataException();
            if(Value(headers,"Expect").Equals("100-continue",StringComparison.OrdinalIgnoreCase)) {var b=Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\n");stream.Write(b,0,b.Length);}
            stage="request-body";var data=ReadBody(stream,headers);
            object requestShape=null;
            if(route.Contains("/download-xml") || route.EndsWith("/delete-cache")) {
                var ids=json.DeserializeObject(Encoding.UTF8.GetString(data)) as object[];
                Guid parsed;
                if(ids==null || ids.Length<1 || ids.Length>invoiceCount || ids.Any(v=>!(v is string) || !Guid.TryParse((string)v,out parsed)) || ids.Cast<string>().Distinct(StringComparer.OrdinalIgnoreCase).Count()!=ids.Length)throw new InvalidDataException();
                requestShape=new {type="array",count=ids.Length,item="GUID"};
            }
            // The only upstream origin is fixed here. Input cannot select a host.
            using(var request=new HttpRequestMessage(new HttpMethod(line[0]),"https://api-hddt.minvoice.com.vn"+line[1].Substring(prefix.Length))) {
                if(data.Length>0 || line[0]=="POST")request.Content=new ByteArrayContent(data);
                foreach(var h in headers) {
                    if(new[]{"host","connection","content-length","transfer-encoding","expect","proxy-authorization","proxy-connection","accept-encoding"}.Contains(h.Key.ToLowerInvariant()))continue;
                    if(!request.Headers.TryAddWithoutValidation(h.Key,h.Value) && request.Content!=null)request.Content.Headers.TryAddWithoutValidation(h.Key,h.Value);
                }
                stage="upstream";using(var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead)) {
                    byte[] body;
                    stage="response-body";using(var input=await response.Content.ReadAsStreamAsync())using(var result=new MemoryStream()) {
                        var buf=new byte[16384];int k;while((k=await input.ReadAsync(buf,0,buf.Length))>0){if(result.Length+k>MaxBody)throw new InvalidDataException();result.Write(buf,0,k);}body=result.ToArray();
                    }
                    var outputHeaders=new Dictionary<string,IEnumerable<string>>(StringComparer.OrdinalIgnoreCase);
                    foreach(var h in response.Headers)outputHeaders[h.Key]=h.Value;
                    foreach(var h in response.Content.Headers)outputHeaders[h.Key]=h.Value;
                    // Never retain raw JSON/login bodies, headers, cookies or error messages.
                    object shape=null;
                    if(body.Length<=1024*1024)try {shape=Shape(new JavaScriptSerializer {MaxJsonLength=1024*1024,RecursionLimit=40}.DeserializeObject(Encoding.UTF8.GetString(body)));}catch{shape="not-json";}
                    string artifact=null;
                    if(route.Contains("/download-xml") && body.Length>=4 && body[0]==80 && body[1]==75) {artifact=id.ToString("D4")+"-download.zip";File.WriteAllBytes(Path.Combine(directory,artifact),body);}
                    if(route.EndsWith("/upload-xml")) {artifact=id.ToString("D4")+"-signed.multipart";File.WriteAllBytes(Path.Combine(directory,artifact),data);}
                    Record(new{sequence=id,utc=DateTime.UtcNow.ToString("o"),method=line[0],route=route,status=(int)response.StatusCode,request_bytes=data.Length,request_shape=requestShape,x_req_id_value_count=headers.ContainsKey("x_req_id")?headers["x_req_id"].Count:0,response_bytes=body.Length,response_content_type=response.Content.Headers.ContentType==null?null:response.Content.Headers.ContentType.ToString(),cookie_present=Header(headers,"Cookie"),verification_header_present=Header(headers,"RequestVerificationToken"),authorization_present=Header(headers,"Authorization"),response_shape=shape,artifact=artifact,artifact_sha256=artifact==null?null:Hash(artifact.EndsWith(".zip")?body:data)});
                    stage="response-forward";Send(stream,(int)response.StatusCode,outputHeaders,body);
                }
            }
        }catch(Exception ex) {Record(new{sequence=id,route=route,stage=stage,failure_type=ex.GetType().Name});try{Send(socket.GetStream(),502,new Dictionary<string,IEnumerable<string>>(),Encoding.ASCII.GetBytes("Capture relay failed; do not retry signing automatically."));}catch{}}
        finally {Interlocked.Decrement(ref active);}
    }
    async Task Run(int port) {
        var listener=new TcpListener(IPAddress.Loopback,port);listener.Start();
        File.WriteAllText(Path.Combine(directory,"relay.json"),json.Serialize(new{pid=System.Diagnostics.Process.GetCurrentProcess().Id,port=port,api="http://127.0.0.1:"+port+prefix+"/api/app/",status="http://127.0.0.1:"+port+prefix+"/status",upstream="https://api-hddt.minvoice.com.vn",expected_invoice_count=invoiceCount,expires_utc=expiresAt.ToString("o")}),new UTF8Encoding(false));
        using(var timer=new Timer(_=>{stopping=true;listener.Stop();},null,expiresAt-DateTime.UtcNow,Timeout.InfiniteTimeSpan)) {
            Console.WriteLine("READY loopback capture; no signing action initiated.");
            while(!stopping)try {var socket=await listener.AcceptTcpClientAsync();var ignored=Task.Run(()=>Handle(socket));}catch(ObjectDisposedException){break;}catch(SocketException){if(!stopping)throw;}
            while(Volatile.Read(ref active)>0)await Task.Delay(250);
        }
        client.Dispose();
    }
    sealed class FixtureHandler : HttpMessageHandler {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct) {
            Assert(request.Headers.Contains("x_req_id"));
            Calls++;var response=new HttpResponseMessage(HttpStatusCode.OK);response.Content=new StringContent("{\"code\":1,\"status\":true,\"password\":\"NEVER_RETAIN_SECRET\",\"cookie\":\"NEVER_RETAIN_COOKIE\",\"message\":\"NEVER_RETAIN_MESSAGE\"}");response.Headers.TryAddWithoutValidation("Set-Cookie","fake=NEVER_RETAIN_COOKIE; HttpOnly");return Task.FromResult(response);
        }
    }
    static void Assert(bool ok) {if(!ok)throw new Exception("self-test assertion failed");}
    static async Task<string> FixtureRequest(MinvoiceBatchCaptureRelay relay,string request) {
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;
        using(var socket=new TcpClient()) {
            await socket.ConnectAsync(IPAddress.Loopback,port);var accepted=await listener.AcceptTcpClientAsync();var handling=Task.Run(()=>relay.Handle(accepted));
            var data=Encoding.ASCII.GetBytes(request);await socket.GetStream().WriteAsync(data,0,data.Length);
            string result;using(var reader=new StreamReader(socket.GetStream()))result=await reader.ReadToEndAsync();
            await handling;listener.Stop();return result;
        }
    }
    static async Task SelfTest(string directory) {
        string nonce="fixture";var mock=new FixtureHandler();var relay=new MinvoiceBatchCaptureRelay(directory,nonce,mock);
        Assert(ValidHeaderName("x_req_id") && !ValidHeaderName("bad name") && !ValidHeaderName("bad\r\nCookie"));
        Assert(Route("POST","/capture-fixture/api/account/login",relay.prefix)!=null);
        foreach(var target in new[]{"https://evil.example/api/account/login","/capture-wrong/api/account/login","/capture-fixture/api/app/../account/login","/capture-fixture/api/account/login?evil=1","/capture-fixture/api/app/companies/update-token/x"})Assert(Route("POST",target,relay.prefix)==null);
        string health=await FixtureRequest(relay,"GET /capture-fixture/status HTTP/1.1\r\nHost: localhost\r\n\r\n");
        Assert(health.Contains("\"ready\":true") && health.Contains("expires_utc") && health.Contains("Access-Control-Allow-Origin: *") && health.Contains("Cache-Control: no-store") && mock.Calls==0);
        string options=await FixtureRequest(relay,"OPTIONS /capture-fixture/status HTTP/1.1\r\nHost: localhost\r\nAccess-Control-Request-Private-Network: true\r\n\r\n");
        Assert(options.StartsWith("HTTP/1.1 204") && options.Contains("Access-Control-Allow-Private-Network: true") && mock.Calls==0);
        relay.expiresAt=DateTime.UtcNow.AddSeconds(30);
        Assert((await FixtureRequest(relay,"GET /capture-fixture/status HTTP/1.1\r\nHost: localhost\r\n\r\n")).Contains("\"ready\":false"));
        relay.expiresAt=DateTime.UtcNow.AddMinutes(LifetimeMinutes);
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;
        var socket=new TcpClient();await socket.ConnectAsync(IPAddress.Loopback,port);var accepted=await listener.AcceptTcpClientAsync();var handling=Task.Run(()=>relay.Handle(accepted));
        var req=Encoding.ASCII.GetBytes("POST /capture-fixture/api/account/login HTTP/1.1\r\nHost: 127.0.0.1\r\nx_req_id: fixture-correlation\r\nCookie: NEVER_RETAIN_COOKIE\r\nContent-Type: application/json\r\nContent-Length: 35\r\nConnection: close\r\n\r\n{\"Password\":\"NEVER_RETAIN_SECRET\"}");
        // Set the exact length rather than relying on a hard-coded count.
        string text=Encoding.ASCII.GetString(req);int separator=text.IndexOf("\r\n\r\n");int size=text.Length-separator-4;text=text.Replace("Content-Length: 35","Content-Length: "+size);req=Encoding.ASCII.GetBytes(text);
        await socket.GetStream().WriteAsync(req,0,req.Length);using(var reader=new StreamReader(socket.GetStream())){string result=await reader.ReadToEndAsync();Assert(result.StartsWith("HTTP/1.1 200"));Assert(result.Contains("NEVER_RETAIN_COOKIE"));}
        await handling;listener.Stop();socket.Dispose();Assert(mock.Calls==1);
        Assert((await FixtureRequest(relay,"GET /capture-fixture/status HTTP/1.1\r\nHost: localhost\r\n\r\n")).Contains("\"ready\":false") && mock.Calls==1);
        for(int i=0;i<3;i++)Assert((await FixtureRequest(relay,"POST /capture-fixture/api/app/release-invoice/00000000-0000-0000-0000-000000000000/upload-xml HTTP/1.1\r\nHost: localhost\r\nx_req_id: fixture\r\nContent-Length: 0\r\n\r\n")).StartsWith("HTTP/1.1 200"));
        Assert((await FixtureRequest(relay,"POST /capture-fixture/api/app/release-invoice/00000000-0000-0000-0000-000000000000/upload-xml HTTP/1.1\r\nHost: localhost\r\nx_req_id: fixture\r\nContent-Length: 0\r\n\r\n")).StartsWith("HTTP/1.1 502"));
        Assert(mock.Calls==4);
        string log=File.ReadAllText(Path.Combine(directory,"events.jsonl"));Assert(!log.Contains("NEVER_RETAIN"));Assert(log.Contains("\"code\":1"));
        using(var input=new MemoryStream(Encoding.ASCII.GetBytes("3\r\nabc\r\n0\r\n\r\n")))Assert(Encoding.ASCII.GetString(ReadBody(input,new Dictionary<string,List<string>>{{"Transfer-Encoding",new List<string>{"chunked"}}}))=="abc");
        bool rejected=false;try{ReadBody(new MemoryStream(),new Dictionary<string,List<string>>{{"Content-Length",new List<string>{"0"}},{"Transfer-Encoding",new List<string>{"chunked"}}});}catch(InvalidDataException){rejected=true;}Assert(rejected);
        Console.WriteLine("PASS offline: health CORS/preflight/expiry/used state, underscore headers forwarded, allowlist, framing, credential redaction, response schema; no external network.");
    }
    public static int Main(string[] args) {
        try {
            if(args.Length==2 && args[0]=="--self-test") {Directory.CreateDirectory(args[1]);SelfTest(args[1]).GetAwaiter().GetResult();return 0;}
            int expected;
            if(args.Length!=2 || !int.TryParse(args[1],out expected) || expected<2 || expected>10000 || !Path.IsPathRooted(args[0]) || Directory.Exists(args[0]))throw new ArgumentException();
            Directory.CreateDirectory(args[0]);
            var handler=new HttpClientHandler {UseCookies=false,UseProxy=false,AllowAutoRedirect=false,AutomaticDecompression=DecompressionMethods.None};
            new MinvoiceBatchCaptureRelay(args[0],NewNonce(),handler,expected).Run(17080).GetAwaiter().GetResult();return 0;
        }catch(Exception ex) {Console.Error.WriteLine("Relay stopped: "+ex.GetType().Name);return 1;}
    }
}
