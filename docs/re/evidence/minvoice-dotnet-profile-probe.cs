// Analyst-controlled replay of the API sequence observed in Minvoice SignFile.
// Does not load vendor assemblies, use a token/certificate store, or access network.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.7.2")]
sealed class FixtureSignedXml : SignedXml {
    public FixtureSignedXml(XmlDocument d) : base(d) {}
    public override XmlElement GetIdElement(XmlDocument d, string id) {
        return (XmlElement)d.SelectSingleNode("//*[@Id='" + id + "']") ?? base.GetIdElement(d,id);
    }
}
static class ProfileProbe {
    public static void Main(string[] args) {
        const string id="12345678-90ab-cdef-1234-567890abcdef";
        var doc=new XmlDocument(); doc.PreserveWhitespace=true;
        doc.LoadXml("<HDon><DLHDon Id='"+id+"'><Fixture>TokenSigner test only</Fixture></DLHDon><DSCKS><NBan /></DSCKS></HDon>");
        using(var key=new RSACryptoServiceProvider(2048)) {
            key.PersistKeyInCsp=false;
            var req=new CertificateRequest("CN=TokenSigner software fixture",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            using(var cert=req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddMinutes(15))) {
                var sx=new FixtureSignedXml(doc); sx.SigningKey=key;
                var t=new XmlDocument(); var root=t.CreateElement("Minvoice"); t.AppendChild(root);
                var props=t.CreateElement("SignatureProperties"); root.AppendChild(props);
                var prop=t.CreateElement("SignatureProperty"); prop.SetAttribute("Target","#signtime"); props.AppendChild(prop);
                var time=t.CreateElement("SigningTime"); time.AppendChild(t.CreateTextNode("2026-10-22T19:00:00")); prop.AppendChild(time);
                var obj=new DataObject(); obj.Data=t.SelectNodes("//SignatureProperties"); obj.Id="signtime"; sx.AddObject(obj);
                obj.GetXml();
                var ki=new KeyInfo(); var xd=new KeyInfoX509Data(cert); xd.AddSubjectName(cert.SubjectName.Name); ki.AddClause(xd); sx.KeyInfo=ki;
                var r=new Reference(); r.Uri="#"+id; r.AddTransform(new XmlDsigEnvelopedSignatureTransform()); r.AddTransform(new XmlDsigC14NTransform()); sx.AddReference(r);
                var rt=new Reference(); rt.Uri="#signtime"; sx.AddReference(rt);
                sx.ComputeSignature();
                doc.SelectSingleNode("//HDon/DSCKS/NBan").AppendChild(sx.GetXml());
                File.WriteAllText(args[0],doc.OuterXml,new System.Text.UTF8Encoding(false));
                var verify=new FixtureSignedXml(doc); verify.LoadXml((XmlElement)doc.GetElementsByTagName("Signature",SignedXml.XmlDsigNamespaceUrl)[0]);
                Console.WriteLine("verify="+verify.CheckSignature(key));
                Console.WriteLine("signature="+sx.SignedInfo.SignatureMethod);
                Console.WriteLine("canonicalization="+sx.SignedInfo.CanonicalizationMethod);
                foreach(Reference reference in sx.SignedInfo.References) Console.WriteLine("digest="+reference.Uri+" "+reference.DigestMethod);
                Console.WriteLine("framework="+AppDomain.CurrentDomain.SetupInformation.TargetFrameworkName);
                Console.WriteLine("system_security="+typeof(SignedXml).Assembly.Location);
                Console.WriteLine("clr="+Environment.Version);
                Console.WriteLine("is64bit="+Environment.Is64BitProcess);
            }
        }
    }
}
