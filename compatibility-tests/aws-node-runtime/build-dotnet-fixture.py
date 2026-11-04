#!/usr/bin/env python3
"""Build a stream-based Lambda fixture using the checksum-verified Microsoft SDK."""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import subprocess
import tarfile
import urllib.request
import zipfile

SDK_ARTIFACTS = {
    'x86_64': ('x64', 'b7b3d8461cf98b07d2552ce9199702fa3ad010ac2671a5f8cd5136f7534e50f6855ba7bbb02b11494563f1d04156276a31cda1103b900e5eecd0d9473dc7b9c5'),
    'aarch64': ('arm64', '0966aa2b70f4677b8319be9df447a78a0dcd6164836425b55a68fd714f4023feb87b4cac21b9a996b79472ad54487cd0adcd2a9dfd570e2b2a1d26423a2baa9b'),
}

SOURCE = '''using System;
using System.IO;
using System.Text;
using System.Threading;
namespace Probe {
 public class Function {
  static int count;
  public Stream Handle(Stream input, Amazon.Lambda.Core.ILambdaContext context) {
   var body = new StreamReader(input).ReadToEnd();
   Console.WriteLine("runtime-probe");
   if(body.Contains("\\"fail\\"")) throw new Exception("deliberate-provider-error");
   if(body.Contains("\\"sleep\\"")) Thread.Sleep(10000);
   var colon = body.IndexOf(':');
   var value = colon < 0 ? "null" : body.Substring(colon+1).Trim().TrimEnd('}').Trim();
   return new MemoryStream(Encoding.UTF8.GetBytes("{\\"count\\":" + (++count) + ",\\"version\\":\\"" + Environment.Version + "\\",\\"value\\":" + value + "}"));
  }
 }
}'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    architecture, sdk_sha512 = SDK_ARTIFACTS[platform.machine()]
    sdk_url = f'https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.403/dotnet-sdk-10.0.403-linux-{architecture}.tar.gz'
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    sdk = work / 'sdk'
    if not (sdk / 'dotnet').exists():
        archive = work / 'sdk.tar.gz'
        if not archive.exists():
            with urllib.request.urlopen(sdk_url, timeout=60) as response, archive.open('wb') as output:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > 350 * 1024 * 1024:
                        raise ValueError('SDK exceeds download bound')
                    output.write(chunk)
        with archive.open('rb') as source:
            if hashlib.file_digest(source, 'sha512').hexdigest() != sdk_sha512:
                raise ValueError('Official SDK checksum mismatch')
        sdk.mkdir(exist_ok=True)
        with tarfile.open(archive) as image:
            members = image.getmembers()
            if len(members) > 50000 or sum(m.size for m in members) > 1500 * 1024 * 1024:
                raise ValueError('SDK exceeds extraction bounds')
            image.extractall(sdk, members=members, filter='data')
    project = work / 'project'
    project.mkdir(exist_ok=True)
    (project / 'Probe.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>netstandard2.1</TargetFramework><GenerateDependencyFile>true</GenerateDependencyFile><CopyLocalLockFileAssemblies>true</CopyLocalLockFileAssemblies><AssemblyName>Probe</AssemblyName></PropertyGroup><ItemGroup><PackageReference Include="Amazon.Lambda.Core" Version="3.4.0" /></ItemGroup></Project>')
    (project / 'Function.cs').write_text(SOURCE)
    (project / 'NuGet.Config').write_text('<configuration><packageSources><clear /><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>')
    env = dict(os.environ, DOTNET_ROOT=str(sdk), DOTNET_CLI_HOME=str(work / 'home'),
               DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_GENERATE_ASPNET_CERTIFICATE='false', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',
               NUGET_PACKAGES=str(work / 'nuget'), MSBUILDDISABLENODEREUSE='1')
    subprocess.run([str(sdk / 'dotnet'), 'build', str(project / 'Probe.csproj'), '-c', 'Release', '--nologo', '-maxcpucount:2', '-p:UseSharedCompilation=false', '--disable-build-servers'], env=env, check=True)
    output = project / 'bin/Release/netstandard2.1'
    for major in [8, 10]:
        with zipfile.ZipFile(work / f'dotnet{major}.zip', 'w', zipfile.ZIP_DEFLATED) as z:
            for path in output.glob('*'):
                if path.is_file():
                    z.write(path, path.name)
            z.writestr('Probe.runtimeconfig.json', json.dumps({'runtimeOptions':{'tfm':f'net{major}.0','framework':{'name':'Microsoft.NETCore.App','version':f'{major}.0.0'}}}))
    print(json.dumps({'sdkSha512':sdk_sha512,'fixtures':['dotnet8.zip','dotnet10.zip']}))

if __name__ == '__main__':
    main()
