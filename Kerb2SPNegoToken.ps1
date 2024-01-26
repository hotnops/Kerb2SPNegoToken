$code = @"
using System;
using System.Runtime.InteropServices;

public static class Win32API
{
    public struct CredHandle
    {
        public IntPtr dwLower;
        public IntPtr dwUpper;
    }

    public struct CtxtHandle
    {
        public IntPtr dwLower;
        public IntPtr dwUpper;
    }

    public struct SecBuffer
    {
        public int cbBuffer;
        public int BufferType;
        public IntPtr pvBuffer;
    }

    public struct SecBufferDesc
    {
        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffers; // Pointer to SecBuffer
    }

    public struct TimeStamp
    {
        public long QuadPart;
    }

    [DllImport("secur32.dll", CharSet = CharSet.Ansi)]
    public static extern int AcquireCredentialsHandle(
        string pszPrincipal,
        string pszPackage,
        int fCredentialUse,
        IntPtr pvLogonId,
        IntPtr pAuthData,
        IntPtr pGetKeyFn,
        IntPtr pvGetKeyArgument,
        ref CredHandle phCredential,
        ref TimeStamp ptsExpiry
    );

    [DllImport("secur32.dll", CharSet = CharSet.Ansi)]
    public static extern int InitializeSecurityContextA(
        ref CredHandle phCredential,
        IntPtr phContext,
        string pszTargetName,
        int fContextReq,
        int Reserved1,
        int TargetDataRep,
        IntPtr pInput,
        int Reserved2,
        ref CtxtHandle phNewContext,
        ref SecBufferDesc pOutput,
        ref int pfContextAttr,
        ref TimeStamp ptsExpiry
    );

    [DllImport("secur32.dll", CharSet = CharSet.Ansi)]
    public static extern int FreeContextBuffer(IntPtr pvContextBuffer);

    [DllImport("secur32.dll", CharSet = CharSet.Ansi)]
    public static extern int DeleteSecurityContext(ref CtxtHandle phContext);
}
"@

Add-Type -TypeDefinition $code

function Get-SPNEGOToken()
{
    $pszPackageName = "Negotiate"
    $serviceName = "HTTP/autologon.microsoftazuread-sso.com"
    $hCredHandle = New-Object Win32API+CredHandle
    $hExpiry = New-Object Win32API+TimeStamp

    $SECPKG_CRED_BOTH = 3
    $SECBUFFER_VERSION = 0
    $SECBUFFER_TOKEN = 2
    $ISC_REQ_SEQUENCE_DETECT = 0x00000008
    $ISC_REQ_ALLOCATE_MEMORY = 0x00000100
    $SECURITY_NATIVE_DREP = 0x00000010
    $SEC_I_CONTINUE_NEEDED = 0x00090312

    $dwSecStatus = [Win32API]::AcquireCredentialsHandle(
        $null,
        $pszPackageName,
        $SECPKG_CRED_BOTH,
        0,
        0,
        0,
        0,
        [ref]$hCredHandle,
        [ref]$hExpiry
    )

    # Check for errors
    if ($dwSecStatus -ne 0) {
        Write-Host "[!] AcquireCredentialsHandle failed"
        return
    }

    $tsExpiry = New-Object Win32API+TimeStamp
    $hNewCtx = New-Object Win32API+CtxtHandle
    $OutBuffDesc = New-Object Win32API+SecBufferDesc
    $OutSecBuff = New-Object Win32API+SecBuffer
    $fContextAttr = 0

    $OutSecBuff.cbBuffer = 0
    $OutSecBuff.BufferType = $SECBUFFER_TOKEN
    $OutSecBuff.pvBuffer = 0

    $OutBuffDesc.cBuffers = 1
    $OutBuffDesc.ulVersion = $SECBUFFER_VERSION

    $OutSecBuffSize = [Runtime.InteropServices.Marshal]::SizeOf($OutSecBuff)
    $OutSecBuffPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($OutSecBuffSize)

    [Runtime.InteropServices.Marshal]::StructureToPtr($OutSecBuff, $OutSecBuffPtr, $false)

    $OutBuffDesc.pBuffers = $OutSecBuffPtr

    $dwSecStatus = [Win32API]::InitializeSecurityContextA(
        [ref]$hCredHandle,
        0,
        $serviceName,
        $ISC_REQ_SEQUENCE_DETECT -bor $ISC_REQ_ALLOCATE_MEMORY,
        0,
        $SECURITY_NATIVE_DREP,
        0,
        0,
        [ref]$hNewCtx,
        [ref]$OutBuffDesc,
        [ref]$fContextAttr,
        [ref]$tsExpiry
    )

    if ($dwSecStatus -ne $SEC_I_CONTINUE_NEEDED) {
        Write-Host "[!] InitializeSecurityContextA failed"
        return
    }

    $OutSecBuff = [Runtime.InteropServices.Marshal]::PtrToStructure($OutSecBuffPtr, [Type][Win32API+SecBuffer])

    $bufferLength = $OutSecBuff.cbBuffer
    $bufferPtr = $OutSecBuff.pvBuffer

    $buffer = New-Object byte[] $bufferLength

    [System.Runtime.InteropServices.Marshal]::Copy($bufferPtr, $buffer, 0, $bufferLength)

    $base64String = [System.Convert]::ToBase64String($buffer)
    $base64String
}