# X509certs NSE script (Lua)

A custom **Nmap NSE script** written in **LUA** to extract and display information from SSL/TLS certificates during a scan - with a special focus on **alerting for expired or untrusted certificates**.

This script was developed as part of a cibersecurity lab assignment in my master's degree. It is shared for learning and demonstration purposes.

---

## Key Features

This script detects servers with a X509 certificate: whose SubjectName or IssuerName are part of a list of suspicious names or IPs (defined in blacklist.csv); it is a self-signed certificate; or the IP associated with the web server name does not belong to the range of IPs associated with such domain.

The output shows: the information certificate that is on the blacklist, if it is not on such list, if the IP is not in the expected range, or if it is a self-signed certificate.

## Usage

```bash
nmap --script untrustedX509certs.nse --script-args "list=blacklist.csv" -p 443 <target>
