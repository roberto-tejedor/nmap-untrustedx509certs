local datetime = require "datetime"
local nmap = require "nmap"
--local outlib = require "outlib"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local unicode = require "unicode"
local openssl = require "openssl"

description = [[
Detects servers with a X509 certificate whose SubjectName or IssuerName
are part of a list of suspicious names or IPs, it is a self-signed certificate, or
the IP associated with the web server name does not belong to the range of IPs
associated with such domain. It prints the result indicating the information of the
certificate that is on the blacklist, if it is not on such list, if the IP is not in the
expected range, or if it is a self-signed certificate.
]]

---
-- @usage
--
-- @output
--
-- @args list the csv file name with the blacklist entries
--       (default: "blacklist.csv") 
--

author = "Roberto Tejedor Moreno"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "default", "safe" }

portrule = function(host, port)
    return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

local function read_list(list_file)

end

local function get_certificate_chain(host, port)
    local cmd = ("echo | openssl s_client -showcerts -connect %s:%s"):format(host.ip, port.number)

    local handle = io.popen(cmd)

    local certificate_chain = handle:read("*a")

    handle:close()
    
    local certificates = {}

    -- Get certificates
    for cert in certificate_chain:gmatch("-----BEGIN CERTIFICATE-----\n(.-)-----END CERTIFICATE-----") do
        table.insert(certificates, "-----BEGIN CERTIFICATE-----\n" .. cert .. "-----END CERTIFICATE-----")
    end

    -- Write certificates in files
    local server_cert_file = io.open("server.pem", "w")
    server_cert_file:write(certificates[1])
    local ca_cert_file = io.open("ca.pem", "w")
    ca_cert_file:write(certificates[2])
    server_cert_file:close()
    ca_cert_file:close()
end


action = function(host, port)
    host.targetname = tls.servername(host)
    local list_file = stdnse.get_script_args('list') or "blacklist.csv"
    local list = read_list(list_file)
    get_certificate_chain(host, port)
    local server_cert_file = "server.pem"
    local ca_cert_file = "ca.pem"
    local openssl_cmd = ("openssl verify -CAfile %s %s"):format(ca_cert_file, server_cert_file)
    local handle = io.popen(openssl_cmd)
    local output = handle:read("*a")
    handle:close()
    if string.find(output, "OK") then
        print("Signature verified")
    else
        print("Incorrect signature")
    end
    
end
