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
--local have_openssl, openssl = pcall(require, "openssl")

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
-- @args
--

author = "Roberto Tejedor Moreno"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "default", "safe" }

portrule = function(host, port)
    return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
  end

local function get_certificate_chain(host, port)

    local cmd = ("echo | openssl s_client -showcerts -connect %s:%s"):format(host.ip, port.number)

    local handle = io.popen(cmd)

    local certificate_chain = handle:read("*a")

    handle:close()

    return certificate_chain

end

action = function(host, port)
    host.targetname = tls.servername(host)
    local certificate_chain = get_certificate_chain(host, port)
    --local ca_cert_file, server_cert_file
    --local openssl_cmd = ("openssl verify -CAfile %s %s"):format(ca_cert_file, server_cert_file)

    return stdnse.format_output(true, certificate_chain)

end