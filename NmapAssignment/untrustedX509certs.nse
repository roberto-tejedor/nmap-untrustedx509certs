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

-- Gets the certificate chain via openssl and stores server cert and ca cert in files
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
    local server_cert_filename = "server.pem"
    local server_cert_file = io.open(server_cert_filename, "w")
    server_cert_file:write(certificates[1])
    server_cert_file:close()
    
    -- The second certificate in the chain is the CA certificate
    if certificates[2] ~= nil then
        local ca_cert_filename = "ca.pem"
        local ca_cert_file = io.open(ca_cert_filename, "w")
        ca_cert_file:write(certificates[2])
        ca_cert_file:close()
    end
    

    return server_cert_filename, ca_cert_filename
end

-- Verifies that the server certificate issuer matches the CA certificate subject
local function check_issuer(server_cert, ca_cert)
    local match = true
    for k, v in pairs(server_cert.issuer) do
        
        if v ~= ca_cert.subject[k] then
            print("The server certificate issuer does not match the CA certificate subject: field" .. k .. "is different.")
            match = false
            break
        end
    end

    if match then
        print("The server certificate issuer matches the CA certificate subject")
    end
end


-- Verifies that the server cert is signed by the ca cert via openssl
local function check_signature(server_cert_file, ca_cert_file)

    local openssl_cmd = ("openssl verify -CAfile %s %s"):format(ca_cert_file, server_cert_file)
    local handle = io.popen(openssl_cmd)
    local output = handle:read("*a")
    handle:close()

    if string.find(output, "OK") then
        print("Signature correct: " .. output)
    else
        print("Error verifying signature: " .. output)
    end

end

-- Gets the certificates and parses them using sslcert library to access the fields easily
local function get_certifiates_info(host, port)

    -- Get the certificate in PEM format
    local server_cert_file, ca_cert_file = get_certificate_chain(host, port)

    -- Transforms from PEM to DER and parse the certificates to manipulate them using the sslcert library
    local openssl_cmd = ("openssl x509 -inform PEM -in %s -outform DER"):format(server_cert_file)
    local handle = io.popen(openssl_cmd)
    local server_cert = sslcert.parse_ssl_certificate(handle:read("*a"))
    openssl_cmd = ("openssl x509 -inform PEM -in %s -outform DER"):format(ca_cert_file)
    handle = io.popen(openssl_cmd)
    local ca_cert = sslcert.parse_ssl_certificate(handle:read("*a"))
    handle:close()
    
    -- Validations
    check_issuer(server_cert, ca_cert)
    check_signature(server_cert_file, ca_cert_file)

    return server_cert, ca_cert
end



action = function(host, port)
    host.targetname = tls.servername(host)
    local list_file = stdnse.get_script_args('list') or "blacklist.csv"
    local list = read_list(list_file)

    local server_cert, ca_cert = get_certifiates_info(host, port)
    

end




-- -- From ssl-cert.nse (https://nmap.org/nsedoc/scripts/ssl-cert.html)
-- -- These are the subject/issuer name fields that will be shown, in this order,
-- -- without a high verbosity.
-- local NON_VERBOSE_FIELDS = { "commonName", "organizationName",
-- "stateOrProvinceName", "countryName" }

-- -- Test to see if the string is UTF-16 and transcode it if possible
-- local function maybe_decode(str)
--   -- If length is not even, then return as-is
--   if #str < 2 or #str % 2 == 1 then
--     return str
--   end
--   if str:byte(1) > 0 and str:byte(2) == 0 then
--     -- little-endian UTF-16
--     return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, false, nil)
--   elseif str:byte(1) == 0 and str:byte(2) > 0 then
--     -- big-endian UTF-16
--     return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, true, nil)
--   else
--     return str
--   end
-- end
-- function stringify_name(name)
--     local fields = {}
--     local _, k, v
--     if not name then
--       return nil
--     end
--     for _, k in ipairs(NON_VERBOSE_FIELDS) do
--       v = name[k]
--       if v then
--         fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
--       end
--     end
--     if nmap.verbosity() > 1 then
--       for k, v in pairs(name) do
--         -- Don't include a field twice.
--         if not table_find(NON_VERBOSE_FIELDS, k) then
--           if type(k) == "table" then
--             k = table.concat(k, ".")
--           end
--           fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
--         end
--       end
--     end
--     return table.concat(fields, "/")
--   end
  
