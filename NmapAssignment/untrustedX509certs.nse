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

local function read_list(list_filename)
    local list_file =  io.open(list_filename, "r")

    local blacklist = {}
    for line in io.lines(list_filename) do
        local date, name, severity = line:match("([^;]+);([^;]+);([^;]+)")
        if date and name and severity then
            table.insert(blacklist, {date = date, name = name, severity = severity})
        end
    end

    list_file:close()
    return blacklist
end
-- Constants to define the filenames of the certificates
local SERVER_CERT_FILENAME = "server.pem"
local CA_CERT_FILENAME = "ca.pem"
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
    local server_cert_filename = SERVER_CERT_FILENAME
    local server_cert_file = io.open(server_cert_filename, "w")
    server_cert_file:write(certificates[1])
    server_cert_file:close()
    
    -- The second certificate in the chain is the CA certificate
    local ca_cert_filename = nil
    if certificates[2] ~= nil then
        ca_cert_filename = CA_CERT_FILENAME
        local ca_cert_file = io.open(ca_cert_filename, "w")
        ca_cert_file:write(certificates[2])
        ca_cert_file:close()
    end
    

    return server_cert_filename, ca_cert_filename
end

-- Verifies that the server certificate issuer matches the CA certificate subject
local function check_issuer(server_cert, ca_cert)
    local match = true
    local output
    for k, v in pairs(server_cert.issuer) do
        
        if v ~= ca_cert.subject[k] then
            output = "WARNING: The server certificate issuer does not match the CA certificate subject: field" .. k .. "is different."
            match = false
            break
        end
    end
    
    if match then
        output = "The server certificate issuer matches the CA certificate subject"
    end

    return output
end


-- Verifies that the server cert is signed by the ca cert via openssl
local function check_signature(server_cert_file, ca_cert_file)
    local output
    local openssl_cmd = ("openssl verify -CAfile %s %s"):format(ca_cert_file, server_cert_file)
    local handle = io.popen(openssl_cmd)
    local cmd_output = handle:read("*a")
    handle:close()

    if string.find(cmd_output, "OK") then
        output = "Signature correct: " .. cmd_output
    else
        output = "WARNING: Error verifying signature: " .. cmd_output
    end

    return output
end

local function check_self_signed_cert(cert)
    local output
    local match = true
    for k, v in pairs(cert.issuer) do
        
        if v ~= cert.subject[k] then
            output = "WARNING: Missing CA certificate"
            match = false
            break
        end
    end
    
    if match then
        output = "The certificate is self-signed"
    end

    return output
    
end

-- Gets the certificates and parses them using sslcert library to access the fields easily
local function get_certifiates_info(host, port)
    -- Get the certificate in PEM format
    local server_cert_file, ca_cert_file = get_certificate_chain(host, port)

    -- Transforms from PEM to DER and parse the certificates to manipulate them using the sslcert library
    local openssl_cmd = ("openssl x509 -inform PEM -in %s -outform DER"):format(server_cert_file)
    local handle = io.popen(openssl_cmd)
    local server_cert = sslcert.parse_ssl_certificate(handle:read("*a"))
    local ca_cert = nil
    if ca_cert_file ~= nil then
        openssl_cmd = ("openssl x509 -inform PEM -in %s -outform DER"):format(ca_cert_file)
        handle = io.popen(openssl_cmd)
        ca_cert = sslcert.parse_ssl_certificate(handle:read("*a"))
    end
    
    handle:close()
    

    return server_cert, ca_cert
end

local function is_in_blacklist(blacklist, cert)
    local in_blacklist = false
    local entry = nil
    for _, v in pairs(blacklist) do
        if (cert.issuer["organizationName"] == v.name) or
           (cert.issuer["commonName"] == v.name) or 
           (cert.subject["organizationName"] == v.name) or 
           (cert.subject["commonName"] == v.name) then
            in_blacklist = true
            entry = v
        end
    end

    return in_blacklist, entry
end

-- Checks the certificate is within its validid date range
local function check_validity(cert)
    local not_before, not_after = datetime.format_timestamp(cert.validity.notBefore),
                                  datetime.format_timestamp(cert.validity.notAfter)
    -- The dates are compared with the current date formatted to the certificate validity dates format                              
    return not_before <= os.date("%Y-%m-%dT%H:%M:%S") and os.date("%Y-%m-%dT%H:%M:%S") <= not_after
end

-- Checks if the Subject Alternative Name contains the host name
local function ckeck_alternative_name(cert, host)
    local correct = nil
    if cert.extensions then
        for _, e in ipairs(cert.extensions) do
          if e.name == "X509v3 Subject Alternative Name" then
            correct = false
            if string.find(e.value, host.targetname) then
                correct = true
            end
            break
          end
        end
    end
    return correct
end

-- Prints the most relevant info of the certificate
local function print_certificate(cert)
    local output = {}
    output[#output + 1] = "Certificate Info:"
    output[#output + 1] = "| Subject: "
    for k, v in pairs(cert.subject) do
        output[#output + 1] = "|  " .. k .. " = " .. v
    end
    if cert.extensions then
        for _, e in ipairs(cert.extensions) do
          if e.name == "X509v3 Subject Alternative Name" then
            output[#output + 1] = "Subject Alternative Name: " .. e.value
            break
          end
        end
    end
    output[#output + 1] = "| Issuer: "
    for k, v in pairs(cert.issuer) do
        output[#output + 1] = "|  " .. k .. " = " .. v
    end

    output[#output + 1] = "| Public Key type: " .. cert.pubkey.type
    output[#output + 1] = "| Public Key bits: " .. cert.pubkey.bits
    output[#output + 1] = "| Signature Algorithm: " .. cert.sig_algorithm

    output[#output + 1] = "| Not valid before " .. datetime.format_timestamp(cert.validity.notBefore)
    output[#output + 1] = "| Not valid after " .. datetime.format_timestamp(cert.validity.notAfter)

    output[#output + 1] = "| MD5:   " .. stdnse.tohex(cert:digest("md5"), { separator = " ", group = 4 })
    output[#output + 1] = "| SHA-1: " .. stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 })

    output[#output + 1] = cert.pem

    return table.concat(output, "\n")
end

-- Removes PEM files
local function remove_files()
    local cmd = ("rm %s %s &> /dev/null"):format(SERVER_CERT_FILENAME, CA_CERT_FILENAME)
    local handle = io.popen(cmd)
    handle:close()
end

action = function(host, port)
    host.targetname = tls.servername(host)
    local output = {}
    -- Basic functionality
    local list_filename = stdnse.get_script_args('list') or "blacklist.csv"
    local blacklist = read_list(list_filename) 
    
    local server_cert, ca_cert = get_certifiates_info(host, port)
    -- Validations
    if ca_cert ~= nil then
        output[#output + 1] = check_issuer(server_cert, ca_cert)
        output[#output + 1] = check_signature(SERVER_CERT_FILENAME, CA_CERT_FILENAME)
    else
        -- If there is no CA certificate, we check if the certificate is self-signed
        output[#output + 1] = check_self_signed_cert(server_cert)
        -- Check the signature of the self-signed certificate
        output[#output + 1] = check_signature(SERVER_CERT_FILENAME, SERVER_CERT_FILENAME)
    end
    local valid = check_validity(server_cert)
    
    if ca_cert ~= nil then
        valid = check_validity(ca_cert)
    end

    if valid then
        output[#output + 1] = "The certificate is within its valid date range"
    else
        output[#output + 1] = "WARNING: The certificate is not within it's valid range"
    end

    local correct_alt_name = ckeck_alternative_name(server_cert, host)
    if correct_alt_name ~= nil then
        if correct_alt_name then
            output[#output + 1] = "The Subject Alternative Name matches the host name"
        else
            output[#output + 1] = "WARNING: The Subject Alternative Name does not match the host name"
        end
    end

    local in_blacklist, entry = is_in_blacklist(blacklist, server_cert)

    if in_blacklist then
        output[#output + 1] = "WARNING: Certificate's name was found in the blacklist!"
        output[#output + 1] = "\t Certificate \'" .. entry.name .. "\' reported on " .. entry.date .. " with \'" .. entry.severity .. "\' severity"
    end
    
   
    
    -- Enhanced functionality
    if server_cert.pubkey.bits < 2048 then
        output[#output + 1] = "WARNING: The key length of public key is less than 2048 bits"
    end

    
    -- Delete PEM files as they are not longer needed
    remove_files()

    output[#output + 1] = print_certificate(server_cert)

    return table.concat(output, "\n")
    

end
