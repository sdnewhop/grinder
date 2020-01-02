local shortport = require "shortport"

portrule = shortport.http

action = function(host, port)
    output = "Test NSE script for host " .. host.ip
    return output
end