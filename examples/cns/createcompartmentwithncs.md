**************************** createcompartmentwithncs ****************************************
In this API call, caller should pass one or more NC IDs already created on the node using DNC. 
Upon successful execution of this call, a network compartment will be created containing the
specified NCs. The result of the request would contain the compartment ID and message.
If the execution fails, no compartment will be created.

Request for multiple NCs in a compartment:

$url= "<CNS-Endpoint>/network/createcompartmentwithncs"
$ncids = @("170e7a01-a4da-4851-cea5-08589a449645", "171e7a01-a4da-4851-cea5-08589a449645")
$nodeInfo= @{NCIDs=$ncids}
$nodeInfoJS = ConvertTo-Json $nodeInfo
$c = Invoke-WebRequest -Uri $url -Method Post -Body $nodeInfoJS
$c.content


Request for single NC in a compartment:

$url= "<CNS-Endpoint>/network/createcompartmentwithncs"
$ncids = @("171e7a01-a4da-4851-cea5-08589a449645")
$nodeInfo= @{NCIDs=$ncids}
$nodeInfoJS = ConvertTo-Json $nodeInfo
$c = Invoke-WebRequest -Uri $url -Method Post -Body $nodeInfoJS
$c.content