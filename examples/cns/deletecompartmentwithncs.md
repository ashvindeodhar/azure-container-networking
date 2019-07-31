**************************** deletecompartmentwithncs ****************************************
In this API call, the caller should pass the compartment ID received with createcompartmentwithncs.
This call will delete the compartment along with the NCs inside it.

$url= "<CNS-Endpoint>/network/deletecompartmentwithncs"
$nodeInfo = @{CompartmentID=4}
$nodeInfoJS = ConvertTo-Json $nodeInfo
$c = Invoke-WebRequest -Uri $url -Method Delete -Body $nodeInfoJS
$c.content