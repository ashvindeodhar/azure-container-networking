****************************     getcompartmentwithnc    ****************************************
With this API, CNS returns the compartment ID for the specified NC ID.

$url= "<CNS-Endpoint>/network/getcompartmentwithnc?ncid=170e7a01-a4da-4851-cea5-08589a449645"
$c = Invoke-WebRequest -Uri $url -Method Get
$c.content