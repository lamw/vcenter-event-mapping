$vcNames = "vcsa-01a.corp.local"

Connect-VIServer -Server $vcNames

$vcenterVersion = ($global:DefaultVIServer.ExtensionData.Content.About.ApiVersion)

$eventMgr = Get-View $global:DefaultVIServer.ExtensionData.Content.EventManager

$results = @()
foreach ($event in $eventMgr.Description.EventInfo) {
    if($event.key -eq "EventEx" -or $event.key -eq "ExtendedEvent") {
        #echo $event
        $eventId = ($event.FullFormat.toString()) -replace "\|.*",""
        $eventType = $event.key
    } else {
        $eventId = $event.key
        $eventType = "Standard"
    }
    $eventCategory = $event.Category
    $eventDescription = $event.Description

    $tmp = [PSCustomObject] @{
        EventId = $eventId;
        EventCategory = $eventCategory
        EventType = $eventType;
        EventDescription = $($eventDescription.Replace("<","").Replace(">",""));
    }

    $results += $tmp
}

Write-Host "Number of Events: $($results.count)"
$results | Sort-Object -Property EventId | ConvertTo-Csv | Out-File -FilePath vcenter-$vcenterVersion-events.csv