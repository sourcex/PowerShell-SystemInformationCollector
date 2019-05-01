function Get-SystemInformation
{
    $systemInformation = New-Object -TypeName PSObject

    $time = (Get-Date).ToUniversalTime()
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name CapturedDateTime -Value $time

    $serialNumber = (Get-CimInstance Win32_BIOS).SerialNumber
    $SMBIOSBIOSVersion = (Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name SerialNumber -Value $serialNumber
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name SMBIOSBIOSVersion -Value $SMBIOSBIOSVersion

    $chassisManufacturer = (Get-CimInstance win32_SystemEnclosure).Manufacturer
    $chassisModel =(Get-CimInstance win32_SystemEnclosure).Model
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name Chassis_Manufacturer -Value $chassisManufacturer
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name Chassis_Model -Value $chassisModel
    
    $systemManufacturer = (Get-CimInstance win32_ComputerSystem).Manufacturer
    $systemModel = (Get-CimInstance win32_ComputerSystem).Model
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name System_Manufacturer -Value $systemManufacturer
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name System_Model -Value $systemModel

    $videoCards = (Get-CimInstance Win32_VideoController | Select Name, DriverVersion, PNPDeviceID)
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name VideoAdapters -Value $videoCards

    $memory = Get-CimInstance Win32_PhysicalMemory | Select Manufacturer, Model, PartNumber, SerialNumber, Capacity, MaxVoltage
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name Memory -Value $memory

    $drives = Get-Disk | Select FriendlyName, SerialNumber, BusType, HealthStatus, OperationalStatus, Size, PartitionStyle, FirmwareVersion
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name Drives -Value $drives

    $networkAdapters = Get-NetAdapter | Select Name, MacAddress, DriverVersion
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name NetworkAdapters -Value $networkAdapters

    $windowsInfo = Get-CimInstance Win32_OperatingSystem | Select Caption, Version, OSArchitecture
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name OperatingSystem -Value $windowsInfo

    $currentUser = (Get-CimInstance win32_ComputerSystem).UserName
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name CurrentUser -Value $currentUser

    $assetTag = (Get-CimInstance Win32_SystemEnclosure).SMBIOSAssetTag
    Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name AssetTag -Value $assetTag

    $30Days = ((Get-Date).AddDays(-30))
    $bugChecks = Get-WinEvent -FilterHashtable @{Logname='System'; ID=@(1001); StartTime=$30Days} -ErrorAction SilentlyContinue
    if($bugChecks -ne $null)
    {
        Add-Member -InputObject $systemInformation -MemberType NoteProperty -Name BugChecks -Value $bugChecks
    }

    return $systemInformation | ConvertTo-Json
}
