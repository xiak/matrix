[CmdletBinding()]
param(
    [string]$SourceUrl = 'https://cloud.tencent.com/document/product/598/10583',
    [string]$OutputPath = (Join-Path ([System.IO.Path]::GetTempPath()) 'matrix-tencent-cam-content-inventory.json'),
    [ValidateRange(1, 4)]
    [int]$ThrottleLimit = 1,
    [ValidateRange(0, 10000)]
    [int]$DelayMilliseconds = 900,
    [ValidateRange(1, 5)]
    [int]$RetryCount = 3,
    [ValidateRange(0, 10000)]
    [int]$PageLimit = 0,
    [switch]$Resume
)

$ErrorActionPreference = 'Stop'

function Get-HydrationData {
    param([Parameter(Mandatory)][string]$Html)

    $pattern = 'window\.__staticRouterHydrationData = JSON\.parse\("(?<encoded>.*?)"\);'
    $match = [regex]::Match(
        $Html,
        $pattern,
        [System.Text.RegularExpressions.RegexOptions]::Singleline
    )
    if (-not $match.Success) {
        throw 'Navigation hydration payload was not found.'
    }

    $json = [System.Text.Json.JsonSerializer]::Deserialize[string](
        '"' + $match.Groups['encoded'].Value + '"'
    )
    return $json | ConvertFrom-Json -Depth 100
}

$existingInventory = $null
if ($Resume -and (Test-Path -LiteralPath $OutputPath)) {
    $existingInventory = Get-Content -Raw -Encoding utf8 -LiteralPath $OutputPath |
        ConvertFrom-Json -Depth 100
}

function Invoke-PageRequest {
    param([Parameter(Mandatory)][string]$Url)

    $lastError = $null
    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        try {
            if ($DelayMilliseconds -gt 0) {
                Start-Sleep -Milliseconds $DelayMilliseconds
            }
            return (Invoke-WebRequest -UseBasicParsing -TimeoutSec 45 $Url).Content
        } catch {
            $lastError = $_
            if ($attempt -lt $RetryCount) {
                Start-Sleep -Milliseconds ($DelayMilliseconds * $attempt)
            }
        }
    }
    throw $lastError
}

$catalogue = $null
try {
    $sourceHtml = Invoke-PageRequest -Url $SourceUrl
    $sourceData = Get-HydrationData -Html $sourceHtml
    $catalogue = $sourceData.loaderData.product.data.sidebar.catalogue.list
} catch {
    if ($null -eq $existingInventory -or @($existingInventory.Pages).Count -eq 0) {
        throw
    }
}

$pages = [System.Collections.Generic.List[object]]::new()
$script:pageOrder = 0

function Add-Page {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Ancestors
    )

    $path = @($Ancestors) + @([string]$Node.title)
    if ($Node.type -eq 'page') {
        $url = if ($Node.link -match '^https?://') {
            [string]$Node.link
        } else {
            "https://cloud.tencent.com$($Node.link)"
        }
        $pages.Add([pscustomobject]@{
            Order = $script:pageOrder
            ID = [string]$Node.id
            TopLevel = $path[0]
            Path = $path
            Title = [string]$Node.title
            Url = $url
        })
        $script:pageOrder++
    }

    foreach ($child in @($Node.children)) {
        if ($null -ne $child) {
            Add-Page -Node $child -Ancestors $path
        }
    }
}

if ($null -ne $catalogue) {
    foreach ($node in $catalogue) {
        Add-Page -Node $node -Ancestors @()
    }
} else {
    foreach ($page in @($existingInventory.Pages | Sort-Object Order)) {
        $pages.Add([pscustomobject]@{
            Order = [int]$page.Order
            ID = [string]$page.ID
            TopLevel = [string]$page.TopLevel
            Path = @($page.Path)
            Title = [string]$page.NavigationTitle
            Url = [string]$page.Url
        })
    }
}

if ($PageLimit -gt 0) {
    $pages = @($pages | Select-Object -First $PageLimit)
}

$completedPages = [System.Collections.Generic.List[object]]::new()
$completedIDs = [System.Collections.Generic.HashSet[string]]::new()
$existingByID = [System.Collections.Generic.Dictionary[string, object]]::new()
if ($null -ne $existingInventory) {
    foreach ($page in @($existingInventory.Pages)) {
        $existingByID[[string]$page.ID] = $page
    }
}
foreach ($navigationPage in @($pages)) {
    if ($existingByID.ContainsKey([string]$navigationPage.ID)) {
        $cachedPage = $existingByID[[string]$navigationPage.ID]
        if (
            $null -eq $cachedPage.Error -and
            -not [string]::IsNullOrWhiteSpace([string]$cachedPage.BodySHA256)
        ) {
            $completedPages.Add([pscustomobject]@{
                Order = [int]$navigationPage.Order
                ID = [string]$navigationPage.ID
                TopLevel = [string]$navigationPage.TopLevel
                Path = @($navigationPage.Path)
                NavigationTitle = [string]$navigationPage.Title
                ArticleTitle = [string]$cachedPage.ArticleTitle
                Url = [string]$navigationPage.Url
                Description = [string]$cachedPage.Description
                UpdatedAt = [string]$cachedPage.UpdatedAt
                Headings = @($cachedPage.Headings)
                ImageUrls = @($cachedPage.ImageUrls)
                ImageCount = [int]$cachedPage.ImageCount
                TableCount = [int]$cachedPage.TableCount
                CodeBlockCount = [int]$cachedPage.CodeBlockCount
                TextLength = [int]$cachedPage.TextLength
                TextPreview = [string]$cachedPage.TextPreview
                BodySHA256 = [string]$cachedPage.BodySHA256
                Error = $null
            })
            [void]$completedIDs.Add([string]$navigationPage.ID)
        }
    }
}

$pendingPages = @($pages | Where-Object { -not $completedIDs.Contains([string]$_.ID) })
$newlyScannedPages = $pendingPages | ForEach-Object -Parallel {
    $page = $_
    $ProgressPreference = 'SilentlyContinue'
    $lastError = $null
    for ($attempt = 1; $attempt -le $using:RetryCount; $attempt++) {
        try {
            if ($using:DelayMilliseconds -gt 0) {
                Start-Sleep -Milliseconds $using:DelayMilliseconds
            }
            $html = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 45 $page.Url).Content
            $pattern = 'window\.__staticRouterHydrationData = JSON\.parse\("(?<encoded>.*?)"\);'
            $match = [regex]::Match(
                $html,
                $pattern,
                [System.Text.RegularExpressions.RegexOptions]::Singleline
            )
            if (-not $match.Success) {
                throw 'Article hydration payload was not found.'
            }
            $json = [System.Text.Json.JsonSerializer]::Deserialize[string](
                '"' + $match.Groups['encoded'].Value + '"'
            )
            $data = $json | ConvertFrom-Json -Depth 100
            $content = $data.loaderData.'product-article'.data.article.content
            if ($null -eq $content) {
                throw 'Article content was not found.'
            }

            $body = [string]$content.body
            $plainText = [regex]::Replace(
                $body,
                '<(?:script|style)\b[^>]*>.*?</(?:script|style)>',
                ' ',
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                    [System.Text.RegularExpressions.RegexOptions]::Singleline
            )
            $plainText = [regex]::Replace($plainText, '<[^>]+>', ' ')
            $plainText = [System.Net.WebUtility]::HtmlDecode($plainText)
            $plainText = [regex]::Replace($plainText, '\s+', ' ').Trim()

            $headings = @(
                [regex]::Matches(
                    $body,
                    '<h(?<level>[1-6])\b[^>]*>(?<text>.*?)</h\k<level>>',
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                        [System.Text.RegularExpressions.RegexOptions]::Singleline
                ) | ForEach-Object {
                    $heading = [regex]::Replace($_.Groups['text'].Value, '<[^>]+>', ' ')
                    $heading = [System.Net.WebUtility]::HtmlDecode($heading)
                    [pscustomobject]@{
                        Level = [int]$_.Groups['level'].Value
                        Text = [regex]::Replace($heading, '\s+', ' ').Trim()
                    }
                }
            )

            $imageUrls = @(
                [regex]::Matches(
                    $body,
                    '<img\b[^>]*(?:src|data-src)=["''](?<url>[^"'']+)["''][^>]*>',
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
                ) | ForEach-Object {
                    [System.Net.WebUtility]::HtmlDecode($_.Groups['url'].Value)
                } | Sort-Object -Unique
            )

            [pscustomobject]@{
                Order = [int]$page.Order
                ID = [string]$page.ID
                TopLevel = [string]$page.TopLevel
                Path = @($page.Path)
                NavigationTitle = [string]$page.Title
                ArticleTitle = [string]$content.title
                Url = [string]$page.Url
                Description = [string]$content.description
                UpdatedAt = [string]$content.recentReleaseTime
                Headings = $headings
                ImageUrls = $imageUrls
                ImageCount = $imageUrls.Count
                TableCount = [regex]::Matches(
                    $body,
                    '<table\b',
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
                ).Count
                CodeBlockCount = [regex]::Matches(
                    $body,
                    '<(?:pre|code)\b',
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
                ).Count
                TextLength = $plainText.Length
                TextPreview = $plainText.Substring(0, [Math]::Min(800, $plainText.Length))
                BodySHA256 = [Convert]::ToHexString(
                    [System.Security.Cryptography.SHA256]::HashData(
                        [System.Text.Encoding]::UTF8.GetBytes($body)
                    )
                ).ToLowerInvariant()
                Error = $null
            }
            $lastError = $null
            break
        } catch {
            $lastError = $_
            if ($attempt -lt $using:RetryCount) {
                Start-Sleep -Milliseconds ($using:DelayMilliseconds * $attempt)
            }
        }
    }

    if ($null -ne $lastError) {
        [pscustomobject]@{
            Order = [int]$page.Order
            ID = [string]$page.ID
            TopLevel = [string]$page.TopLevel
            Path = @($page.Path)
            NavigationTitle = [string]$page.Title
            ArticleTitle = $null
            Url = [string]$page.Url
            Description = $null
            UpdatedAt = $null
            Headings = @()
            ImageUrls = @()
            ImageCount = 0
            TableCount = 0
            CodeBlockCount = 0
            TextLength = 0
            TextPreview = $null
            BodySHA256 = $null
            Error = $lastError.Exception.Message
        }
    }
} -ThrottleLimit $ThrottleLimit

$scannedPages = @($completedPages) + @($newlyScannedPages) | Sort-Object Order

$inventory = [ordered]@{
    Source = $SourceUrl
    ScannedAt = (Get-Date).ToUniversalTime().ToString('o')
    PageCount = $pages.Count
    SuccessCount = @($scannedPages | Where-Object { $null -eq $_.Error }).Count
    FailureCount = @($scannedPages | Where-Object { $null -ne $_.Error }).Count
    Pages = @($scannedPages)
}

$outputDirectory = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    throw "Output directory does not exist: $outputDirectory"
}

$serialized = $inventory | ConvertTo-Json -Depth 12
[System.IO.File]::WriteAllText(
    $OutputPath,
    $serialized,
    [System.Text.UTF8Encoding]::new($false)
)

[pscustomobject]@{
    Output = (Resolve-Path $OutputPath).Path
    Pages = $inventory.PageCount
    Success = $inventory.SuccessCount
    Failed = $inventory.FailureCount
    WithImages = @($scannedPages | Where-Object ImageCount -gt 0).Count
}
