[CmdletBinding()]
param(
    [string]$SourceUrl = 'https://cloud.tencent.com/document/product/598/10583',
    [string]$OutputPath = (Join-Path $PSScriptRoot 'tencent-cam-navigation.md')
)

$ErrorActionPreference = 'Stop'
$html = (Invoke-WebRequest -UseBasicParsing $SourceUrl).Content
$pattern = 'window\.__staticRouterHydrationData = JSON\.parse\("(?<encoded>.*?)"\);'
$match = [regex]::Match($html, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $match.Success) {
    throw "Navigation payload not found at $SourceUrl"
}

$json = [System.Text.Json.JsonSerializer]::Deserialize[string](
    '"' + $match.Groups['encoded'].Value + '"'
)
$data = $json | ConvertFrom-Json -Depth 100
$catalogue = $data.loaderData.product.data.sidebar.catalogue.list
$script:pageCount = 0
$script:directoryCount = 0
$script:maxDepth = 0
$script:lines = [System.Collections.Generic.List[string]]::new()

function Add-Node {
    param([Parameter(Mandatory)]$Node, [Parameter(Mandatory)][int]$Depth)

    $script:maxDepth = [Math]::Max($script:maxDepth, $Depth)
    $indent = '  ' * $Depth
    $title = $Node.title.Replace('[', '\[').Replace(']', '\]')

    if ($Node.type -eq 'page') {
        $script:pageCount++
        $url = if ($Node.link -match '^https?://') { $Node.link } else { "https://cloud.tencent.com$($Node.link)" }
        $script:lines.Add("$indent- [$title]($url) <!-- page:$($Node.id) -->")
    } else {
        $script:directoryCount++
        $pdf = if ($Node.pdfUrl) { " · [官方合并 PDF]($($Node.pdfUrl))" } else { '' }
        $script:lines.Add("$indent- $title$pdf <!-- directory:$($Node.id) -->")
    }

    foreach ($child in @($Node.children)) {
        if ($null -ne $child) { Add-Node -Node $child -Depth ($Depth + 1) }
    }
}

foreach ($node in $catalogue) { Add-Node -Node $node -Depth 0 }

$header = @(
    '# 腾讯云访问管理完整来源导航'
    ''
    '> 本文件仅记录公开文档的标题、父子层级与原始链接，用于验证产品能力抽象没有遗漏来源栏目。'
    ''
    '- 来源：[腾讯云访问管理](https://cloud.tencent.com/document/product/598)'
    "- 抓取日期：$(Get-Date -Format 'yyyy-MM-dd')"
    "- 一级节点：$($catalogue.Count)"
    "- 目录节点：$script:directoryCount"
    "- 页面节点：$script:pageCount"
    "- 总节点：$($script:directoryCount + $script:pageCount)"
    "- 最大层级：$($script:maxDepth + 1)"
    ''
    '## 完整左侧导航树'
    ''
)

$outputDirectory = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    throw "Output directory does not exist: $outputDirectory"
}

$content = ($header + $script:lines + '') -join "`n"
[System.IO.File]::WriteAllText(
    (Join-Path (Resolve-Path $outputDirectory).Path (Split-Path -Leaf $OutputPath)),
    $content,
    [System.Text.UTF8Encoding]::new($false)
)

$written = Get-Content -Raw -Encoding utf8 $OutputPath
$pages = ([regex]::Matches($written, '<!-- page:\d+ -->')).Count
$directories = ([regex]::Matches($written, '<!-- directory:\d+ -->')).Count
$ids = [regex]::Matches($written, '<!-- (?:page|directory):(\d+) -->') |
    ForEach-Object { $_.Groups[1].Value }

if ($pages -ne $script:pageCount -or $directories -ne $script:directoryCount) {
    throw 'Written node counts differ from source navigation counts.'
}
if (($ids | Sort-Object -Unique).Count -ne $ids.Count) {
    throw 'Duplicate source node IDs found.'
}

[pscustomobject]@{
    Output = (Resolve-Path $OutputPath).Path
    TopLevel = $catalogue.Count
    Directories = $directories
    Pages = $pages
    Total = $directories + $pages
    Levels = $script:maxDepth + 1
}
