<?php

declare(strict_types=1);

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');

function e(mixed $value): string
{
    return htmlspecialchars(
        (string)$value,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}

function readReport(string $file): ?array
{
    if (!is_file($file)) {
        return null;
    }

    $raw = file_get_contents($file);

    if ($raw === false || strlen($raw) > 25 * 1024 * 1024) {
        return null;
    }

    $decoded = json_decode(
        $raw,
        true,
        512,
        JSON_THROW_ON_ERROR
    );

    return is_array($decoded) ? $decoded : null;
}

function getPath(array $data, array $path, mixed $default = null): mixed
{
    $current = $data;

    foreach ($path as $key) {
        if (!is_array($current) || !array_key_exists($key, $current)) {
            return $default;
        }

        $current = $current[$key];
    }

    return $current;
}

function formatBytes(int|float $bytes): string
{
    if ($bytes < 1024) {
        return $bytes . ' B';
    }

    if ($bytes < 1024 ** 2) {
        return number_format($bytes / 1024, 2) . ' KB';
    }

    if ($bytes < 1024 ** 3) {
        return number_format($bytes / (1024 ** 2), 2) . ' MB';
    }

    return number_format($bytes / (1024 ** 3), 2) . ' GB';
}

function severityForEntropy(float $entropy): string
{
    if ($entropy >= 7.5) {
        return 'High';
    }

    if ($entropy >= 7.0) {
        return 'Elevated';
    }

    return 'Normal';
}

function safeJsonEncode(mixed $data): string
{
    return json_encode(
        $data,
        JSON_PRETTY_PRINT |
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE
    ) ?: '{}';
}

$report = null;
$error = null;

if (isset($_GET['report'])) {

    $requested = (string)$_GET['report'];

    /*
     * Only allow simple JSON filenames from the local reports directory.
     * Prevents arbitrary filesystem traversal.
     */
    if (
        !preg_match(
            '/^[a-zA-Z0-9._-]+\.json$/',
            $requested
        )
    ) {
        $error = 'Invalid report filename.';
    } else {

        $base =
            realpath(
                __DIR__ . DIRECTORY_SEPARATOR . '..' .
                DIRECTORY_SEPARATOR . 'reports'
            );

        if ($base === false) {
            $error = 'Reports directory does not exist.';
        } else {

            $candidate =
                realpath(
                    $base .
                    DIRECTORY_SEPARATOR .
                    $requested
                );

            if (
                $candidate === false ||
                !str_starts_with(
                    $candidate,
                    $base . DIRECTORY_SEPARATOR
                )
            ) {
                $error = 'Report could not be located.';
            } else {

                try {
                    $report =
                        readReport($candidate);

                    if ($report === null) {
                        $error = 'Invalid or unreadable JSON report.';
                    }

                } catch (Throwable $exception) {
                    $error = 'JSON parsing failed.';
                }
            }
        }
    }
}

$reportDirectory =
    realpath(
        __DIR__ . DIRECTORY_SEPARATOR . '..' .
        DIRECTORY_SEPARATOR . 'reports'
    );

$reports = [];

if ($reportDirectory !== false) {

    $entries =
        scandir($reportDirectory);

    if ($entries !== false) {

        foreach ($entries as $entry) {

            if (
                $entry === '.' ||
                $entry === '..'
            ) {
                continue;
            }

            if (
                preg_match(
                    '/^[a-zA-Z0-9._-]+\.json$/',
                    $entry
                )
            ) {
                $reports[] = $entry;
            }
        }
    }
}

sort($reports, SORT_NATURAL | SORT_FLAG_CASE);

$fileName =
    getPath(
        $report ?? [],
        ['file', 'name'],
        'Unknown'
    );

$fileSize =
    getPath(
        $report ?? [],
        ['file', 'size'],
        0
    );

$sha256 =
    getPath(
        $report ?? [],
        ['file', 'sha256'],
        'N/A'
    );

$md5 =
    getPath(
        $report ?? [],
        ['file', 'md5'],
        'N/A'
    );

$sha1 =
    getPath(
        $report ?? [],
        ['file', 'sha1'],
        'N/A'
    );

$sections =
    getPath(
        $report ?? [],
        ['pe', 'sections'],
        getPath(
            $report ?? [],
            ['pe', 'sections_info'],
            []
        )
    );

if (!is_array($sections)) {
    $sections = [];
}

$indicators =
    getPath(
        $report ?? [],
        ['indicators'],
        []
    );

if (!is_array($indicators)) {
    $indicators = [];
}

$warnings =
    getPath(
        $report ?? [],
        ['warnings'],
        []
    );

if (!is_array($warnings)) {
    $warnings = [];
}

$strings =
    getPath(
        $report ?? [],
        ['strings'],
        []
    );

if (!is_array($strings)) {
    $strings = [];
}

?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1"
>

<title>Malware Research Suite</title>

<style>

:root {
    color-scheme: dark;

    --background: #08090c;
    --panel: #101218;
    --panel2: #151821;
    --border: #252936;
    --text: #e6e8ee;
    --muted: #9298a7;
    --accent: #8ab4ff;
    --warning: #e8b65b;
    --danger: #ff7777;
    --good: #78d6a2;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: var(--background);
    color: var(--text);
    font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}

header {
    border-bottom: 1px solid var(--border);
    padding: 24px;
    background: #0b0d12;
}

header h1 {
    margin: 0 0 6px;
    font-size: 24px;
}

header p {
    margin: 0;
    color: var(--muted);
}

main {
    max-width: 1400px;
    margin: auto;
    padding: 24px;
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(240px, 1fr)
        );
    gap: 14px;
}

.card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px;
    margin-bottom: 18px;
}

.card h2 {
    margin-top: 0;
    font-size: 17px;
}

.metric {
    font-size: 20px;
    font-weight: 700;
    overflow-wrap: anywhere;
}

.label {
    color: var(--muted);
    font-size: 12px;
    margin-bottom: 7px;
    text-transform: uppercase;
    letter-spacing: .05em;
}

.hash {
    font-family: monospace;
    font-size: 12px;
    overflow-wrap: anywhere;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    padding: 10px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: top;
}

th {
    color: var(--muted);
    font-size: 12px;
}

code,
pre {
    font-family:
        "Cascadia Code",
        "JetBrains Mono",
        Consolas,
        monospace;
}

pre {
    background: #090b0f;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 15px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
}

select,
button {
    background: var(--panel2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 9px 12px;
}

button {
    cursor: pointer;
}

.warning {
    color: var(--warning);
}

.danger {
    color: var(--danger);
}

.good {
    color: var(--good);
}

.muted {
    color: var(--muted);
}

.tag {
    display: inline-block;
    border: 1px solid var(--border);
    background: var(--panel2);
    border-radius: 999px;
    padding: 4px 8px;
    margin: 3px;
    font-family: monospace;
    font-size: 12px;
}

.empty {
    color: var(--muted);
    padding: 15px 0;
}

@media (max-width: 700px) {

    main {
        padding: 14px;
    }

    th,
    td {
        font-size: 12px;
    }

}

</style>
</head>

<body>

<header>

<h1>Malware Research Suite</h1>

<p>
    Local static-analysis report viewer
    — samples are not executed by this application.
</p>

</header>

<main>

<div class="card">

<h2>Report</h2>

<form method="get">

<select name="report">

<option value="">
    Select a JSON report
</option>

<?php foreach ($reports as $item): ?>

<option
    value="<?= e($item) ?>"
    <?= (
        isset($_GET['report']) &&
        $_GET['report'] === $item
    ) ? 'selected' : '' ?>
>
    <?= e($item) ?>
</option>

<?php endforeach; ?>

</select>

<button type="submit">
    Open report
</button>

</form>

</div>

<?php if ($error !== null): ?>

<div class="card">

<h2 class="danger">Error</h2>

<p><?= e($error) ?></p>

</div>

<?php endif; ?>

<?php if ($report !== null): ?>

<div class="grid">

<div class="card">

<div class="label">File</div>

<div class="metric">
    <?= e($fileName) ?>
</div>

<p class="muted">
    <?= e(formatBytes((int)$fileSize)) ?>
</p>

</div>

<div class="card">

<div class="label">SHA-256</div>

<div class="hash">
    <?= e($sha256) ?>
</div>

</div>

<div class="card">

<div class="label">PE</div>

<div class="metric">

<?= e(
    getPath(
        $report,
        ['pe', 'is_pe'],
        false
    ) ? 'Detected' : 'Not detected'
) ?>

</div>

</div>

<div class="card">

<div class="label">Static Indicators</div>

<div class="metric">
    <?= count($warnings) ?>
</div>

</div>

</div>

<div class="card">

<h2>Hashes</h2>

<table>

<tr>
    <th>Algorithm</th>
    <th>Digest</th>
</tr>

<tr>
    <td>MD5</td>
    <td class="hash"><?= e($md5) ?></td>
</tr>

<tr>
    <td>SHA-1</td>
    <td class="hash"><?= e($sha1) ?></td>
</tr>

<tr>
    <td>SHA-256</td>
    <td class="hash"><?= e($sha256) ?></td>
</tr>

</table>

</div>

<div class="card">

<h2>PE Metadata</h2>

<table>

<tr>
    <th>Machine</th>
    <td>
        <?= e(getPath($report, ['pe', 'machine'], 'N/A')) ?>
    </td>
</tr>

<tr>
    <th>Sections</th>
    <td>
        <?= e(getPath($report, ['pe', 'sections'], 'N/A')) ?>
    </td>
</tr>

<tr>
    <th>Entry Point</th>
    <td>
        <?= e(getPath($report, ['pe', 'entry_point'], getPath($report, ['pe', 'entry_point_rva'], 'N/A'))) ?>
    </td>
</tr>

<tr>
    <th>Image Base</th>
    <td>
        <?= e(getPath($report, ['pe', 'image_base'], 'N/A')) ?>
    </td>
</tr>

<tr>
    <th>Image Size</th>
    <td>
        <?= e(getPath($report, ['pe', 'size_of_image'], 'N/A')) ?>
    </td>
</tr>

</table>

</div>

<div class="card">

<h2>Sections</h2>

<?php if (!$sections): ?>

<div class="empty">
    No section information available.
</div>

<?php else: ?>

<table>

<tr>
    <th>Name</th>
    <th>RVA</th>
    <th>Raw Size</th>
    <th>Entropy</th>
    <th>Assessment</th>
</tr>

<?php foreach ($sections as $section): ?>

<?php

$entropy =
    (float)($section['entropy'] ?? 0);

$assessment =
    severityForEntropy($entropy);

?>

<tr>

<td>
    <code>
        <?= e($section['name'] ?? 'unknown') ?>
    </code>
</td>

<td>
    <?= e(
        $section['virtual_address']
        ?? 'N/A'
    ) ?>
</td>

<td>
    <?= e(
        $section['raw_size']
        ?? 'N/A'
    ) ?>
</td>

<td>
    <?= number_format(
        $entropy,
        4
    ) ?>
</td>

<td class="<?= (
    $assessment === 'High'
        ? 'warning'
        : ''
) ?>">
    <?= e($assessment) ?>
</td>

</tr>

<?php endforeach; ?>

</table>

<?php endif; ?>

</div>

<div class="card">

<h2>Indicators</h2>

<?php

$indicatorFound = false;

foreach ($indicators as $category => $values):

    if (!is_array($values) || !$values) {
        continue;
    }

    $indicatorFound = true;

?>

<div>

<strong>
    <?= e($category) ?>
</strong>

<div>

<?php foreach ($values as $value): ?>

<span class="tag">
    <?= e($value) ?>
</span>

<?php endforeach; ?>

</div>

</div>

<?php endforeach; ?>

<?php if (!$indicatorFound): ?>

<div class="good">
    No indicators were reported.
</div>

<?php endif; ?>

</div>

<div class="card">

<h2>Warnings</h2>

<?php if (!$warnings): ?>

<div class="good">
    No parser or heuristic warnings.
</div>

<?php else: ?>

<?php foreach ($warnings as $warning): ?>

<div class="warning">
    [!] <?= e($warning) ?>
</div>

<?php endforeach; ?>

<?php endif; ?>

</div>

<div class="card">

<h2>Extracted Strings</h2>

<?php if (!$strings): ?>

<div class="empty">
    No strings available.
</div>

<?php else: ?>

<pre><?php
echo e(
    implode(
        PHP_EOL,
        array_slice($strings, 0, 1000)
    )
);
?></pre>

<?php endif; ?>

</div>

<div class="card">

<h2>Raw JSON</h2>

<pre><?= e(
    safeJsonEncode($report)
) ?></pre>

</div>

<div class="card">

<h2>Safety Status</h2>

<div class="good">
    Sample execution: NO
</div>

<div class="good">
    Network access by viewer: NO
</div>

<div class="good">
    Sample modification: NO
</div>

</div>

<?php endif; ?>

</main>

</body>
</html>
