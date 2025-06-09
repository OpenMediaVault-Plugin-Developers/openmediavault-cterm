<?php
 require_once("openmediavault/functions.inc");

\OMV\System\LogFileSpec::registerSpecification("omv-cterm", [       
    "filename" => "omv_cterm.log",         
    "filepath" => "/var/log/omv_cterm.log",         
    "regex" => "/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3} - ([^-]+) - ([^-]+) - (.*)$/",
    "columns" => [
        "date" => 1,
        "module" => 2,
        "level" => 3,
        "message" => 4
    ]
]);
