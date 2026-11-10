<?php

declare(strict_types=1);

use PhpCsFixer\Config;
use PhpCsFixer\Finder;

$finder = Finder::create()
    ->in([__DIR__.'/src', __DIR__.'/tests']);

return (new Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@PhpCsFixer' => true,
        '@PhpCsFixer:risky' => true,
        '@PHP8x4Migration' => true,
        'declare_strict_types' => true,
        'ordered_imports' => ['sort_algorithm' => 'alpha'],
        'no_unused_imports' => true,
        'concat_space' => ['spacing' => 'none'],
        'single_line_empty_body' => true,
        'trailing_comma_in_multiline' => ['elements' => ['arguments', 'array_destructuring', 'arrays', 'match', 'parameters']],
        'phpdoc_align' => false,
        'phpdoc_summary' => false,
        'yoda_style' => false,
        'php_unit_test_class_requires_covers' => false, // coverage targets are declared with #[Covers*] attributes
    ])
    ->setFinder($finder);
