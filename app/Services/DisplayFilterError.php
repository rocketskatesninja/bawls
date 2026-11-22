<?php

namespace App\Services;

use InvalidArgumentException;

/** A display filter that doesn't parse, with where in the text it went wrong. */
class DisplayFilterError extends InvalidArgumentException
{
    public function __construct(string $message, public readonly int $position)
    {
        parent::__construct($message);
    }
}
