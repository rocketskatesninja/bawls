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

    /**
     * The error as the filter bar reads it: what is wrong, and where.
     *
     * @return array{message: string, at: int}
     */
    public function toArray(): array
    {
        return ['message' => $this->getMessage(), 'at' => $this->position];
    }
}
