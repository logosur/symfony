<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Scheduler\Tests\Fixtures;

use Symfony\Component\Scheduler\Attribute\AsCronTask;

class EveryMinuteAttributeTasks
{
    #[AsCronTask('* * * * *')]
    public function first(): void
    {
    }

    #[AsCronTask('* * * * *')]
    public function second(): void
    {
    }
}
