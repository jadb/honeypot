<?php
namespace Honeypot\Test;

use Honeypot\Quicklink;

class QuicklinkTest extends \PHPUnit_Framework_TestCase
{

    public function provideRender()
    {
        return [
            [1, 1],
            [4, 4],
            [9, 8],
        ];
    }

    /**
     * @dataProvider provideRender
     */
    public function testRender($count, $expected)
    {
        $result = explode('<a href="', (new Quicklink('http://foo'))->render($count));
        array_shift($result);
        $this->assertCount($expected, $result);
        foreach ($result as $link) {
            $this->assertEquals('http://foo', substr($link, 0, 10));
        }
    }
}
