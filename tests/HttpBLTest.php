<?php
namespace Honeypot\Test;

use Honeypot\Address;
use Honeypot\HttpBL;
use ReflectionClass;

class HttpBLTest extends \PHPUnit_Framework_TestCase
{
    protected static function getMethod($name)
    {
        $class = new ReflectionClass('Honeypot\HttpBL');
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method;
    }

    public function testFlip()
    {
        $flip = self::getMethod('flip');
        $class = new HttpBL('apikey');
        $result = $flip->invokeArgs($class, ['1.2.3.4']);
        $this->assertEquals('4.3.2.1', $result);
    }

    public function testHostname()
    {
        $hostname = self::getMethod('hostname');
        $class = new HttpBL('apikey');
        $result = $hostname->invokeArgs($class, ['1.2.3.4']);
        $this->assertEquals('apikey.4.3.2.1.dnsbl.httpbl.org', $result);
    }

    public function testQueryReturnsHostname()
    {
        $hostname = 'apikey.4.3.2.1.dnsbl.httpbl.org';
        $query = self::getMethod('query');
        $class = $this->getMock('Honeypot\HttpBL', ['send'], ['apikey']);
        $class->expects($this->once())
            ->method('send')
            ->with($hostname)
            ->will($this->returnValue($hostname));

        $result = $query->invokeArgs($class, [$hostname]);
        $this->assertFalse($result);
    }

    public function testQueryReturnsNxDomain()
    {
        $hostname = 'apikey.4.3.2.1.dnsbl.httpbl.org';
        $query = self::getMethod('query');
        $class = $this->getMock('Honeypot\HttpBL', ['send'], ['apikey']);
        $class->expects($this->once())
            ->method('send')
            ->with($hostname)
            ->will($this->returnValue('NXDOMAIN'));

        $result = $query->invokeArgs($class, [$hostname]);
        $this->assertFalse($result);
    }

    public function testQuery()
    {
        $hostname = 'apikey.4.3.2.1.dnsbl.httpbl.org';
        $query = self::getMethod('query');
        $class = $this->getMock('Honeypot\HttpBL', ['send'], ['apikey']);
        $class->expects($this->once())
            ->method('send')
            ->with($hostname)
            ->will($this->returnValue('127.10.3.4'));

        $result = $query->invokeArgs($class, [$hostname]);
        $expected = [
            'lastSeen' => 10,
            'threatScore' => 3,
            'visitorType' => 4,
        ];

        $this->assertEquals($expected, $result);
    }

    public function provideIsSafe()
    {
        return [
            [
                '127.0.0.1',
                ['age' => 60, 'risk' => 0, 'type' => Address::TRUSTED],
                [],
                true
            ],
            [
                '127.0.0.1',
                ['age' => 50, 'risk' => 0, 'type' => Address::TRUSTED],
                [],
                false
            ],
            [
                '127.0.0.1',
                ['age' => 50, 'risk' => 0, 'type' => Address::TRUSTED],
                ['rules' => [], 'strict' => false],
                true
            ],
            [
                '127.0.0.1',
                ['age' => 50, 'risk' => 0, 'type' => Address::SUSPICIOUS],
                ['rules' => ['age' => 40, 'type' => 4]],
                false
            ],
        ];
    }

    /**
     * @dataProvider provideIsSafe
     */
    public function testIsSafe($ip, array $address, array $args, $expected)
    {
        $address += [
            'age' => 60,
            'risk' => 0,
            'type' => Address::TRUSTED
        ];

        $args += [
            'rules' => [],
            'strict' => true,
        ];

        $address = new Address($ip, $address['age'], $address['risk'], $address['type']);
        $class = $this->getMock('Honeypot\HttpBL', ['address'], ['apikey']);
        $class->expects($this->once())
            ->method('address')
            ->with($ip)
            ->will($this->returnValue($address));

        $result = $class->isSafe($ip, $args['rules'], $args['strict']);
        $this->assertEquals($expected, $result);
    }

    public function provideAddress()
    {
        return [
            // search engine
            [
                '127.1.1.0',
                'visitorType',
                [Address::TRUSTED]
            ],

            // suspicious
            [
                '127.1.1.1',
                'visitorType',
                [Address::SUSPICIOUS]
            ],

            // harvester
            [
                '127.1.1.2',
                'visitorType',
                [Address::HARVESTER]
            ],

            // suspicious & harvester
            [
                '127.1.1.3',
                'visitorType',
                [Address::SUSPICIOUS, Address::HARVESTER]
            ],

            // comment spammer
            [
                '127.1.1.4',
                'visitorType',
                [Address::SPAMMER]
            ],

            // suspicious & comment spammer
            [
                '127.1.1.5',
                'visitorType',
                [Address::SUSPICIOUS, Address::SPAMMER]
            ],

            // harvester & comment spammer
            [
                '127.1.1.6',
                'visitorType',
                [Address::HARVESTER, Address::SPAMMER]
            ],

            // suspicious & harvester & comment spammer
            [
                '127.1.1.7',
                'visitorType',
                [Address::SUSPICIOUS, Address::HARVESTER, Address::SPAMMER]
            ],

            [
                '127.1.10.1',
                'threatScore',
                10
            ],

            [
                '127.1.20.1',
                'threatScore',
                20
            ],

            [
                '127.1.40.1',
                'threatScore',
                40
            ],

            [
                '127.1.80.1',
                'threatScore',
                80
            ],

            [
                '127.10.1.1',
                'lastSeen',
                new \DateTime('-10 days')
            ],

            [
                '127.20.1.1',
                'lastSeen',
                new \DateTime('-20 days')
            ],

            [
                '127.40.1.1',
                'lastSeen',
                new \DateTime('-40 days')
            ],

            [
                '127.80.1.1',
                'lastSeen',
                new \DateTime('-80 days')
            ],

        ];
    }

    /**
     * @group integration
     * @dataProvider provideAddress
     */
    public function testAddress($ip, $key, $expected)
    {
        if (!$apiKey = getenv('HTTPBL_APIKEY')) {
            $this->markTestSkipped(
                "A valid API key is required to run integration tests.\n" .
                "Use one by prepending the test command: `HTTPBL_APIKEY=xxxx phpunit`"
            );
        }

        $httpbl = new HttpBL($apiKey);

        $result = $httpbl->address($ip)->$key;

        if (!is_array($expected)) {
            $expected = [$expected];
        }

        if (!is_array($result)) {
            $result = [$result];
        }

        $this->assertEquals(count($expected), count($result));
        foreach ($expected as $e) {
            $this->assertTrue(in_array($e, $result));
        }
    }
}
