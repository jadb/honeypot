<?php
namespace Honeypot;

use Exception;

class HttpBL
{
    const HOST = 'dnsbl.httpbl.org';

    private $apiKey;

    public function __construct($apiKey)
    {
        $this->apiKey = $apiKey;
    }

    public function isSafe($ip, array $rules = [], $strict = true)
    {
        $rules += [
            'visitorType' => Address::TRUSTED,
            'lastSeen' => new \DateTime('-60 days'),
            'threatScore' => 2
        ];

        $address = $this->address($ip);

        $age = $address->lastSeen->diff($rules['lastSeen'])->d <= 0;
        $type = array_sum($address->visitorType) <= $rules['visitorType'];
        $risk = $address->threatScore <= $rules['threatScore'];

        return ($type && $age && $risk) || (!$strict && ($age || $type || $risk));
    }

    public function address($ip)
    {
        if (!$this->validate($ip)) {
            throw new Exception('Invalid IP address.');
        }

        $result = $this->query($this->hostname($ip));

        if (!$result) {
            $result = [
                'lastSeen' => 365,
                'threatScore' => 0,
                'visitorType' => 0,
            ];
        }

        return new Address($ip, $result['lastSeen'], $result['threatScore'], $result['visitorType']);
    }

    protected function validate($ip)
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE);
    }

    protected function flip($ip)
    {
        return implode('.', array_reverse(explode('.', $ip)));
    }

    protected function query($hostname)
    {
        $response = $this->send($hostname);

        if (in_array($response, [$hostname, 'NXDOMAIN'])) {
            return false;
        }

        list($result, $lastSeen, $threatScore, $visitorType) = explode('.', $response);

        if ((int)$result !== 127) {
            throw new Exception(sprintf("Malformed http:BL query ($hostname)"));
        }

        return [
            'lastSeen' => (int)$lastSeen,
            'threatScore' => (int)$threatScore,
            'visitorType' => (int)$visitorType,
        ];
    }

    protected function send($hostname)
    {
        return gethostbyname($hostname);
    }

    protected function hostname($address)
    {
        return implode('.', [$this->apiKey, $this->flip($address), self::HOST]);
    }
}
