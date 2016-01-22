<?php
namespace Honeypot;

use DateTime;

class Address
{

    const TRUSTED = 0;
    const SUSPICIOUS = 1;
    const HARVESTER = 2;
    const SPAMMER = 4;

    const UNKNOWN = 0;
    const ALTAVISTA = 1;
    const ASK = 2;
    const BAIDU = 3;
    const EXCITE = 4;
    const GOOGLE = 5;
    const LOOKSMART = 6;
    const LYCOS = 7;
    const MSN = 8;
    const YAHOO = 9;
    const CUIL = 10;
    const INFOSEEK = 11;
    const MISCELLANEOUS = 12;

    /**
     * The IP address.
     *
     * @var string
     */
    protected $value;

    /**
     * @var
     */
    protected $lastSeen;

    /**
     * Threat score.
     *
     * @var
     * @see https://www.projecthoneypot.org/threat_info.php
     */
    protected $threatScore;

    /**
     * Type of visitor.
     *
     * @var string[]
     */
    protected $visitorType;

    /**
     * Address constructor.
     *
     * @param string $value
     * @param int $lastSeen
     * @param int $threatScore
     * @param int $visitorType
     */
    public function __construct($value, $lastSeen, $threatScore, $visitorType)
    {
        $this->value = $value;
        $this->threatScore = $threatScore;
        $this->lastSeen = new DateTime("-$lastSeen days");
        $this->visitorType = $this->resolveType($visitorType);
    }

    /**
     * @param int $type
     * @return array
     */
    protected function resolveType($type)
    {
        $types = [
            self::TRUSTED,
            self::SUSPICIOUS,
            self::HARVESTER,
            self::SPAMMER
        ];

        if (in_array($type, $types)) {
            return [$type];
        }

        $result = [];
        foreach (array_reverse(array_combine($types, $types)) as $k) {
            if ($type && $k <= $type) {
                $type -= $k;
                $result[] = $k;
            }
        }
        return $result;
    }

    /**
     * @param string $name
     * @return mixed
     */
    public function __get($name)
    {
        return $this->{$name};
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->value;
    }
}
