<?php
namespace Honeypot;

class Quicklink
{
    private static $links = [
        '<a href="{{honeypot}}"></a>',
        '<!-- <a href="{{honeypot}}">{{text}}</a> -->',
        '<a href="{{honeypot}}"><!-- {{text}} --></a>',
        '<a href="{{honeypot}}" style="display:none">{{text}}</a>',
        '<a href="{{honeypot}}"><span style="display: none;">{{text}}</span></a>',
        '<a href="{{honeypot}}"><div style="height: 0px; width: 0px;"></div></a>',
        '<div style="display:none"><a href="{{honeypot}}">{{text}}</a></div>',
        '<div style="position: absolute; top: -250px; left: -250px;"><a href="{{honeypot}}">{{text}}</a></div>'
    ];
    
    public function __construct($honeypot)
    {
        $this->honeypot = $honeypot;
    }

    public function render($count = 1)
    {

        $total = count(static::$links);
        $length = rand(4, 16);
        $min = array(48, 65, 97);
        $max = array(57, 90, 122);
        $text = '';
        $stack = [];

        while (strlen($text) < $length) {
            $random = rand(0, 2);
            $text .= chr(rand($min[$random], $max[$random]));
        }

        if ($count > $total) {
            $count = $total;
        }

        if ($count !== 0) {
            $random = array_rand(static::$links, $count);
            $search = ['{{honeypot}}', '{{text}}'];
            $replace = [$this->honeypot, $text];
            foreach ((array)$random as $key) {
                $stack[] = str_replace($search, $replace, static::$links[$key]);
            }
        }

        return implode(' ', $stack);
    }
}
