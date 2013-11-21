<?php
/**
 * Part of composer package: axelitus/security
 *
 * @package     axelitus\Security
 * @version     0.1
 * @author      Axel Pardemann (axelitusdev@gmail.com)
 * @license     MIT License
 * @copyright   2013 - Axel Pardemann
 * @link        http://axelitus.mx/projects/axelitus/security
 */

namespace axelitus\Security\Tests;

use axelitus\Security\Hash;
use axelitus\Security\HashAlgorithm;

/**
 * Class TestsHash
 *
 * @package axelitus\Security\Tests
 */
class TestsHash extends TestCase
{
    protected $data;

    public function setUp()
    {
        $this->data = 'Winter is coming!';
    }

    public function test_md5()
    {
        $expected = md5($this->data);
        $output = Hash::calculate($this->data, HashAlgorithm::MD5);
        $this->assertEquals($expected, $output);
    }

    public function test_sha1()
    {
        $expected = sha1($this->data);
        $output = Hash::calculate($this->data, HashAlgorithm::SHA1);
        $this->assertEquals($expected, $output);
    }

    public function test_crc32b()
    {
        // @see The warning in http://php.net/manual/en/function.crc32.php
        $expected = dechex(crc32($this->data));
        $output = Hash::calculate($this->data, HashAlgorithm::CRC32B);
        $this->assertEquals($expected, $output);
    }
}
