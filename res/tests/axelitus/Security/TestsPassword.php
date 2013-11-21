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

use axelitus\Security\Password;
use axelitus\Base\String;

/**
 * Class TestsPassword
 *
 * @package axelitus\Security\Tests
 */
class TestsPassword extends TestCase
{
    protected $password;
    protected $salt;
    protected $saltedHash;

    public function setUp()
    {
        $this->password = 'JonSnow<3Ygritte';
        $this->hash = 'e66deaff15a5d7732d041b4f4bd5da1cc0c27474';
        $this->salt = 'Longclaw';
        $this->saltedHash = $this->salt.'$'.$this->hash;
    }

    public function test_secure()
    {
        $saltedHash = Password::secure($this->password, $this->salt);
        $this->assertEquals($this->saltedHash, $saltedHash);

        $pos = String::pos($saltedHash, '$');
        $salt = String::sub($saltedHash, 0, $pos);
        $this->assertEquals($this->salt, $salt);
    }

    /**
     * @depends test_secure
     */
    public function test_validateSecureSalted()
    {
        $this->assertTrue(Password::validateSecureSalted($this->password, $this->saltedHash));
    }
}
