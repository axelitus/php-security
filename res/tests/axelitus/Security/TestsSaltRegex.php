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

use axelitus\Security\SaltRegex;
use axelitus\Security\SaltType;

/**
 * Class TestsSaltRegex
 *
 * @package axelitus\Security\Tests
 */
class TestsSaltRegex extends TestCase
{
    /**
     * Tests the examples from the crypt function documentation.
     * Note: some of the salts where changed because the regex patterns of the SaltRegex class are more
     *       restrictive than the examples shown in the documentation. The length is a strict rule for the
     *       SaltRegex class. Examples slightly modified: blowfish, sha256, sha512.
     */
    public function test_exampleMatches()
    {
        $this->assertEquals(true, SaltRegex::matchStdDes('rl'), "Standard DES salt regex match");
        $this->assertEquals(true, SaltRegex::matchExtDes('_J9..rasm'), "Extended DES salt regex match");
        $this->assertEquals(true, SaltRegex::matchMd5('$1$rasmusle$'), "MD5 salt regex match");
        $this->assertEquals(true, SaltRegex::matchBlowfish('$2a$07$usesomesillystringfors$'), "Blowfish salt regex match");
        $this->assertEquals(true, SaltRegex::matchSha256('$5$rounds=5000$usesomesillystri$'), "SHA256 salt regex match");
        $this->assertEquals(true, SaltRegex::matchSha512('$6$rounds=5000$usesomesillystri$'), "SHA512 salt regex match");
    }

    /**
     * Tests SaltRegex::match()
     * @depends test_exampleMatches
     */
    public function test_match()
    {
        $this->assertEquals(true, SaltRegex::match('rl', SaltType::STD_DES), "Standard DES salt regex match");
        $this->assertEquals(true, SaltRegex::match('_J9..rasm', SaltType::EXT_DES), "Extended DES salt regex match");
        $this->assertEquals(true, SaltRegex::match('$1$rasmusle$', SaltType::MD5), "MD5 salt regex match");
        $this->assertEquals(true, SaltRegex::match('$2a$07$usesomesillystringfors$', SaltType::BLOWFISH), "Blowfish salt regex match");
        $this->assertEquals(true, SaltRegex::match('$5$rounds=5000$usesomesillystri$', SaltType::SHA256), "SHA256 salt regex match");
        $this->assertEquals(true, SaltRegex::match('$6$rounds=5000$usesomesillystri$', SaltType::SHA512), "SHA512 salt regex match");
    }
}
