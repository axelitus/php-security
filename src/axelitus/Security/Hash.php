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

namespace axelitus\Security;

use axelitus\Base\String;

/**
 * Class Hash
 *
 * Class to help creating and validating salts that conform to the PHP salt standards depicted in the
 * reference for the crypt function.
 *
 * @package     axelitus\Security
 * @see         http://www.php.net/manual/es/function.crypt.php     PHP crypt function reference
 */
class Hash
{
    public static function calculate($data, $algorithm = HashType::SHA1)
    {
        if(!String::is($data) or !String::is($algorithm))
        {
            throw new \InvalidArgumentException("The \$data and \$algorithm parameters must be strings.");
        }

        if(!in_array($algorithm, HashAlgorithm::available())) {
            throw new \RuntimeException("The given algorithm '{$algorithm}' is not supported by the current platform stack.");
        }

        return hash($algorithm, $data);
    }

    public static function md5($data)
    {
        return static::calculate($data, HashAlgorithm::MD5);
    }

    public static function sha1($data)
    {
        return static::calculate($data, HashAlgorithm::SHA1);
    }

    public static function sha256($data)
    {
        return static::calculate($data, HashAlgorithm::SHA256);
    }

    public static function sha512($data)
    {
        return static::calculate($data, HashAlgorithm::SHA512);
    }

    public static function crc32b($data)
    {
        return static::calculate($data, HashAlgorithm::CRC32);
    }
}
