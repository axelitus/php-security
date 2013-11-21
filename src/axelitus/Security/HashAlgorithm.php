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

/**
 * Class HashAlgorithm
 *
 * Class that contains the different hash types supported by this package. (Based on PHP 5.4.x results)
 *
 * @package     axelitus\Security
 * @see         http://www.php.net/manual/es/function.hash-algos.php     PHP hash_algos function reference
 */
abstract class HashAlgorithm
{
    /**
     * @var string MD2 hash type.
     */
    const MD2 = 'md2';

    /**
     * @var string MD4 hash type.
     */
    const MD4 = 'md4';

    /**
     * @var string MD5 hash type.
     */
    const MD5 = 'md5';

    /**
     * @var string SHA1 hash type.
     */
    const SHA1 = 'sha1';

    /**
     * @var string SHA224 hash type.
     */
    const SHA224 = 'sha224';

    /**
     * @var string SHA256 hash type.
     */
    const SHA256 = 'sha256';

    /**
     * @var string SHA384 hash type.
     */
    const SHA384 = 'sha384';

    /**
     * @var string SHA512 hash type.
     */
    const SHA512 = 'sha512';

    /**
     * @var string
     */
    const RIPEMD128 = 'ripemd128';

    /**
     * @var string
     */
    const RIPEMD160 = 'ripemd160';

    /**
     * @var string
     */
    const RIPEMD256 = 'ripemd256';

    /**
     * @var string
     */
    const RIPEMD320 = 'ripemd320';

    /**
     * @var string
     */
    const WHIRLPOOL = 'whirlpool';

    /**
     * @var string
     */
    const TIGER128_3 = 'tiger128,3';

    /**
     * @var string
     */
    const TIGER160_3 = 'tiger160,3';

    /**
     * @var string
     */
    const TIGER192_3 = 'tiger192,3';

    /**
     * @var string
     */
    const TIGER128_4 = 'tiger128,4';

    /**
     * @var string
     */
    const TIGER160_4 = 'tiger160,4';

    /**
     * @var string
     */
    const TIGER192_4 = 'tiger192,4';

    /**
     * @var string
     */
    const SNEFRU = 'snefru';

    /**
     * @var string
     */
    const SNEFRU256 = 'snefru256';

    /**
     * @var string
     */
    const GOST = 'gost';

    /**
     * @var string
     */
    const ADLER32 = 'adler32';

    /**
     * @var string
     */
    const CRC32 = 'crc32';

    /**
     * @var string
     */
    const CRC32B = 'crc32b';

    /**
     * @var string
     */
    const FNV132 = 'fnv132';

    /**
     * @var string
     */
    const FNV164 = 'fnv164';

    /**
     * @var string
     */
    const JOAAT = 'joaat';

    /**
     * @var string
     */
    const HAVAL128_3 = 'haval128,3';

    /**
     * @var string
     */
    const HAVAL160_3 = 'haval160,3';

    /**
     * @var string
     */
    const HAVAL192_3 = 'haval192,3';

    /**
     * @var string
     */
    const HAVAL224_3 = 'haval224,3';

    /**
     * @var string
     */
    const HAVAL256_3 = 'haval256,3';

    /**
     * @var string
     */
    const HAVAL128_4 = 'haval128,4';

    /**
     * @var string
     */
    const HAVAL160_4 = 'haval160,4';

    /**
     * @var string
     */
    const HAVAL192_4 = 'haval192,4';

    /**
     * @var string
     */
    const HAVAL224_4 = 'haval224,4';

    /**
     * @var string
     */
    const HAVAL256_4 = 'haval256,4';

    /**
     * @var string
     */
    const HAVAL128_5 = 'haval128,5';

    /**
     * @var string
     */
    const HAVAL160_5 = 'haval160,5';

    /**
     * @var string
     */
    const HAVAL192_5 = 'haval192,5';

    /**
     * @var string
     */
    const HAVAL224_5 = 'haval224,5';

    /**
     * @var string
     */
    const HAVAL256_5 = 'haval256,5';

    /**
     * Gets the supported algorithms.
     *
     * @return array Returns a numerically indexed array containing the list of supported hashing algorithms.
     */
    public static function available()
    {
        return hash_algos();
    }
}
