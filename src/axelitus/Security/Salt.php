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
 * Uses axelitus\Base package (composer: axelitus/base)
 */
use axelitus\Base\String;
use axelitus\Base\Int;

/**
 * Class Salt
 *
 * Class to help to create and validate salts that conform to the PHP salt standards depicted in the
 * reference for the crypt function.
 *
 * @package     axelitus\Security
 * @see         http://www.php.net/manual/es/function.crypt.php     PHP crypt function reference
 */
class Salt
{
    /**
     * @var int The default length for a generic salt.
     */
    const GENERIC_DEFAULT_LENGTH = 16;

    /**
     * Forges a new salt.
     *
     * Forges a new salt. This function can create every kind of supported salts. Use the $type parameter to determine
     * which salt will be generated. Some salts need a $length_cost parameter, if ommitted the default will be used.
     * For the generic type a string containing the pool of valid chars can be given as well as if they will be shuffled
     * to increase randomness (entropy).
     *
     * @see     axelitus\Acre\Security\SaltType
     *
     * @param string     $type        The type of salt to generate. One of the supported salt types.
     * @param   null|int $length_cost The length or cost for the generated salt.
     * @param   bool     $shuffle     Whether to shuffle the chars to increase randomness for a generic salt.
     * @param string     $chars       The chars to generate a generic salt from. for a generic salt.
     *
     * @throws \InvalidArgumentException
     * @return  string  The generated salt.
     */
    public static function forge($type = SaltType::GENERIC, $length_cost = null, $shuffle = false, $chars = String::ALNUM)
    {
        $type = String::lower($type);
        if ($length_cost != null
            and (String::isOneOf($type, [SaltType::GENERIC, SaltType::BLOWFISH, SaltType::SHA256, SaltType::SHA512])
                and (!Int::is($length_cost) or $length_cost < 1))
        ) {
            throw new \InvalidArgumentException("For the chosen type ({$type}), the \$length_cost parameter must be a positive integer.");
        }

        switch ($type) {
            case SaltType::GENERIC:
                $length = ($length_cost == null) ? static::GENERIC_DEFAULT_LENGTH : $length_cost;
                $salt = String::random($length, $chars, $shuffle);
                break;
            case SaltType::STD_DES:
                $salt = static::stdDes();
                break;
            case SaltType::EXT_DES:
                $salt = (($length_cost == null) ? static::extDes() : static::extDes($length_cost));
                break;
            case SaltType::MD5:
                $salt = static::md5();
                break;
            case SaltType::BLOWFISH:
                $salt = (($length_cost == null) ? static::blowfish() : static::blowfish($length_cost));
                break;
            case SaltType::SHA256:
                $salt = (($length_cost == null) ? static::sha256() : static::sha256($length_cost));
                break;
            case SaltType::SHA512:
                $salt = (($length_cost == null) ? static::sha512() : static::sha512($length_cost));
                break;
            default:
                throw new \InvalidArgumentException("Salt \$type parameter not identified, it can can only be one of: generic, std_des, ext_des, md5, blowfish, sha256, sha512. Given value: {$type}");
                break;
        }

        return $salt;
    }

    /**
     * Generates a generic salt.
     *
     * Generates a generic salt. The length can be varied with the $length parameter. The generated salt will contain
     * only characters from the $chars string. This string can be shuffled to increase randomness (entropy).
     *
     * @param int|string $length  The length of the generated salt
     * @param   bool     $shuffle Whether to shuffle the chars to increase randomness for the salt
     * @param string     $chars   The chars to generate the salt from
     *
     * @throws \InvalidArgumentException
     * @return  string  The generated generic salt
     */
    public static function generic($length = 8, $shuffle = false, $chars = String::ALNUM)
    {
        if (!Int::is($length) or $length < 1) {
            throw new \InvalidArgumentException("The \$length parameter must be a positive integer.");
        }

        return String::random($length, $chars, $shuffle);
    }

    /**
     * Generates a Standard DES salt.
     *
     * Generates a Standard DES salt. The function selects automatically the valid character pool to generate
     * a Standard DES salt that complies with the salt description in the PHP crypt function reference.
     *
     * @see     http://www.php.net/manual/es/function.crypt.php     PHP crypt function reference
     * @return  string  The generated Standard DES salt
     */
    public static function stdDes()
    {
        $salt = String::random(2, './' . String::ALNUM, true);

        return $salt;
    }

    /**
     * Generates an Extended DES salt.
     *
     * Generates an Extended DES salt. The function selects automatically the valid character pool to generate
     * an Extended DES salt that complies with the salt description in the PHP crypt function reference. The rounds
     * parameter determines how many rounds to loop when generating an Extended DES hash.
     *
     * @see     http://www.php.net/manual/es/function.crypt.php     PHP crypt function reference
     *
     * @param   int|string The number of rounds defined in the salt. Please refer to the crypt documentation
     *
     * @throws \InvalidArgumentException
     * @see     axelitus\Acre\Security\Salt::extDesEncodeRounds()  Function to encode the rounds as a string
     *          as described in the crypt documentation
     * @return  string  The generated Extended DES salt
     */
    public static function extDes($rounds = 5000)
    {
        if (Int::is($rounds)) {
            $rounds = static::extDesEncodeRounds($rounds);
        } elseif (is_string($rounds)) {
            if ($rounds == '') {
                $rounds = static::extDesEncodeRounds(5000);
            } elseif (strlen($rounds) != 4) {
                // TODO: make regexp for validating rounds encoding
                throw new \InvalidArgumentException("When using the \$rounds parameter as a string it must be a 4-char string fromt the alphabet \"./0-9A-Z-a-z\".");
            }
        }

        $salt = '_' . $rounds . String::random(4, './' . String::ALNUM, true);

        return $salt;
    }

    /**
     * Encodes the rounds value into a string.
     *
     * Encodes the rounds value into a string. To know how this is done please refer to the crypt function reference.
     *
     * @see     http://www.php.net/manual/es/function.crypt.php     PHP crypt function reference
     *
     * @param   int $rounds The rounds to be encoded
     *
     * @throws \InvalidArgumentException
     * @return  string  The encoded rounds string
     */
    public static function extDesEncodeRounds($rounds)
    {
        if (!Int::is($rounds) or !Int::between($rounds, 0, 16777215)) {
            throw new \InvalidArgumentException("The \$rounds parameter must be an integer from 0 to 16,777,215 (2^24 - 1).");
        }

        $alphabet = './' . String::ALNUM;
        $encoding = '';
        $division = $rounds;
        while ($division > 0) {
            $encoding .= substr($alphabet, $division % 64, 1);
            $division = (int)($division / 64);
        }
        $encoding .= (strlen($encoding) < 4) ? substr($alphabet, $division % 64, 1) : '';

        return str_pad($encoding, 4, $alphabet[0]);
    }

    /**
     * Generates an MD5 salt.
     *
     * Generates an MD5 salt. The function selects automatically the valid character pool to generate
     * an MD5 salt that complies with the salt description in the PHP crypt function reference.
     *
     * @see     http://www.php.net/manual/es/function.crypt.php     PHP crypt function reference
     * @return  string  The generated MD5 salt
     */
    public static function md5()
    {
        $salt = '$1$';
        $salt .= String::random(8, './' . String::ALNUM . '_-+', true);
        $salt .= '$';

        return $salt;
    }

    /**
     * Generates a Blowfish salt.
     *
     * Generates a Blowfish salt. The function selects automatically the valid character pool to generate
     * a Blowfish salt that complies with the salt description in the PHP crypt function reference. The cost can
     * be varied with the $cost parameter. Please refer to the cryp documentation for possible values.
     *
     * @see     http://www.php.net/manual/es/function.crypt.php     PHP crypt function reference
     *
     * @param   int $cost The Blowfish cost defined in the salt
     *
     * @throws \InvalidArgumentException
     * @return  string  The generated Blowfish salt
     */
    public static function blowfish($cost = 8)
    {
        if (!Int::is($cost) or !Int::between($cost, 4, 31)) {
            throw new \InvalidArgumentException("The \$cost parameter must be an integer between 4 and 31.");
        }

        $salt = '$2a$' . str_pad($cost, 2, '0', STR_PAD_LEFT) . '$';
        $salt .= String::random(22, './' . String::ALNUM, true);
        $salt .= '$';

        return $salt;
    }

    /**
     * Generates a SHA256 salt.
     *
     * Generates a SHA256 salt. The function selects automatically the valid character pool to generate
     * a SHA256 salt that complies with the salt description in the PHP crypt function reference. A rounds value
     * can be given to specify the rounds for the hashing algorithm. Please refer to the crypt function documentation
     * for the possible values.
     *
     * @see     http://www.php.net/manual/es/function.crypt.php     PHP crypt function reference
     *
     * @param   null|int $rounds The number of SHA rounds. Please refer to the crypt documentation
     *
     * @return  string  The generated SHA256 salt
     */
    public static function sha256($rounds = null)
    {
        $formatted_rounds = static::shaFormatRounds($rounds);

        $salt = '$5$' . $formatted_rounds . String::random(16, './' . String::ALNUM, true) . '$';

        return $salt;
    }

    /**
     * Generates a SHA512 salt.
     *
     * Generates a SHA512 salt. The function selects automatically the valid character pool to generate
     * a SHA512 salt that complies with the salt description in the PHP crypt function reference. A rounds value
     * can be given to specify the rounds for the hashing algorithm. Please refer to the crypt function documentation
     * for the possible values.
     *
     * @see     http://www.php.net/manual/es/function.crypt.php     PHP crypt function reference
     *
     * @param   null|int $rounds The number of SHA rounds. Please refer to the crypt documentation
     *
     * @return  string  The generated SHA512 salt
     */
    public static function sha512($rounds = null)
    {
        $formatted_rounds = static::shaFormatRounds($rounds);

        $salt = '$6$' . $formatted_rounds . String::random(16, './' . String::ALNUM, true) . '$';

        return $salt;
    }

    /**
     * Gets the SHA rounds string.
     *
     * Gets the SHA rounds string. The rounds value is formatted accordingly to the input value and the rules
     * described in the crypt function documentation.
     *
     * @param   null|int $rounds The number of SHA rounds. Please refer to the crypt documentation
     *
     * @throws \InvalidArgumentException
     * @return  string  The formatted rounds string
     */
    private static function shaFormatRounds($rounds = null)
    {
        $is_int = Int::is($rounds);
        if ($rounds != null and !$is_int) {
            throw new \InvalidArgumentException("The \$rounds parameter must be an integer between 1,000 and 999,999,999 (will be truncated to the nearest limit) or null (for no rounds).");
        }

        $formatted_rounds = ($is_int) ? 'rounds=' . min(max($rounds, 1000), 999999999) . '$' : '';

        return $formatted_rounds;
    }

    /**
     * Validates the given salt.
     *
     * Validates the given salt. If not specified, the function will try to identify the salt's type.
     * The identification and validation is made by the use of the SaltRegex regular expression patterns.
     *
     * @see      axelitus\Acre\Security\SaltRegex
     *
     * @param      $salt
     * @param null $type
     *
     * @throws \InvalidArgumentException
     * @internal param \axelitus\Security\The $string salt to validate
     * @internal param \axelitus\Security\If $string known, the salt's type (using one of the supported salt types)
     * @return  bool    Whether the salt is valid
     */
    public static function validate($salt, $type = null)
    {
        if (!is_string($salt) and $salt != '') {
            throw new \InvalidArgumentException("The \$salt parameter must be a non-empty string");
        }

        $types = array(
            SaltType::STD_DES,
            SaltType::EXT_DES,
            SaltType::MD5,
            SaltType::BLOWFISH,
            SaltType::SHA256,
            SaltType::SHA512
        );

        $type = String::lower($type);
        if (is_string($type) and String::isOneOf($type, $types)) {
            $func = 'SaltRegex::match' . String::camel($type);
            if (is_callable($func)) {
                return call_user_func($func, $salt);
            }
        }

        if (static::identify($salt) !== false) {
            return true;
        }

        return false;
    }

    /**
     * Tries to identify a given salt by using the different salt regular expressions.
     *
     * Tries to identify a given salt by using the different salt regular expressions. The identification is done
     * by validating the salt against all regular expressions stopping at the first successful validation.
     *
     * @param   string $salt The salt to be identified
     *
     * @throws \InvalidArgumentException
     * @return  bool|string     The identified salt's type or false if unsuccessful
     */
    public static function identify($salt)
    {
        if (!is_string($salt) && $salt != '') {
            throw new \InvalidArgumentException("The \$salt parameter must be a non-empty string");
        }

        $types = array(
            SaltType::STD_DES,
            SaltType::EXT_DES,
            SaltType::MD5,
            SaltType::BLOWFISH,
            SaltType::SHA256,
            SaltType::SHA512
        );

        foreach ($types as $type) {
            $func = 'SaltRegex::match' . String::camel($type);
            if (is_callable($func)) {
                if (call_user_func($func, $salt)) {
                    return $type;
                }
            }
        }

        return false;
    }
}
