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
 * Class SaltType
 *
 * Class that contains the different salt types supported by this package.
 *
 * @package     axelitus\Security
 * @see         http://www.php.net/manual/es/function.crypt.php     PHP crypt function reference
 */
abstract class SaltType
{
    /**
     * @var string  Generic salt type
     */
    const GENERIC = 'generic';

    /**
     * @var string  Standard DES salt type
     */
    const STD_DES = 'std_des';

    /**
     * @var string  Extended DES salt type
     */
    const EXT_DES = 'ext_des';

    /**
     * @var string  MD5 salt type
     */
    const MD5 = 'md5';

    /**
     * @var string  Blowfish salt type
     */
    const BLOWFISH = 'blowfish';

    /**
     * @var string  SHA256 salt type
     */
    const SHA256 = 'sha256';

    /**
     * @var string  SHA512 salt type
     */
    const SHA512 = 'sha512';
}
