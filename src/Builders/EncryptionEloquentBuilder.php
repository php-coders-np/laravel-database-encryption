<?php

/**
 * src/Builders/EncryptionEloquentBuilder.php.
 *
 */

namespace PHPCodersNp\DBEncryption\Builders;

use Illuminate\Database\Eloquent\Builder;

class EncryptionEloquentBuilder extends Builder
{
  protected $salt;
  public function __construct($query)
  {
    parent::__construct($query);
    // Set the salt for encryption
    $this->salt = substr(hash('sha256', config('laravelDatabaseEncryption.encrypt_key')), 0, 16);
  }
  public function whereEncrypted($param1, $param2, $param3 = null)
  {
    $filter            = new \stdClass();
    $filter->field     = $param1;
    $filter->operation = isset($param3) ? $param2 : '=';
    $filter->value     = isset($param3) ? $param3 : $param2;
    if (strpos($param1, '.') !== false) {
      $parts = explode('.', $param1);
      return self::whereRaw("CONVERT(AES_DECRYPT(FROM_bASE64(`{$parts[0]}`.`{$parts[1]}`), '{$this->salt}') USING utf8mb4) {$filter->operation} ? ", [$filter->value]);
    } else {
      $filter->field = $param1;
      return self::whereRaw("CONVERT(AES_DECRYPT(FROM_bASE64(`{$filter->field}`), '{$this->salt}') USING utf8mb4) {$filter->operation} ? ", [$filter->value]);
    }
  }
  public function orWhereEncrypted($param1, $param2, $param3 = null)
  {
    $filter            = new \stdClass();
    $filter->field     = $param1;
    $filter->operation = isset($param3) ? $param2 : '=';
    $filter->value     = isset($param3) ? $param3 : $param2;
    if (strpos($param1, '.') !== false) {
      $parts = explode('.', $param1);
      return self::orWhereRaw("CONVERT(AES_DECRYPT(FROM_bASE64(`{$parts[0]}`.`{$parts[1]}`), '{$this->salt}') USING utf8mb4) {$filter->operation} ? ", [$filter->value]);
    } else {
      $filter->field = $param1;
      return self::orWhereRaw("CONVERT(AES_DECRYPT(FROM_bASE64(`{$filter->field}`), '{$this->salt}') USING utf8mb4) {$filter->operation} ? ", [$filter->value]);
    }
  }
  public function orderByEncrypted($column, $direction = 'asc')
  {
    if (strpos($column, '.') !== false) {
      $parts = explode('.', $column);
      return self::orderByRaw("CONVERT(AES_DECRYPT(FROM_bASE64(`{$parts[0]}`.`{$parts[1]}`), '{$this->salt}') USING utf8mb4) {$direction}");
    } else {
      return self::orderByRaw("CONVERT(AES_DECRYPT(FROM_bASE64(`{$column}`), '{$this->salt}') USING utf8mb4) {$direction}");
    }
  }

  public function selectEncrypted($column)
  {    
    $parts = explode(' as ', $column);
    $columnNameAlias = trim($parts[0]);
    $columnAlias = trim($parts[1]);

    $columnNameParts = explode('.', $columnNameAlias);
    $tableName = $columnNameParts[0];
    $columnName = $columnNameParts[1];

    return self::selectRaw("CONVERT(AES_DECRYPT(FROM_BASE64(`{$tableName}`.`{$columnName}`), '{$this->salt}') USING utf8mb4) AS `{$columnAlias}`");
  }
}
