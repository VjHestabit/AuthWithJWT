<?php

namespace Modules\AuthWithJWT\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Log extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id','subject','ip'
    ];

    protected static function newFactory()
    {
        return \Modules\AuthWithJWT\Database\factories\LogFactory::new();
    }
}
