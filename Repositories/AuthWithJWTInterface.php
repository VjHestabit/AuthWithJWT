<?php

namespace Modules\AuthWithJWT\Repositories;

interface AuthWithJWTInterface
{
    public function save($data);

    public function updateOrCreate($where, $data);

    public function show($condition);

    public function addLog($subject, $user_id);

    public function responseMessage($responseData, $statusCode);
}
