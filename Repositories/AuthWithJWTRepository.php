<?php

namespace Modules\AuthWithJWT\Repositories;

use App\Models\User;
use Illuminate\Support\Facades\Request;
use Modules\AuthWithJWT\Entities\Log;

/* Class AuthWithJWTRepository.
 * This class is responsible for handling database operations related to authentication with JWT.
 */
class AuthWithJWTRepository
{
    /**
     * Register a new user with the given data.
     *
     * @param array $data
     * @return \App\Models\User
     */
    public function register($data)
    {
        $user = User::create($data);
        return $user;
    }

    /**
    * Update or create Registered with the given data.
    *
    * @param array $data
    * @param array $where
    * @return \App\Models\User
    */
   public function updateOrCreate($where,$data)
   {
       $user = User::updateOrCreate($where,$data);
       return $user;
   }


    /**
    * Show user details given by condition.
    *
    * @param array $condition
    * @return \App\Models\User
    */
    public function show($condition)
    {
      return User::where($condition)->first();
    }

    /**
     * Add a new log entry to the database.
     *
     * @param string $subject
     * @param int $user_id
     * @return bool
     */
    public function addLog($subject, $user_id)
    {
        Log::create([
            'subject' => $subject,
            'ip' => Request::ip(),
            'user_id' => $user_id,
        ]);
        return true;
    }

    /**
     * Generate a response with the given status, message, data and status code.
     *
     * @param array $responseData
     * @param int $statusCode
     * @return \Illuminate\Http\JsonResponse
     */
    public function responseMessage($responseData, $statusCode)
    {
        return response()->json($responseData, $statusCode);
    }
}
