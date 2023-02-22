<?php

namespace Modules\AuthWithJWT\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Exception;
use Illuminate\Http\Response;
use Illuminate\Support\Str;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Request;
use Modules\AuthWithJWT\Emails\ForgetPassword;
use Modules\AuthWithJWT\Entities\Log;
use Modules\AuthWithJWT\Http\Requests\AuthenticateRequest;
use Modules\AuthWithJWT\Http\Requests\AuthLoginRequest;
use Modules\AuthWithJWT\Http\Requests\ChangePasswordRequest;
use Modules\AuthWithJWT\Http\Requests\ForgetPasswordRequest;
use Modules\AuthWithJWT\Http\Requests\UserRegistrationRequest;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;

class ApiController extends Controller
{


    public function register(UserRegistrationRequest $request)
    {
        $validate = $request->validated();
        $user = User::create([
            'name'=> $request->input('name'),
            'email'=> $request->input('email'),
            'password' => Hash::make($request->input('password'))
        ]);
        if($user){
            $user['token'] = JWTAuth::attempt($request->only(['email','password']));
            $log = $this->addLog('User Logged In',$user->id);
            return response()->json([
                'status'  => true,
                'message' => 'User Registered Successfully',
                'data'    => $user
            ],Response::HTTP_OK);
        }else{
            return response()->json([
                'status'  => false,
                'message' => 'Failed To Register User',
                'data'    => array()
            ],Response::HTTP_BAD_REQUEST);
        }
    }

    public function authenticate(AuthLoginRequest $request)
    {
        $validate = $request->validated();
        $credentials = $request->only(['email','password']);
        try{
            if(!$token = JWTAuth::attempt($request->only(['email','password']))){
                return response()->json([
                    'status'  => false,
                    'message' => 'Login credentials are invalid'
                ],Response::HTTP_BAD_REQUEST);
            }
            $log = $this->addLog('User Logged In',Auth::user()->id);
        }catch(JWTException $e){
            return response()->json([
                'status' => false,
                'message' => 'Could not create token'
            ],Response::HTTP_INTERNAL_SERVER_ERROR);
        }
        return response()->json([
            'status' => 'true',
            'message' => 'Login Successfully',
            'token' => $token
        ],Response::HTTP_OK);
    }

    public function logout(AuthenticateRequest $request){
        $validate = $request->validated();
        try{
            $user = JWTAuth::authenticate($request->input('token'));
            $log = $this->addLog('User Logged Out',$user->id);
            JWTAuth::invalidate($request->input('token'));
            return response()->json([
                'status' => true,
                'message' => 'User has been logged out'
            ],Response::HTTP_OK);
        }catch(JWTException $e){
            return response()->json([
                'status' => false,
                'message' => 'Sorry user cannot be logged out',
            ],Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function getUser(AuthenticateRequest $request){
        $validate = $request->validated();
        try{
            $user = JWTAuth::authenticate($request->input('token'));
            return response()->json([
                'status' => true,
                'message' => 'Details Fetch Successfully',
                'data' => $user
            ],Response::HTTP_OK);
        }catch(JWTException $e){
            return response()->json([
                'status' => false,
                'message' => 'Failed to fetch the user details'
            ],Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function updateUser(UserRegistrationRequest $request){
        $validate = $request->validated();
        try{
            $authenticate = JWTAuth::authenticate($request->input('token'));
            $userUpdate = User::find($authenticate->id)->update([
                'name' => $request->input('name'),
                'email'=> $request->input('email')
            ]);
            $user = User::find($authenticate->id);
            return response()->json([
                'status' => true,
                'message' => 'User updated successfully',
                'data' => $user
            ], Response::HTTP_OK);
        }catch(JWTException $e){
            return response()->json([
                'status' => false,
                'message' => 'Failed to update the user details'
            ],Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function changePassword(ChangePasswordRequest $request){
        $validate = $request->validated();
        try{
            $user = JWTAuth::authenticate($request->input('token'));

            $old_password = Hash::make($request->input('old_password'));
            $userUpdate = User::where('id',$user->id)->where('password',$old_password)->first();
            if(!$userUpdate){
                return response()->json([
                    'status' => false,
                    'message' => 'User Not Found',
                ], Response::HTTP_OK);
            }
            $userUpdate->password = Hash::make($request->input('password'));
            $userUpdate->update();
            return response()->json([
                'status' => true,
                'message' => 'Password Updated Successfully',
                'data' => $user
            ], Response::HTTP_OK);
        }catch(JWTException $e){
            return response()->json([
                'status' => false,
                'message' => 'Failed to update the password',
                'data' => array()
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function forgotPassword(ForgetPasswordRequest $request){
        $validate = $request->validated();
        try{
            $user = User::where('email',$request->input('email'))->first();
            if(!$user){
                return response()->json([
                    'status' => false ,
                    'message' => 'User Not Found'
                ],Response::HTTP_NOT_FOUND);
            }
            $pass = Str::random(6);
            $user->password = Hash::make($pass);
            $user->password_status = 1;
            $user->update();
            $details = [
                'password' =>$pass
            ];

            $mail = Mail::to($request->input('email'))->send(new ForgetPassword($details));
            if(!$mail){
                return response()->json([
                    'status' => false,
                    'message' => 'Failed to send the mail'
                ],Response::HTTP_UNAUTHORIZED);
            }else{
                return response()->json([
                    'status' => true,
                    'message' => 'Mail Sent Successfully'
                ],Response::HTTP_OK);
            }
        }catch(Exception $e){
             \Log::error($e);
            return response()->json([
                'status' => false,
                'message' => 'Failed'
            ],Response::HTTP_BAD_REQUEST);
        }
    }

    public function addLog($subject,$user_id){
        Log::create([
            'subject' => $subject,
            'ip' => Request::ip(),
            'user_id' => $user_id
        ]);
        return true;
    }

    public function userLogs(AuthenticateRequest $request){
        $validate = $request->validated();
        try{
            $authenticate = JWTAuth::authenticate($request->input('token'));
            $logs = Log::where('user_id',$authenticate->id)->latest()->get();
            return response()->json([
                'status'  => true,
                'message' => 'User logs fetched successfully',
                'date' => $logs
            ],Response::HTTP_OK);
        }catch(JWTException $e){
            return response()->json([
                'status' => false,
                'message' => 'Failed to fetch the user logs'
            ],Response::HTTP_BAD_REQUEST);
        }
    }

}
