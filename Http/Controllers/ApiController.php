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
use Modules\AuthWithJWT\Repositories\AuthWithJWTRepository;

class ApiController extends Controller
{
    protected $auth;

    public function __construct(AuthWithJWTRepository $auth)
    {
        $this->auth = $auth;
    }
     /**
     *
     *  Store a newly registered user information.
     * @param UserRegistrationRequest $request
     * @return response
     *
     */

    public function register(UserRegistrationRequest $request)
    {
        $data = [
            'name'=> $request->input('name'),
            'email'=> $request->input('email'),
            'password' => Hash::make($request->input('password'))
        ];

        $user = $this->auth->register($data);

        if($user){
            $user['token'] = JWTAuth::attempt($request->only(['email','password']));

            $this->auth->addLog(__('authwithjwt::messages.user.login'),$user->id);

            $responseData = [
                'status' => true,
                'message'=> __('authwithjwt::messages.user.registered'),
                'data'   => $data,
            ];

            return $this->auth->responseMessage($responseData,Response::HTTP_OK);
        }else{
            $responseData = [
                'status' => false,
                'message'=> __('authwithjwt::messages.user.registered_failed'),
                'data'   => [],
            ];

            return $this->auth->responseMessage($responseData,Response::HTTP_BAD_REQUEST);
        }
    }

    /**
     *
     * Verify the user credentials
     * @param AuthLoginRequest $request
     * @return response
     *
     */

    public function authenticate(AuthLoginRequest $request)
    {
        $validate = $request->validated();
        $credentials = $request->only(['email','password']);
        try{
            if(!$token = JWTAuth::attempt($credentials)){

                $responseData = [
                    'status' => false,
                    'message'=> __('authwithjwt::messages.user.invalid_credentials'),
                ];

                return $this->auth->responseMessage($responseData,Response::HTTP_UNAUTHORIZED);
            }

            $log = $this->auth->addLog(__('authwithjwt::messages.user.login'),Auth::user()->id);

        }catch(JWTException $e){

            $responseData = [
                 'status' => false,
                'message' => __('authwithjwt::messages.missing_token')
            ];

            return $this->auth->responseMessage($responseData,Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $responseData = [
            'status' => 'true',
            'message' => __('authwithjwt::messages.user.successfully_login'),
            'token' => $token
        ];

        return $this->auth->responseMessage($responseData,Response::HTTP_OK);
    }

    /**
     *
     * Verify the token and make User Logged out
     * @param AuthenticateRequest $request
     * @return response
     *
     */

    public function logout(AuthenticateRequest $request){
        $validate = $request->validated();
        try{
            $user = JWTAuth::authenticate($request->input('token'));
            $this->auth->addLog(__('authwithjwt::messages.user.logout'),$user->id);
            JWTAuth::invalidate($request->input('token'));

            $responseData = [
                'status' => true,
                'message' => __('authwithjwt::messages.user.successfully_logout')
            ];
            return $this->auth->responseMessage($responseData,Response::HTTP_OK);

        }catch(JWTException $e){
            $responseData = [
                'status' => false,
                'message' => __('authwithjwt::messages.try_again'),
            ];
            return $this->auth->responseMessage($responseData,Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     *
     *  Verify the token and fetched the user information
     * @param AuthenticateRequest $request
     * @return response
     *
     */

    public function getUser(AuthenticateRequest $request){
        $validate = $request->validated();
        try{
            $user = JWTAuth::authenticate($request->input('token'));
            $responseData = [
                'status' => true,
                'message' => __('authwithjwt::messages.user.successfully_fetch'),
                'data' => $user
            ];
            return $this->auth->responseMessage($responseData,Response::HTTP_OK);
        }catch(JWTException $e){
            $responseData = [
                'status' => false,
                'message' => __('authwithjwt::messages.try_again'),
            ];
            return $this->auth->responseMessage($responseData,Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Update the specified information of user.
     * @param UserRegistrationRequest $request
     * @param int $id
     * @return Response
     */

    public function updateUser(UserRegistrationRequest $request){

        try{
            $authenticate = JWTAuth::authenticate($request->input('token'));
            $condition = [
                'id'=>$authenticate->id
            ];
            $data = [
                'name' => $request->input('name'),
                'email'=> $request->input('email')
            ];
            $user =  $this->auth->updateOrCreate($condition,$data);

            $responseData = [
                'status' => true,
                'message' => __('authwithjwt::messages.user.updated'),
                'data' => $user
            ];
            return $this->auth->responseMessage($responseData,Response::HTTP_OK);
        }catch(JWTException $e){
            $responseData = [
                'status' => false,
                'message' => __('authwithjwt::messages.try_again'),
            ];
            return $this->auth->responseMessage($responseData,Response::HTTP_BAD_REQUEST);
        }
    }

    /**
     *
     * Change the user's password
     * @param ChangePasswordRequest $request
     * @return Response
     *
     */

    public function changePassword(ChangePasswordRequest $request){
        $validate = $request->validated();
        try{
            $user = JWTAuth::authenticate($request->input('token'));
            if (!Hash::check($request->input('old_password'), $user->password)) {
                return response()->json([
                    'status' => false,
                    'message' => __('authwithjwt::messages.user.password_not_matched'),
                ], Response::HTTP_BAD_REQUEST);
            }

            $where = ['id' => $user->id];
            $data = ['password'=> Hash::make($request->input('password'))];
            $userData =  $this->auth->updateOrCreate($where,$data);

            $responseData = [
                'status' => true,
                'message' => __('authwithjwt::messages.user.password_updated'),
                'data' => $userData
            ];
            return $this->auth->responseMessage($responseData,Response::HTTP_OK);

        }catch(JWTException $e){
            $responseData = [
                'status' => false,
                'message' => __('authwithjwt::messages.user.password_failed'),
                'data' => array()
            ];
            return $this->auth->responseMessage($responseData,Response::HTTP_UNAUTHORIZED);
        }
    }

    /**
     *
     * Update the password temporary & send the email to user
     * @param ForgetPasswordRequest $request
     * @return response
     *
     */

    public function forgotPassword(ForgetPasswordRequest $request){
        $validate = $request->validated();
        try{
            $user = $this->auth->show(['email'=>$request->input('email')]);
            if(!$user){
                $responseData = [
                    'status' => false ,
                    'message' => __('authwithjwt::messages.user.not_found')
                ];
                return $this->auth->responseMessage($responseData,Response::HTTP_NOT_FOUND);
            }

            $pass = Str::random(6);
            $where = ['id' => $user->id];
            $data = ['password'=> Hash::make($pass),'password_status' => 1];
            $userData =  $this->auth->updateOrCreate($where,$data);
            $details = [
                'password' =>$pass
            ];

            $mail = Mail::to($request->input('email'))->send(new ForgetPassword($details));
            if(!$mail){
                $responseData = [
                    'status' => false,
                    'message' => __('authwithjwt::messages.mail_failed')
                ];
                return $this->auth->responseMessage($responseData,Response::HTTP_UNAUTHORIZED);
            }else{
                $responseData = [
                    'status' => true,
                    'message' => __('authwithjwt::messages.mail_sent')
                ];
                return $this->auth->responseMessage($responseData,Response::HTTP_OK);
            }
        }catch(Exception $e){
            $responseData = [
                'status' => false,
                'message' => 'Failed'
            ];
            return $this->auth->responseMessage($responseData,Response::HTTP_BAD_REQUEST);
        }
    }


    /**
     *
     * Fetch the logs records for the user
     * @param AuthenticateRequest $request
     * @return response
     *
     */
    public function userLogs(AuthenticateRequest $request){
        $validate = $request->validated();
        try{
            $authenticate = JWTAuth::authenticate($request->input('token'));
            $logs = Log::where('user_id',$authenticate->id)->latest()->get();
            $responseData = [
                'status'  => true,
                'message' => __('authwithjwt::messages.user.logs'),
                'date' => $logs
            ];
            return $this->auth->responseMessage($responseData,Response::HTTP_OK);
        }catch(JWTException $e){
            $responseData = [
                'status'  => true,
                'message' => __('authwithjwt::messages.user.failed_logs'),
            ];
            return $this->auth->responseMessage($responseData,Response::HTTP_UNAUTHORIZED);
        }
    }

}
