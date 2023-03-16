<?php

namespace Modules\AuthWithJWT\Tests\Unit;

use App\Models\User;
use Illuminate\Http\Response;
use Tests\TestCase;
use Illuminate\Foundation\Testing\WithFaker;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Request;
use Modules\AuthWithJWT\Entities\Log;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Mail;

class ApiControllerTest extends TestCase
{
    use  WithFaker, DatabaseTransactions;

    const INVALIDTOKEN = 'authwithjwt::messages.invalid_token';

    /**
     * Test User Successfully register
     */
    public function testCanRegisterUser()
    {
        $name = $this->faker->name;
        $email = $this->faker->safeEmail;
        $password = $this->faker->password;

        $response = $this->postJson(route('auth.register'), [
            'name' => $name,
            'email' => $email,
            'password' => $password,
            'password_confirmation' => $password
        ]);

        $response->assertStatus(Response::HTTP_OK)
            ->assertJsonStructure(['status','message', 'data'])
            ->assertJson([
                'status' => true,
                'message' => __('authwithjwt::messages.user.registered'),
                'data' => [
                    'name' => $name,
                    'email' => $email
                ]
            ]);
    }


    /**
     * Check User can register with invalid Data
     */
    public function testCannotRegisterUserWithInvalidData()
    {
        $response = $this->postJson(route('auth.register'), [
            'name' => '',
            'email' => 'invalid-email',
            'password' => 'short',
            'password_confirmation' => 'short'
        ]);

        // Assert status
        $response->assertStatus(Response::HTTP_OK)
            ->assertJsonStructure(['status', 'message']);
    }


     /**
     * Test login with valid credentials
     *
     * @return void
     */
    public function testCanLoginWithValidCredentials()
    {
        // Create a user
        $user = User::factory()->create([
            'password' => bcrypt('password'),
        ]);

        // Make a login request with valid credentials
        $response = $this->postJson(route('auth.login'), [
            'email' => $user->email,
            'password' => 'password',
        ]);

        // Assert response
        $response->assertOk()
                 ->assertJson([
                     'status' => true,
                     'message' => __('authwithjwt::messages.user.successfully_login'),
                 ])
                 ->assertJsonStructure([
                     'token',
                 ]);
    }

    /**
     * Test login with invalid credentials
     *
     * @return void
     */
    public function testCannotLoginWithInvalidCredentials()
    {
        // Make a login request with invalid credentials
        $response = $this->postJson(route('auth.login'), [
            'email' => 'invalid-email',
            'password' => 'invalid-password',
        ]);

        // Assert response
        $response->assertStatus(Response::HTTP_OK)
                 ->assertJson([
                     'status' => false
                 ]);
    }

    /**
     * Check User can Logout
     */
    public function testUserCanLogout()
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
            'password' => bcrypt('password')
        ]);
        //Get JwtAuth Token
        $token = JWTAuth::fromUser($user);

        $response = $this->get(route('auth.logout', ['token' => $token]));

        $response->assertStatus(Response::HTTP_OK);
        $response->assertJson([
            'status' => true,
            'message' => __('authwithjwt::messages.user.successfully_logout')
        ]);

        //Check log table data in database
        $this->assertDatabaseHas('logs', [
            'user_id' => $user->id,
            'ip' => Request::ip(),
            'subject' => __('authwithjwt::messages.user.logout')
        ]);

        //check token working or not
        $this->assertFalse(JWTAuth::check($token));
    }

    /**
     * Check With Invalid Token
     */
    public function testLogoutFailsWithInvalidToken()
    {
        $response = $this->get(route('auth.logout', ['token' => 'invalid_token']));

        $response->assertStatus(Response::HTTP_OK);
        $response->assertJson([
            'status' => __(self::INVALIDTOKEN),
            'message' => []
        ]);
    }


   /**
     * Test changing password with valid data and token.
     *
     * @return void
     */
    public function testChangePasswordWithValidDataAndToken()
    {
        $user = User::factory()->create([
            'password' => Hash::make('old_password')
        ]);

        $token = JWTAuth::fromUser($user);
        $newPassword = 'new_password';

        $response = $this->post(route('auth.change_password'), [
            'token' => $token,
            'old_password' => 'old_password',
            'password' => $newPassword,
            'password_confirmation' => $newPassword
        ]);

        $response->assertStatus(Response::HTTP_OK);

        //Check database password updated or not
        $this->assertDatabaseHas('users', [
            'id' => $user->id,
            'password' => Hash::check($newPassword, $user->password)
        ]);
    }

    /**
     * Test changing password with invalid data.
     *
     * @return void
     */
    public function testChangePasswordWithInvalidData()
    {
        $user = User::factory()->create([
            'password' => Hash::make('old_password')
        ]);
        $token = JWTAuth::fromUser($user);
        $newPassword = '123';

        $response = $this->post(route('auth.change_password'), [
            'token' => $token,
            'old_password' => 'old_password',
            'password' => $newPassword,
            'password_confirmation' => $newPassword
        ]);

        $response->assertStatus(Response::HTTP_OK);
    }

    /**
     * Test the forgot password feature with invalid email
     *
     * @return void
     */
    public function testForgotPasswordWithInvalidEmail()
    {
        Mail::fake();
        $response = $this->postJson(route('auth.forget_password'), ['email' => $this->faker->unique()->safeEmail]);
        $response->assertStatus(Response::HTTP_NOT_FOUND);
        $response->assertJson(['status' => false, 'message' => __('authwithjwt::messages.user.not_found')]);
        Mail::assertNothingSent();
    }

    /**
     * Test the forgot password feature with valid mail
     *
     * @return void
     */
    public function testForgotPasswordWithValidEmail()
    {
        // Create a test user
        $user = User::factory()->create();

        // Make a request to the forgot password endpoint
        $response = $this->postJson(route('auth.forget_password'), [
            'email' => $user->email,
        ]);

        // Assert that the response has a 200 status code
        $response->assertStatus(Response::HTTP_OK);
    }

    /**
     * Test the forgot password feature with failed mail sending
     *
     * @return void
     */
    public function testForgotPasswordWithFailedMailSending()
    {
        Mail::shouldReceive('to')->andThrow(new \Exception('Mail sending failed'));
        $user = User::factory()->create();
        $response = $this->postJson(route('auth.forget_password'), ['email' => $user->email]);
        $response->assertStatus(Response::HTTP_BAD_REQUEST);
        $response->assertJson(['status' => false, 'message' => 'Failed']);
    }

    /**
     * Test user logs API endpoint with valid token.
     *
     * @return void
     */
    public function testUserLogsApiWithValidToken()
    {
        $user = User::factory()->create();
        Log::factory()->count(5)->create(['user_id' => $user->id]);

        $token = JWTAuth::fromUser($user);

        $response = $this->post(route('auth.user_logs'), [
            'token' => $token,
        ]);

        // Assert that the response has a 200 status code
        $response->assertStatus(Response::HTTP_OK);

    }

    /**
     * Test user logs API endpoint with invalid token.
     *
     * @return void
     */
    public function testUserLogsApiWithInvalidToken()
    {
        $response = $this->post(route('auth.user_logs'), [
            'token' => $this->faker->text(30),
        ]);

        $response->assertStatus(Response::HTTP_OK);

            $response->assertJson([
            'status' => __(self::TRYAGAIN)
        ]);
    }

    /**
     * Test get user API endpoint with valid token.
     *
     * @return void
     */
    public function testGetUserApiWithValidToken()
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
            'password' => bcrypt('password')
        ]);

        //Get JwtAuth Token
        $token = JWTAuth::fromUser($user);

        $response = $this->get(route('auth.get_user', ['token' => $token]));

        // Assert that the response has a 200 status code
        $response->assertStatus(Response::HTTP_OK);

        $response->assertJson([
            'status' =>  true,
            'message' => __('authwithjwt::messages.user.successfully_fetch')
        ]);

    }

    /**
     * Test get user API endpoint with invalid token.
     *
     * @return void
     */
    public function testGetUserApiWithInvalidToken()
    {
       // Make a request to the get user endpoint
        $response = $this->get(route('auth.get_user', ['token' => 'invalid_token']));

        // Assert that the response has a 200 status code
        $response->assertStatus(Response::HTTP_OK);

        $response->assertJson([
            'status' =>  __(self::INVALIDTOKEN)
        ]);

    }



    /**
     * Test update user Api endpoint with valid token
     */
    public function testUpdateUserApiWithValidToken()
    {
        $name = $this->faker->name;
        $email = $this->faker->safeEmail;

        $user = User::factory()->create([
            'email' => 'test@example.com',
            'password' => bcrypt('password')
        ]);

        //Get JwtAuth Token
        $token = JWTAuth::fromUser($user);

         // Send request to updateUser method
        $response = $this->putJson(route('auth.update_user'), [
            'token' => $token,
            'name'  => $name,
            'email' => $email
        ]);
        //assert that has the response 200
        $response->assertStatus(Response::HTTP_OK);

        $response->assertJson([
            'status' =>  true,
            'message' => __('authwithjwt::messages.user.updated'),
            'data'    => [
                'id' => $user->id,
                'name' => $name,
                'email' => $email
            ],
        ]);

    }


    /**
     * Test update user Api endpoint with invalid token
     */
    public function testUpdateUserApiWithInvalidToken()
    {
         // Send request to updateUser method
        $response = $this->putJson(route('auth.update_user'), [
            'token' => $this->faker->text(30),
            'name'  => $this->faker->name,
            'email' => $this->faker->safeEmail
        ]);
        //assert that has the response 200
        $response->assertStatus(Response::HTTP_OK);

        $response->assertJson([
            'status' => __('authwithjwt::messages.invalid_token'),
        ]);

    }




}
