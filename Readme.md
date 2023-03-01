# Introduction


The Authentication With JWT module is a pre-built and maintained module that provides all the necessary functionality for user authentication in a Laravel project. The module includes features such as user registration, login, logout, forgot password, change password, and authentication logging. By using this module, developers can save time and effort in implementing these common authentication features in their projects, while promoting consistency and standardization in module design and implementation.


# Requirement 


Laravel freamwork -nWidart/laravel-modules package, Implementing JWT authentication, php 7.2 or higher

## Steps to use this module


Step 1: Install Module Package Library  


``` bash
composer require nwidart/laravel-modules
```

Step 1.1: Create Modules folder on root laravel project also register in composer.json

``` bash
{
  "autoload": {
    "psr-4": {
      "App\\": "app/",
      "Modules\\": "Modules/"
    }
  }
}
```
Tip: don't forget to run composer dump-autoload afterwards

Step 1.2: clone the code in modules folder

``` bash
git clone https://github.com/prashanthestabit/AuthWithJWT.git
```
Tip: don't forget to run php artisan module:enable AuthWithJWT afterwards



``` bash
composer require nwidart/laravel-modules
```

Step 2:- Install the JWT Package inside the root directory 

``` bash
composer require tymon/jwt-auth
```


Step 3:- Open app/Http/Kernel.php and paste the below command

``` bash
'jwt.verify' => \Modules\AuthWithJWT\Http\Middleware\JWTMiddleware::class,
'jwt.auth' => 'Tymon\JWTAuth\Middleware\GetUserFromToken',
'jwt.refresh' => 'Tymon\JWTAuth\Middleware\RefreshToken',
```


Step 4:- Run php artisan migrate


Step 5:- Add the Mailer Mail Details in the .env file



# EndPoints


1) Register

``` bash
URL:- http://127.0.0.1/api/register
Method:- POST
Request Body:- name(string, required), email (email,required), password (string,required,min:6),
password_confirmation (same as password)
Response:- 
1.1) If Success: HTTP_OK response code :- 200 with JSON containing user information and token
1.2) If Unsuccess: HTTP_BAD_REQUEST response code :- 400 Bad Request with error message in
JSON Format
```


2) Login

``` bash
URL:- http://127.0.0.1/api/login
Method:- POST
Request Body:- email (email,required), password (string,required,min:6)
Response:- 
2.1) If Success: HTTP_OK response code :- 200 with JSON containing token
2.2) If Unsuccess: HTTP_UNAUTHORIZED response code :- 401 Unauthorized with error 
message in JSON format
```


3) Logout

```bash
URL:- http://127.0.0.1/api/logout
Method:- GET
Request Body:- token (required)
Response:- 
3.1) If Success: HTTP_OK response code :- 200 with success message in JSON format
3.2) If Unsuccess: HTTP_INTERNAL_SERVER_ERROR response code :- 500 with error message
in JSON format
```


4) Fetch User Profile

```bash
URL:- http://127.0.0.1/api/user_profile
Method:- GET
Request Body:- token (required)
Response:- 
4.1) If Success: HTTP_OK response code :- 200 with user information in JSON format
4.2) If Unsuccess: HTTP_INTERNAL_SERVER_ERROR response code :- 500 with error message
in JSON format
```


5) Update User Profile

```bash
URL:- http://127.0.0.1/api/udpate_user_profile
Method:- PUT
Request Body:- token (required), name (string), email (email)
Response:- 
5.1) If Success: HTTP_OK response code :- 200 with update users information & fetch the 
updated information in JSON format
5.2) If Unsuccess: HTTP_BAD_REQUEST response code :- 400 with error message in JSON format
```


6) Forget Password

```bash
URL:- http://127.0.0.1/api/forgot-password
Method:- POST
Request Body:- email (email,required)
Response:- 
6.1) If Success: HTTP_OK response code :- 200 with success message in JSON Format and email
will be sent to the user with temporary password
6.2) If Unsuccess: HTTP_BAD_REQUEST response code :- 400 with error message in JSON format
```


7) Change Password

```bash
URL:- http://127.0.0.1/api/change-password
Method:- POST
Request Body:- old_password (required,string,min:6), password (required,string,min:6), 
password_confirmation (same as password)
Response:- 
7.1) If Success: HTTP_OK response code :- 200 with success message in JSON Format.
7.2) If Unsuccess: HTTP_BAD_REQUEST response code :- 400 (or) HTTP_UNAUTHORIZED response
code:- 401 with error message in JSON format
```


7) Audit Logs

```bash
URL:- http://127.0.0.1/api/user-logs
Method:- POST
Request Body:- token (required)
Response:- 
7.1) If Success: HTTP_OK response code :- 200 with users logs data in JSON Format.
7.2) If Unsuccess: HTTP_UNAUTHORIZED response code:- 401 with error message in JSON format
```


## NOTE:- For testing the api you can run the following command
 
```bash
php artisan test Modules/AuthWithJWT/Tests/Unit/ApiControllerTest.php
```
