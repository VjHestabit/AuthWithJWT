# Introduction

The Authentication With JWT module is a pre-built and maintained module that provides all the necessary functionality for user authentication in a Laravel project. The module includes features such as user registration, login, logout, forgot password, change password, and authentication logging. By using this module, developers can save time and effort in implementing these common authentication features in their projects, while promoting consistency and standardization in module design and implementation.

# Requirement 


Laravel freamwork -nWidart/laravel-modules package, Implementing JWT authentication, php 7.2 or higher

## Steps to use this module


#### Step 1: Install [Module Package](https://nwidart.com/laravel-modules/v6/installation-and-setup) Library  


``` bash
composer require nwidart/laravel-modules
```

##### Step 1.1: Create Modules folder on root laravel project also register in composer.json

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
#### Tip: don't forget to run composer dump-autoload afterwards

##### Step 1.2: clone the code in Modules folder

if don't have Modules folder on laravel root then create manually.

``` bash
git clone https://github.com/Hestabit/AuthWithJWT.git
```
##### Tip: don't forget to run php artisan module:enable AuthWithJWT afterwards


#### Step 2:- Install the JWT Package inside the root directory 

``` bash
composer require tymon/jwt-auth
```
For installation and setup jwt [read documents](https://jwt-auth.readthedocs.io/en/develop/)

#### Step 3:- Open app/Http/Kernel.php and paste the below command

``` bash
'jwt.verify' => \Modules\AuthWithJWT\Http\Middleware\JWTMiddleware::class,
'jwt.auth' => 'Tymon\JWTAuth\Middleware\GetUserFromToken',
'jwt.refresh' => 'Tymon\JWTAuth\Middleware\RefreshToken',
```


#### Step 4:- Run php artisan migrate


#### Step 5:- Add the Mailer Mail Details in the .env file


## Features

1) [Register](#1-register)
2) [Login](#2-login)
3) [Logout](#3-logout)
4) [Fetch User Profile](#4-fetchuserprofile)
5) [Update User Profile](#5-updateuserprofile)
6) [Forget Password](#6-forgetpassword)
7) [Change Password](#7-changepassword)
8) [Audit Logs](#8-auditlogs)

## EndPoints


#### 1. Register

``` bash
URL:- /api/register

Method:- POST
```

Request Body:-

|    Parameter        |     Type           |     Required        |          Description           |
|:-------------------:|:------------------:|:-------------------:|:------------------------------:|
|     name            |     string         |       Yes           |       Name of the user         |
|     email           |     email          |       Yes           |       Email of the user        |
|    password         |     string         |       Yes           |       Password of the user     |
|password_confirmation|     string         |       Yes           |       Confirm Pasword          |




#### 2. Login

``` bash
URL:- api/login

Method:- POST
```

Request Body:-

|    Parameter        |     Type           |     Required        |          Description           |
|:-------------------:|:------------------:|:-------------------:|:------------------------------:|
|     email           |     email          |       Yes           |       Email of the user        |
|    password         |     string         |       Yes           |       Password of the user     |



#### 3. Logout

```bash
URL:- api/logout

Method:- GET
```

Request Body:- 
|    Parameter        |     Type           |     Required        |          Description           |
|:-------------------:|:------------------:|:-------------------:|:------------------------------:|
|     token           |     string         |       Yes           |      JWT Token                 |



#### 4. FetchUserProfile

```bash
URL:- api/user_profile

Method:- GET
```
Request Body:- 

|    Parameter        |     Type           |     Required        |          Description           |
|:-------------------:|:------------------:|:-------------------:|:------------------------------:|
|     token           |     string         |       Yes           |       JWT Token                |



#### 5. UpdateUserProfile

```bash
URL:- api/udpate_user_profile

Method:- PUT
```

Request Body:-

|    Parameter        |     Type           |     Required        |          Description           |
|:-------------------:|:------------------:|:-------------------:|:------------------------------:|
|     name            |     string         |       Yes           |       Name of the user         |
|     email           |     email          |       Yes           |       Email of the user        |
|    token            |     string         |       Yes           |       JWT Token                |



#### 6. ForgetPassword

```bash
URL:- api/forgot-password

Method:- POST
```

Request Body:- email (email,required)

|    Parameter        |     Type           |     Required        |          Description           |
|:-------------------:|:------------------:|:-------------------:|:------------------------------:|
|     email           |     email          |       Yes           |       Email of the user        |


#### 7. ChangePassword

```bash
URL:- api/change-password

Method:- POST
```
 old_password (required,string,min:6), password (required,string,min:6), 
password_confirmation (same as password)

Request Body:-

|    Parameter        |     Type           |     Required        |          Description           |
|:-------------------:|:------------------:|:-------------------:|:------------------------------:|
|   old_password      |     string         |       Yes           |       Old password of the user |
|    password         |     string         |       Yes           |       Password of the user     |
|password_confirmation|     string         |       Yes           |       Confirm Pasword          |
|    token            |     string         |       Yes           |       JWT Token                |



#### 8. AuditLogs

```bash
URL:- api/user-logs

Method:- POST
```
Request Body:-

|    Parameter        |     Type           |     Required        |          Description           |
|:-------------------:|:------------------:|:-------------------:|:------------------------------:|
|    token            |     string         |       Yes           |       JWT Token                |



## NOTE:- For testing the api you can run the following command
 
```bash
  php artisan test Modules/AuthWithJWT/Tests/Unit/ApiControllerTest.php
```
