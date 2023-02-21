<?php

namespace Modules\AuthWithJWT\Http\Requests;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;

class UserRegistrationRequest extends FormRequest
{
    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        return [
            'name' => 'required|string|max:255',
        ] +
        ($this->isMethod('POST') ? $this->store() : $this->update());
    }

    public function store()
    {
        $rules = [
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:6|confirmed'
        ];

        return $rules;
    }

    public function update()
    {
        $rules = [
            'email' => 'required|email|unique:users,email,'.$this->user()->id,
        ];

        return $rules;
    }

    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        return true;
    }

    public function failedValidation(Validator $validator){
        throw new HttpResponseException(response()->json([
            'status' => false,
            'message' => $validator->errors()
        ]));
    }
}
