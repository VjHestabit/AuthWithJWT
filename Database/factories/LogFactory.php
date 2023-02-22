<?php

namespace Modules\AuthWithJWT\Database\factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class LogFactory extends Factory
{
    /**
     * The name of the factory's corresponding model.
     *
     * @var string
     */
    protected $model = \Modules\AuthWithJWT\Entities\Log::class;

    /**
     * Define the model's default state.
     *
     * @return array
     */
    public function definition()
    {
        return [
            'user_id' => fake()->randomNumber(),
            'subject' => fake()->randomElement(['login', 'logout']),
            'ip' => fake()->ipv4(),
            'created_at' => fake()->dateTime(),
        ];
    }
}

