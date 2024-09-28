<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\SignupRequest;
use Illuminate\Support\Facades\Auth;
class AuthController extends Controller
{
    //
    public function login(LoginRequest $request)
    {
        //
        $credentials = $request->valiated();
        $remember = $credentials['remember'] ?? false;
        unset($credentials['remember']);

        if (!Auth::attempt($credentials, $remember)) {
            return response([
                'message' => 'Incorrect credentials'
            ], 422);
        }

        $user = Auth::user();
        $token = $user->createToken('auth_token')->plainTextToken;
        return response([
            'token' => $token,
            'user' => $user,
        ]);
    
    }

    public function signup ( SignupRequest $request){

        $credentials = $request->validated();
        $user = User::create([
            'email' => $credentials['email'],
            'password' => bcrypt($credentials['password']),
            'name' => $credentials['fullname'],
            'address' => $credentials['address'],
            'country' => $credentials['country'],
        ]);
        $token = $user->createToken('auth_token')->plainTextToken;
        return response([
            'token' => $token,
            'user' => $user,
        ]);

    }

}
