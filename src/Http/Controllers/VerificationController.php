<?php

namespace OleAnti\LaravelCognito\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Routing\Controller;
use OleAnti\LaravelCognito\CognitoClient;
use OleAnti\LaravelCognito\Cognito;


class VerificationController extends Controller
{

    public function view(Request $request)
    {
        $client = app(CognitoClient::class);
        $details = $client->getCodeDeliveryDetails();
        if(is_null($details)){
            $user = Auth::user();
            $client->resendConfirmationCode($user->cognito_username);
        }
        return view('cognito.verify', [
            'details' => $details
        ]);
    }
    public function post(Request $request)
    {
        $validated = $request->validate([
            'code' => 'required',
        ]);
        $cognito = app(Cognito::class);
        $user = Auth::user();
        $code = $validated['code'];
        $client = app(CognitoClient::class);
        $client->confirmSignUp($user->{$cognito::username()}, $code);
        $user->cognito_verified_at = now();
        $user->save();
        return redirect('/');
    }
}
