<?php

namespace oleanti\LaravelCognito\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use oleanti\LaravelCognito\Cognito;
use oleanti\LaravelCognito\CognitoClient;

class VerificationController extends Controller
{
    public function view(Request $request)
    {
        $client = app(CognitoClient::class);
        $details = $client->getCodeDeliveryDetails();
        if(is_null($details)) {
            $user = Auth::user();
            $client->resendConfirmationCode($user->cognito_username);
        }

        return view('cognito.verify', [
            'details' => $details,
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
