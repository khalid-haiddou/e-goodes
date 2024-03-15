<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;
use App\Models\user;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Password;
use Illuminate\Auth\Events\PasswordReset;

class AuthController extends Controller
{
    public function showLoginForm()
    {
        return view('auth.login');
    }

    public function login(Request $request)
{
    // Validate the login request
    $request->validate([
        'name' => ['required', 'regex:/^[^@.]*$/'],
        'email' => 'required|email',
        'password' => 'required',
    ]);

    if (auth()->attempt($request->only('email', 'password'))) {
        $user = auth()->user();
        
        if ($user->role === 'admin') {
            return redirect()->route('dashboard.admin');
        } elseif ($user->role === 'organisateur') {
            return redirect()->route('dashboard.organisateur');
        } else {
            return redirect('/home');
        }
    }

    return back()->withErrors(['email' => 'Invalid credentials.']);
}


    public function showSignupForm()
    {
        return view('auth.login'); 
    }

    public function signup(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);

        User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        return redirect()->route('login')->with('success', 'Signup successful. Please login.');
    }
    public function logout()
    {
        Auth::logout(); 
        return redirect()->route('login'); 
    }
    public function showPasswordResetForm()
{
    return view('auth.password_reset');
}

// Method to handle the password reset request
public function resetPassword(Request $request)
{
    // Validate the request
    $request->validate([
        'email' => 'required|email',
        'token' => 'required',
        'password' => 'required|min:8',
    ]);

    // Reset the user's password
    $status = Password::reset(
        $request->only('email', 'password', 'token'),
        function ($user, $password) {
            $user->password = bcrypt($password);
            $user->save();
            event(new PasswordReset($user));
        }
    );

    // Redirect the user based on the password reset status
    if ($status == Password::PASSWORD_RESET) {
        return redirect()->route('login')->with('success', 'Password reset successfully. Please log in with your new password.');
    } else {
        return back()->withInput($request->only('email'))->withErrors(['email' => __($status)]);
    }

}
public function index()
    {
        $users = User::all();
        return view('dashboard.users', compact('users'));
    }

   public function updateUserRole(Request $request)
{
    $request->validate([
        'user_id' => 'required|exists:users,id',
        'role' => 'required|in:admin,organisateur,user',
    ]);

    $user = User::findOrFail($request->user_id);
    $user->role = $request->role;
    $user->save();

    return redirect()->back()->with('success', 'User role updated successfully.');
}

}